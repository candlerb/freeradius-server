/*
 * rlm_packetblast.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000-2011  TalkTalk Telecom Group PLC
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NETINET_IN_H
#include  <netinet/in.h>
#endif

#include  <sys/socket.h>

#ifdef HAVE_ARPA_INET_H
#include  <arpa/inet.h>
#endif

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct hostinfo {
	unsigned int host, port;
	struct sockaddr_in sa;
	struct hostinfo *next;
}HOSTINFO;

typedef struct rlm_packetblast_t {
	char *hostname;
	char *secret;
	unsigned int secretlen,defport;
	HOSTINFO *hosts;
	int sock;
} rlm_packetblast_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
  { "host",      PW_TYPE_STRING_PTR, offsetof(rlm_packetblast_t,hostname),
    NULL, NULL },
  { "port",        PW_TYPE_INTEGER,    offsetof(rlm_packetblast_t,defport),
    NULL, "1813" },
  { "secret",        PW_TYPE_STRING_PTR,    offsetof(rlm_packetblast_t,secret),
    NULL, "testing123" },

  { NULL, -1, 0, NULL, NULL }		/* end the list */

};


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int packetblast_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_packetblast_t *data;

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		return -1;
	}
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}

	data->secretlen = strlen(data->secret);

	*instance = data;

	if(data->hostname) {
		char *str = strdup(data->hostname);
		char *c,*d,*e;
		fr_ipaddr_t rad_ipaddr;
		unsigned int port = data->defport;
		HOSTINFO *n;
		
		for(c=str;c;c=d) {
			d = strchr(c,',');
			if(d) *d++=0;

			if((e=strchr(c,':'))) {
				*e++=0;
				port = atoi(e);
			}else{
				port = data->defport;
			}		

			if (ip_hton(c, AF_INET, &rad_ipaddr) < 0) {
				radlog(L_ERR, "rlm_packetblast: Unable to resolve '%s'", c);
				return -1;
			}
			n = (HOSTINFO*)malloc(sizeof(HOSTINFO));
			if(!n) {
				radlog(L_ERR, "rlm_packetblast: NO MEM");
				continue;
			}
			memset(n, 0, sizeof(HOSTINFO));
			
			radlog(L_INFO, "rlm_packetblast: will forward to host %x:%d",ntohl(rad_ipaddr.ipaddr.ip4addr.s_addr),port);

			n->sa.sin_family = AF_INET;
			n->sa.sin_addr.s_addr = rad_ipaddr.ipaddr.ip4addr.s_addr;
			n->sa.sin_port = htons(port);
			n->host = rad_ipaddr.ipaddr.ip4addr.s_addr;
			n->port = port;

			n->next = data->hosts;
			data->hosts = n;
		}

		data->sock = socket(PF_INET, SOCK_DGRAM, 0);
	} else {
		radlog(L_ERR, "rlm_packetblast: 'host' must be set.");
		return -1;
	}


	return 0;
}


/*
 *	Accounting module call to loop through the list of hosts in inst->hosts
 *	and send a copy of the radius packet.
 */

static int packetblast_return(void *instance, REQUEST *request)
{
	struct rlm_packetblast_t *inst = (struct rlm_packetblast_t*)instance;
	unsigned char *pack;
	HOSTINFO *h;
	int ret = RLM_MODULE_OK;
	struct sockaddr_in sa;

	if((!request) || (!request->packet) || (!inst))
		return RLM_MODULE_FAIL;

	pack = malloc(request->packet->data_len + inst->secretlen);
	if(!pack) {
		radlog(L_ERR, "rlm_packetblast: NO MEMORY!!!!!");
	 	return RLM_MODULE_FAIL;
	}

	memcpy(pack, request->packet->data, request->packet->data_len);
	memcpy(pack+request->packet->data_len, inst->secret, inst->secretlen);
	memset(pack+4, 0, 16); /* Zero authenticator */

	fr_md5_calc(pack+4, pack, request->packet->data_len + inst->secretlen);

	for(h=inst->hosts; h; h=h->next) {
		memcpy(&sa, &h->sa, sizeof(struct sockaddr_in));
		if(sendto(inst->sock, pack, (int)request->packet->data_len,
				0, (struct sockaddr *)&sa, sizeof(struct sockaddr_in))<=0)
		{
			radlog(L_ERR, "rlm_packetblast: cannot send packet");
	 		ret = RLM_MODULE_FAIL;
		}		
	}

	free(pack);

	return ret;
}



/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int packetblast_detach(void *instance)
{
	struct rlm_packetblast_t *inst = (struct rlm_packetblast_t*)instance;
	HOSTINFO *tmp;

	if(inst->sock) close(inst->sock);

	while(inst->hosts) {
		tmp = inst->hosts->next;
		free(inst->hosts);
		inst->hosts = tmp;
	}

	free(instance);
	return 0;

}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_packetblast = {
	RLM_MODULE_INIT,
	"packetblast",
	RLM_TYPE_THREAD_SAFE,		/* type */
	packetblast_instantiate,	/* instantiation */
	packetblast_detach,			/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		packetblast_return,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
