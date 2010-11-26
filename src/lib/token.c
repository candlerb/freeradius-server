/*
 * token.c	Read the next token from a string.
 *		Yes it's pretty primitive but effective.
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/token.h>

#include <ctype.h>

#ifdef HAVE_REGEX_H
#include <regex.h>

/*
 *  For POSIX Regular expressions.
 *  (0) Means no extended regular expressions.
 *  REG_EXTENDED means use extended regular expressions.
 */
#ifndef REG_EXTENDED
#define REG_EXTENDED (0)
#endif

#ifndef REG_NOSUB
#define REG_NOSUB (0)
#endif

#ifndef REG_ICASE
#define REG_ICASE (0)
#endif
#endif

static const FR_NAME_NUMBER tokens[] = {
	{ "=~", T_OP_REG_EQ,	}, /* order is important! */
	{ "!~", T_OP_REG_NE,	},
	{ "{",	T_LCBRACE,	},
	{ "}",	T_RCBRACE,	},
	{ "(",	T_LBRACE,	},
	{ ")",	T_RBRACE,	},
	{ ",",	T_COMMA,	},
	{ "+=",	T_OP_ADD,	},
	{ "-=",	T_OP_SUB,	},
	{ ":=",	T_OP_SET,	},
	{ "=*", T_OP_CMP_TRUE,  },
	{ "!*", T_OP_CMP_FALSE, },
	{ "==",	T_OP_CMP_EQ,	},
	{ "=",	T_OP_EQ,	},
	{ "!=",	T_OP_NE,	},
	{ ">=",	T_OP_GE,	},
	{ ">",	T_OP_GT,	},
	{ "<=",	T_OP_LE,	},
	{ "<",	T_OP_LT,	},
	{ "#",	T_HASH,		},
	{ ";",	T_SEMICOLON,	},
	{ NULL, 0,		},
};

/*
 *	This works only as long as special tokens
 *	are max. 2 characters, but it's fast.
 */
#define TOKEN_MATCH(bptr, tptr) \
	( (tptr)[0] == (bptr)[0] && \
	 ((tptr)[1] == (bptr)[1] || (tptr)[1] == 0))

/*
 *	Read a word from a buffer and advance pointer.
 *	This function knows about escapes and quotes.
 *
 *	At end-of-line, buf[0] is set to '\0'.
 *	Returns 0 or special token value.
 */
static FR_TOKEN getthing(const char **ptr, char *buf, int buflen, int tok,
			 const FR_NAME_NUMBER *tokenlist)
{
	char *s;
	const char *p;
	int	quote, end = 0;
	int	escape;
	unsigned int	x;
	const FR_NAME_NUMBER*t;
	FR_TOKEN rcode;

	buf[0] = 0;

	/* Skip whitespace */
	p = *ptr;
	while (*p && isspace((int) *p))
		p++;

	if (*p == 0) {
		*ptr = p;
		return T_EOL;
	}

	/*
	 *	Might be a 1 or 2 character token.
	 */
	if (tok) for (t = tokenlist; t->name; t++) {
		if (TOKEN_MATCH(p, t->name)) {
			strcpy(buf, t->name);
			p += strlen(t->name);
			while (isspace((int) *p))
				p++;
			*ptr = p;
			return (FR_TOKEN) t->number;
		}
	}

	/* Read word. */
	quote = 0;
	if ((*p == '"') ||
	    (*p == '\'') ||
	    (*p == '`')) {
		quote = *p;
		end = 0;
		p++;
	}
	s = buf;
	escape = 0;

	while (*p && buflen-- > 1) {
		if (quote && (*p == '\\')) {
			p++;

			switch(*p) {
				case 'r':
					*s++ = '\r';
					break;
				case 'n':
					*s++ = '\n';
					break;
				case 't':
					*s++ = '\t';
					break;
				case '\0':
					*s++ = '\\';
					p--; /* force EOS */
					break;
				default:
					if (*p >= '0' && *p <= '9' &&
					    sscanf(p, "%3o", &x) == 1) {
						*s++ = x;
						p += 2;
					} else
						*s++ = *p;
					break;
			}
			p++;
			continue;
		}
		if (quote && (*p == quote)) {
			end = 1;
			p++;
			break;
		}
		if (!quote) {
			if (isspace((int) *p))
				break;
			if (tok) {
				for (t = tokenlist; t->name; t++)
					if (TOKEN_MATCH(p, t->name))
						break;
				if (t->name != NULL)
					break;
			}
		}
		*s++ = *p++;
	}
	*s++ = 0;

	if (quote && !end) {
		fr_strerror_printf("Unterminated string");
		return T_OP_INVALID;
	}

	/* Skip whitespace again. */
	while (*p && isspace((int) *p))
		p++;
	*ptr = p;

	/* we got SOME form of output string, even if it is empty */
	switch (quote) {
	default:
	  rcode = T_BARE_WORD;
	  break;

	case '\'':
	  rcode = T_SINGLE_QUOTED_STRING;
	  break;

	case '"':
	  rcode = T_DOUBLE_QUOTED_STRING;
	  break;

	case '`':
	  rcode = T_BACK_QUOTED_STRING;
	  break;
	}

	return rcode;
}

/*
 *	Read a "word" - this means we don't honor
 *	tokens as delimiters.
 */
int getword(const char **ptr, char *buf, int buflen)
{
	return getthing(ptr, buf, buflen, 0, tokens) == T_EOL ? 0 : 1;
}

/*
 *	Read a bare "word" - this means we don't honor
 *	tokens as delimiters.
 */
int getbareword(const char **ptr, char *buf, int buflen)
{
	FR_TOKEN token;

	token = getthing(ptr, buf, buflen, 0, NULL);
	if (token != T_BARE_WORD) {
		return 0;
	}

	return 1;
}

/*
 *	Read the next word, use tokens as delimiters.
 */
FR_TOKEN gettoken(const char **ptr, char *buf, int buflen)
{
	return getthing(ptr, buf, buflen, 1, tokens);
}

/*
 *	Expect a string.
 */
FR_TOKEN getstring(const char **ptr, char *buf, int buflen)
{
	const char *p = *ptr;

	while (*p && (isspace((int)*p))) p++;

	*ptr = p;

	if ((*p == '"') || (*p == '\'') || (*p == '`')) {
		return gettoken(ptr, buf, buflen);
	}

	return getthing(ptr, buf, buflen, 0, tokens);
}

/*
 *	Convert a string to an integer
 */
int fr_str2int(const FR_NAME_NUMBER *table, const char *name, int def)
{
	const FR_NAME_NUMBER *this;

	for (this = table; this->name != NULL; this++) {
		if (strcasecmp(this->name, name) == 0) {
			return this->number;
		}
	}

	return def;
}

/*
 *	Convert an integer to a string.
 */
const char *fr_int2str(const FR_NAME_NUMBER *table, int number,
			 const char *def)
{
	const FR_NAME_NUMBER *this;

	for (this = table; this->name != NULL; this++) {
		if (this->number == number) {
			return this->name;
		}
	}

	return def;
}

#ifdef HAVE_REGEX_H
FR_TOKEN getregex(const char **ptr, char *buffer, size_t buflen,
			 int *pcflags)
{
	const char *p = *ptr;
	char *q = buffer;

	if (*p != '/') return T_OP_INVALID;

	*pcflags = REG_EXTENDED;

	p++;
	while (*p) {
		if (buflen <= 1) break;

		if (*p == '/') {
			p++;

			/*
			 *	Check for case insensitivity
			 */
			if (*p == 'i') {
				p++;
				*pcflags |= REG_ICASE;
			}

			break;
		}

		if (*p == '\\') {
			int x;
			
			switch (p[1]) {
			case 'r':
				*q++ = '\r';
				break;
			case 'n':
				*q++ = '\n';
				break;
			case 't':
				*q++ = '\t';
				break;
			case '"':
				*q++ = '"';
				break;
			case '\'':
				*q++ = '\'';
				break;
			case '`':
				*q++ = '`';
				break;
				
				/*
				 *	FIXME: add 'x' and 'u'
				 */

			default:
				if ((p[1] >= '0') && (p[1] <= '9') &&
				    (sscanf(p + 1, "%3o", &x) == 1)) {
					*q++ = x;
					p += 2;
				} else {
					*q++ = p[1];
				}
				break;
			}
			p += 2;
			buflen--;
			continue;
		}

		*(q++) = *(p++);
		buflen--;
	}
	*q = '\0';
	*ptr = p;

	return T_DOUBLE_QUOTED_STRING;
}
#endif
