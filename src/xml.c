/* 	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	xml.c
	XML I/O Handler
*/

#include "astmanproxy.h"

#define XML_UNPARSED	"UnparsedText"
#define XML_BEGIN_INPUT	"<AsteriskManagerInput>"
#define XML_END_INPUT	"</AsteriskManagerInput>"

#define XML_SERVERTAG	"AsteriskManagerOutput"
#define XML_PROXYTAG	"AsteriskManagerProxyOutput"

void xml_quote_string(char *s, char *o);
int ParseXMLInput(char *xb, struct message *m);

int _read(struct mansession *s, struct message *m) {

	/* Note: No single line may be longer than MAX_LEN/s->inbuf, as per get_input */
	/* No XML Input may be longer than BUFSIZE */

	char line[MAX_LEN], xmlbuf[BUFSIZE];
	int res;

	/* first let's read the whole xml block into our buffer */
	memset(xmlbuf, 0, sizeof xmlbuf);
	for (;;) {
		memset(line, 0, sizeof line);
		res = get_input(s, line);

		if (res > 0) {
			if (*line == '\0' ) {
				break;
			} else if (strlen(xmlbuf) < (BUFSIZE - strlen(line)) )
				strcat(xmlbuf, line);
		} else if (res < 0)
			return res;
	}

	/* now, let's transform and copy into a standard message block */
	debugmsg("Got xml: %s", xmlbuf);
	res = ParseXMLInput(xmlbuf, m);

	if (res < 0)
		proxyerror_do(s, "Invalid XML Input");

	/* Return res>0 to process block, return res<0 to kill client, res=0, continue */
	return res;
}

void *setdoctag(char *tag, struct mansession *s) {

	/* if message came from a server, say so; otherwise it must be from proxy */
	/* right now there is no such thing as client<->client comms */
	if (s && s->server)
		strcpy(tag, XML_SERVERTAG);
	else
		strcpy(tag, XML_PROXYTAG);

	return 0;
}

int _write(struct mansession *s, struct message *m) {
	int i;
	char buf[BUFSIZE], outstring[MAX_LEN*3], xmlescaped[MAX_LEN*3], xmldoctag[MAX_LEN];
	char *dpos, *lpos;

	setdoctag(xmldoctag, m->session);
	sprintf(buf, "<%s>\r\n", xmldoctag);

	pthread_mutex_lock(&s->lock);
	ast_carefulwrite(s->fd, buf, strlen(buf), s->writetimeout);

	for (i=0; i<m->hdrcount; i++) {
		memset(xmlescaped, 0, sizeof xmlescaped);
		xml_quote_string(m->headers[i], xmlescaped);
		lpos = xmlescaped;
		dpos = strstr(lpos, ": ");
		if (dpos && *(lpos)!= ' ' && strlen(xmlescaped)<30 ) {
			strcpy(outstring, " <");
			strncat(outstring, lpos, dpos-lpos);
			strcat(outstring, " Value=\"");
			strncat(outstring, dpos+2, strlen(dpos)-2);
			strcat(outstring, "\"/>\r\n");
		} else
			sprintf(outstring, " <%s Value=\"%s\"/>\r\n", XML_UNPARSED, lpos);
		ast_carefulwrite(s->fd, outstring, strlen(outstring), s->writetimeout);
	}
	sprintf(buf, "</%s>\r\n\r\n", xmldoctag);
	ast_carefulwrite(s->fd, buf, strlen(buf), s->writetimeout);
	pthread_mutex_unlock(&s->lock);

	return 0;
}

/* Takes a single manager header line and converts xml entities */
void xml_quote_string(char *s, char *o) {

	char *c;
	c = s;

	do {
		if (*c == '<')
			strcat(o, "&lt;");
		else if (*c == '>')
			strcat(o, "&gt;");
		else if (*c == '&')
			strcat(o, "&amp;");
		else if (*c == '"')
			strcat(o, "&quot;");
		else if (*c == '\n')
			strcat(o, " ");
		else
			strncat(o, c, 1);
	} while (*(c++));

	return;
}

int ParseXMLInput(char *xb, struct message *m) {
	char *b, *e, *bt, *et, tag[MAX_LEN], *i;
	int res = 0;

	/* just an empty block; go home */
	if ( !(*xb) )
		return 0;

	/* initialize message block */
	memset(m, 0, sizeof(struct message) );

	b = strstr(xb, XML_BEGIN_INPUT);
	e = strstr(xb, XML_END_INPUT);
	if (b && e) {
		bt = strstr((char *)(b + strlen(XML_BEGIN_INPUT) + 1), "<");
		while (bt < e) {
			et = strstr(bt+1, "<");
			memset(tag, 0, sizeof tag);
			strncpy(tag, bt, (et-bt) );
			bt = et;

			strncpy( m->headers[m->hdrcount], tag+1, strstr(tag+1," ")-(tag+1) );
			strcat(m->headers[m->hdrcount], ": ");
			i = strstr(tag+1, "\"") + 1;
			strncat( m->headers[m->hdrcount], i, strstr(i, "\"") - i );
			debugmsg("parsed: %s",  m->headers[m->hdrcount]);
			m->hdrcount++;
		}
		res = 1;
	} else
		res = -1;

	return res;
}
