/*	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	http.c
	HTTP Input Handler
*/

#include "astmanproxy.h"

// SwapChar:	This routine swaps one character for another
void SwapChar(char *pOriginal, char cBad, char cGood) {
	int i;	// generic counter variable

	// Loop through the input string (cOriginal), character by
	// character, replacing each instance of cBad with cGood

	i = 0;
	while (pOriginal[i]) {
		if (pOriginal[i] == cBad) pOriginal[i] = cGood;
		i++;
	}
}

// IntFromHex:	A subroutine to unescape escaped characters.
static int IntFromHex(char *pChars) {
	int Hi;	// holds high byte
	int Lo;	// holds low byte
	int Result;	// holds result

	// Get the value of the first byte to Hi

	Hi = pChars[0];
	if ('0' <= Hi && Hi <= '9') {
		Hi -= '0';
	} else
		if ('a' <= Hi && Hi <= 'f') {
			Hi -= ('a'-10);
		} else
			if ('A' <= Hi && Hi <= 'F') {
				Hi -= ('A'-10);
			}

	// Get the value of the second byte to Lo

	Lo = pChars[1];
	if ('0' <= Lo && Lo <= '9') {
		Lo -= '0';
	} else
		if ('a' <= Lo && Lo <= 'f') {
			Lo -= ('a'-10);
		} else
			if ('A' <= Lo && Lo <= 'F') {
				Lo -= ('A'-10);
			}
	Result = Lo + (16 * Hi);
	return (Result);
}

// URLDecode: This routine loops through the string pEncoded
// (passed as a parameter), and decodes it in place. It checks for
// escaped values, and changes all plus signs to spaces. The result
// is a normalized string. It calls the two subroutines directly
// above in this listing, IntFromHex() and SwapChar().

void URLDecode(char *pEncoded) {
	char *pDecoded;		// generic pointer

	// First, change those pesky plusses to spaces
	SwapChar (pEncoded, '+', ' ');

	// Now, loop through looking for escapes
	pDecoded = pEncoded;
	while (*pEncoded) {
	if (*pEncoded=='%') {
		// A percent sign followed by two hex digits means
		// that the digits represent an escaped character. We
		// must decode it.

		pEncoded++;
		if (isxdigit(pEncoded[0]) && isxdigit(pEncoded[1])) {
			*pDecoded++ = (char) IntFromHex(pEncoded);
			pEncoded += 2;
		}
	} else {
		*pDecoded ++ = *pEncoded++;
	}
	}
	*pDecoded = '\0';
}

int ParseHTTPInput(char *buf, struct message *m) {
	char *n, *v;

	n = buf;
	while ( (v = strstr(n, "=")) ) {
		v += 1;
		debugmsg("n: %s, v: %s", n, v);
		strncat(m->headers[m->hdrcount], n, v-n-1);
		strcat(m->headers[m->hdrcount], ": ");

		if ( (n = strstr(v, "&")) ) {
			n += 1;
		} else {
			n = (v + strlen(v) + 1);
		}
		strncat(m->headers[m->hdrcount], v, n-v-1);
		debugmsg("got hdr: %s", m->headers[m->hdrcount]);
		m->hdrcount++;
	}

	return (m->hdrcount > 0);
}

int HTTPHeader(struct mansession *s, char *status) {


	time_t t;
	struct tm tm;
	char date[80];
	char ctype[15], hdr[MAX_LEN];

	time(&t);
	localtime_r(&t, &tm);
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", &tm);

	if ( !strcasecmp("xml", s->output->formatname) )
		sprintf(ctype, "text/xml");
	else
		sprintf(ctype, "text/plain");

	if (!strcmp("200 OK", status) )
		sprintf(hdr,
					"HTTP/1.1 %s\r\n"
					"Date: %s\r\n"
					"Content-Type: %s\r\n"
					"Connection: close\r\n"
					"Server: %s/%s\r\n\r\n", status,
					date, ctype, PROXY_BANNER, PROXY_VERSION);
	else
		sprintf(hdr,
			"HTTP/1.1 %s\r\n"
			"Date: %s\r\n"
			"Status: %s\r\n"
			"Server: %s/%s\r\n\r\n", status, date, status, PROXY_BANNER, PROXY_VERSION);

	pthread_mutex_lock(&s->lock);
	s->inputcomplete = 1;
	ast_carefulwrite(s->fd, hdr, strlen(hdr), s->writetimeout);
	pthread_mutex_unlock(&s->lock);
	debugmsg("http header: %s", hdr);

	return 0;
}

int _read(struct mansession *s, struct message *m) {

	/* Note: No single line may be longer than MAX_LEN/s->inbuf, as per get_input */
	/* No HTTP Input may be longer than BUFSIZE */

	char line[MAX_LEN], method[10], formdata[MAX_LEN], status[15];
	char *tmp;
	int res, clength = 0;

	memset(method, 0, sizeof method);
	memset(formdata, 0, sizeof formdata);
	memset(status, 0, sizeof status);

	/* for http, don't do get_input forever */
	for (;;) {

		if (s->inputcomplete && !s->outputcomplete) {
			sleep(1);
			continue;
		} else if (s->inputcomplete && s->outputcomplete)
			return -1;

		memset(line, 0, sizeof line);
		res = get_input(s, line);
		debugmsg("res=%d, line: %s",res, line);

		if (res > 0) {
			debugmsg("Got http: %s", line);

			if ( !clength && !strncasecmp(line, "Content-Length: ", 16) )
				clength = atoi(line+16);

			if (!*method) {
				if ( !strncmp(line,"POST",4) ) {
					strncpy(method, line, 4);
				} else if ( !strncmp(line,"GET",3)) {
					if ( strlen(line) > 14 && (tmp = strcasestr(line, " HTTP")) ) {
						/* GET / HTTP/1.1 ---- this is bad */
						/* GET /?Action=Ping&ActionID=Foo HTTP/1.1 */
						strncpy(method, line, 3);
						memcpy(formdata, line+6, tmp-line-6);
						sprintf(status, "200 OK");
					} else
						sprintf(status, "501 Not Implemented");
				}
			}
		} else if (res == 0) {
			/* x-www-form-urlencoded handler */
			/* Content-Type: application/x-www-form-urlencoded */
			if (*method && !*formdata) {
				if ( !strcasecmp(method, "POST") && clength && s->inlen==clength) {
				pthread_mutex_lock(&s->lock);
				strncpy(formdata, s->inbuf, clength);
				s->inlen = 0;
				pthread_mutex_unlock(&s->lock);
				sprintf(status, "200 OK");
				}
			}
		}

		if (res < 0)
			break;

		if (*status) {
			HTTPHeader(s, status);

			/* now, let's transform and copy into a standard message block */
			if (!strcmp("200 OK", status) ) {
				URLDecode(formdata);
				res = ParseHTTPInput(formdata, m);
				return res;
			} else {
				pthread_mutex_lock(&s->lock);
				s->outputcomplete = 1;
				pthread_mutex_unlock(&s->lock);
				return 0;
			}
		}
	}
	return -1;
}

/* We do not define a _write or _onconnect method */
