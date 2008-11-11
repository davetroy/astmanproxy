/*	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	standard.c
	Standard I/O Handler
*/

#include "astmanproxy.h"

extern struct mansession *sessions;

/* Return a fully formed message block to session_do for processing */
int _read(struct mansession *s, struct message *m) {
	int res;

	for (;;) {
		res = get_input(s, m->headers[m->hdrcount]);

		if (strstr(m->headers[m->hdrcount], "--END COMMAND--")) {
				if (debug) debugmsg("Found END COMMAND");
				m->in_command = 0;
		}
		if (strstr(m->headers[m->hdrcount], "Response: Follows")) {
				if (debug) debugmsg("Found Response Follows");
				m->in_command = 1;
		}
		if (res > 0) {
			if (!m->in_command && *(m->headers[m->hdrcount]) == '\0' ) {
				break;
			} else if (m->hdrcount < MAX_HEADERS - 1) {
				m->hdrcount++;
			} else {
				m->in_command = 0; // reset when block full
			}
		} else if (res < 0)
			break;
	}

	return res;
}

int _write(struct mansession *s, struct message *m) {
	int i;

	pthread_mutex_lock(&s->lock);
	for (i=0; i<m->hdrcount; i++) {
		if( ! strlen(m->headers[i]) )
			continue;
		ast_carefulwrite(s->fd, m->headers[i], strlen(m->headers[i]) , s->writetimeout);
		ast_carefulwrite(s->fd, "\r\n", 2, s->writetimeout);
	}
	ast_carefulwrite(s->fd, "\r\n", 2, s->writetimeout);
	pthread_mutex_unlock(&s->lock);

	return 0;
}

int _onconnect(struct mansession *s, struct message *m) {

	char banner[100];

	sprintf(banner, "%s/%s\r\n", PROXY_BANNER, PROXY_VERSION);
	pthread_mutex_lock(&s->lock);
	ast_carefulwrite(s->fd, banner, strlen(banner), s->writetimeout);
	pthread_mutex_unlock(&s->lock);

	return 0;
}

