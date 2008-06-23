/*	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	csv.c
	CSV I/O Handler
*/

#include "astmanproxy.h"

/* TODO: catch and expand/handle commas in output */

int _write(struct mansession *s, struct message *m) {
	int i;
	char outstring[MAX_LEN];

	pthread_mutex_lock(&s->lock);
	for (i=0; i<m->hdrcount; i++) {
		sprintf(outstring, "\"%s\"", m->headers[i]);
		if (i<m->hdrcount-1)
			strcat(outstring, ", ");
		ast_carefulwrite(s->fd, outstring, strlen(outstring), s->writetimeout);
	}
	ast_carefulwrite(s->fd, "\r\n\r\n", 4, s->writetimeout);
	pthread_mutex_unlock(&s->lock);

	return 0;
}

