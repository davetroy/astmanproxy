/* 	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>
	
	This program is free software, distributed under the terms of
	the GNU General Public License.

	common.c
	contains common utililty functions used by both astmanproxy
	core as well as (many) of the various I/O handlers
*/

#include "astmanproxy.h"

/* This routine based on get_input from Asterisk manager.c */
/* Good generic line-based input routine for \r\n\r\n terminated input */
/* Used by standard.c and other input handlers */
int get_input(struct mansession *s, char *output)
{
	/* output must have at least sizeof(s->inbuf) space */
	int res;
	int x;
	struct pollfd fds[1];
	char iabuf[INET_ADDRSTRLEN];

	/* Look for \r\n from the front, our preferred end of line */
	for (x=0;x<s->inlen;x++) {
			int xtra = 0;
		if (s->inbuf[x] == '\n') {
				if (x && s->inbuf[x-1] == '\r') {
					xtra = 1;
				}
			/* Copy output data not including \r\n */
			memcpy(output, s->inbuf, x - xtra);
			/* Add trailing \0 */
			output[x-xtra] = '\0';
			/* Move remaining data back to the front */
			memmove(s->inbuf, s->inbuf + x + 1, s->inlen - x);
			s->inlen -= (x + 1);
			return 1;
		}
	}

	if (s->inlen >= sizeof(s->inbuf) - 1) {
		if (debug)
		debugmsg("Warning: Got long line with no end from %s: %s\n", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr), s->inbuf);
		s->inlen = 0;
	}
	/* get actual fd, even if a negative SSL fd */
	fds[0].fd = get_real_fd(s->fd);

	fds[0].events = POLLIN;
	do {
		res = poll(fds, 1, -1);
		if (res < 0) {
			if (errno == EINTR) {
				if (s->dead)
					return -1;
				continue;
			}
			if (debug)
				debugmsg("Select returned error");
			return -1;
		} else if (res > 0) {
			pthread_mutex_lock(&s->lock);
			/* read from socket; SSL or otherwise */
			res = m_recv(s->fd, s->inbuf + s->inlen, sizeof(s->inbuf) - 1 - s->inlen, 0);
			pthread_mutex_unlock(&s->lock);
			if (res < 1)
				return -1;
			break;

		}
	} while(1);

	/* We have some input, but it's not ready for processing */
	s->inlen += res;
	s->inbuf[s->inlen] = '\0';
	return 0;
}

char *astman_get_header(struct message *m, char *var)
{
	char cmp[80];
	int x;
	snprintf(cmp, sizeof(cmp), "%s: ", var);
	for (x=0;x<m->hdrcount;x++)
		if (!strncasecmp(cmp, m->headers[x], strlen(cmp)))
			return m->headers[x] + strlen(cmp);
	return "";
}

int AddHeader(struct message *m, const char *fmt, ...) {
	va_list ap;

	int res;

	if (m->hdrcount < MAX_HEADERS - 1) {
		va_start(ap, fmt);
		vsprintf(m->headers[m->hdrcount], fmt, ap);
		va_end(ap);
		m->hdrcount++;
		res = 0;
	} else
		res = 1;

	return res;
}

/* Recursive thread safe replacement of inet_ntoa */
const char *ast_inet_ntoa(char *buf, int bufsiz, struct in_addr ia)
{
	return inet_ntop(AF_INET, &ia, buf, bufsiz);
}


/*! If you are calling ast_carefulwrite, it is assumed that you are calling
	it on a file descriptor that _DOES_ have NONBLOCK set.  This way,
	there is only one system call made to do a write, unless we actually
	have a need to wait.  This way, we get better performance. */
int ast_carefulwrite(int fd, char *s, int len, int timeoutms)
{
	/* Try to write string, but wait no more than ms milliseconds
		before timing out */
	int res=0;
	struct pollfd fds[1];
	while(len) {
		res = m_send(fd, s, len);
		if ((res < 0) && (errno != EAGAIN)) {
			return -1;
		}
		if (res < 0) res = 0;
		len -= res;
		s += res;
		res = 0;
		if (len) {
			fds[0].fd = get_real_fd(fd);
			fds[0].events = POLLOUT;
			/* Wait until writable again */
			res = poll(fds, 1, timeoutms);
			if (res < 1)
				return -1;
		}
	}
	return res;
}

