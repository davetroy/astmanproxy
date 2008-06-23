/*	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	log.c
	Log & debug routines
*/

#include "astmanproxy.h"

#define DATEFORMAT		"%b %e %T"

extern FILE *proxylog;
extern int debug;
extern pthread_mutex_t loglock;
extern pthread_mutex_t debuglock;

void debugmsg (const char *fmt, ...)
{
	va_list ap;

	time_t t;
	struct tm tm;
	char date[80];

	if (!debug)
		return;

	time(&t);
	localtime_r(&t, &tm);
	strftime(date, sizeof(date), DATEFORMAT, &tm);

	pthread_mutex_lock(&debuglock);
	va_start(ap, fmt);
	printf("%s: ", date);
	vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
	pthread_mutex_unlock(&debuglock);
}


void logmsg (const char *fmt, ...)
{
	va_list ap;

	time_t t;
	struct tm tm;
	char date[80];

	time(&t);
	localtime_r(&t, &tm);
	strftime(date, sizeof(date), DATEFORMAT, &tm);

	if (proxylog) {
		pthread_mutex_lock(&loglock);
		va_start(ap, fmt);
		fprintf(proxylog, "%s: ", date);
		vfprintf(proxylog, fmt, ap);
		fprintf(proxylog, "\n");
		va_end(ap);
		fflush(proxylog);
		pthread_mutex_unlock(&loglock);
	}
}
