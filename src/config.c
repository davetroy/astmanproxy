/* 	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>
	
	This program is free software, distributed under the terms of
	the GNU General Public License.

	config.c
	routines to read and parse the configuration file and initialize
	the internal configuration datastructures
*/

#include <pwd.h>
#include <grp.h>
#include "astmanproxy.h"

extern struct iohandler *iohandlers;

void *add_server(char *srvspec) {

	int ccount = 0;
	struct ast_server *srv;
	char *s;
	char usessl[10];
	
	/* malloc ourselves a server credentials structure */
	srv = malloc(sizeof(struct ast_server));
	if ( !srv ) {
		fprintf(stderr, "Failed to allocate server credentials: %s\n", strerror(errno));
		exit(1);
	}
	memset(srv, 0, sizeof (struct ast_server) );
	memset(usessl, 0, sizeof (usessl) );
	
	s = srvspec;
	do {
		*s = tolower(*s);
		if ( *s == ',' ) {
			ccount++;
			continue;
		}
		switch(ccount) {
		  case 0:
			 strncat(srv->ast_host, s, 1);
			 break;
		  case 1:
			 strncat(srv->ast_port, s, 1);
			 break;
		  case 2:
			 strncat(srv->ast_user, s, 1);
			 break;
		  case 3:
			 strncat(srv->ast_pass, s, 1);
			 break;
		  case 4:
			 strncat(srv->ast_events, s, 1);
			 break;
		  case 5:
			 strncat(usessl, s, 1);
			 break;
		}
	} while (*(s++));


	if (!*srv->ast_host || !*srv->ast_port || !*srv->ast_user || !*srv->ast_pass || !*srv->ast_events || !*usessl) {
		fprintf(stderr, "Aborting: server spec incomplete: %s\n", srvspec);
		free(srv);
		exit(1);
	}

	srv->use_ssl = (!strcmp(usessl,"on"));
	srv->next = pc.serverlist;
	pc.serverlist = srv;

	return 0;
}

void *processline(char *s) {
	char name[80],value[80];
	int nvstate = 0;


	memset (name,0,sizeof name);
	memset (value,0,sizeof value);

	do {
		*s = tolower(*s);

		if ( *s == ' ' || *s == '\t')
			continue;
		if ( *s == ';' || *s == '#' || *s == '\r' || *s == '\n' )
			break;
		if ( *s == '=' ) {
			nvstate = 1;
			continue;
		}
		if (!nvstate)
			strncat(name, s, 1);
		else
			strncat(value, s, 1);
	} while (*(s++));

	if (debug)
		debugmsg("config: %s, %s", name, value);

	if ( !strcmp(name,"host") )
		add_server(value);
	else if (!strcmp(name,"retryinterval") )
		pc.retryinterval = atoi(value);
	else if (!strcmp(name,"maxretries") )
		pc.maxretries = atoi(value);
	else if (!strcmp(name,"listenaddress") )
		strcpy(pc.listen_addr, value);
	else if (!strcmp(name,"listenport") )
		pc.listen_port = atoi(value);
	else if (!strcmp(name,"asteriskwritetimeout") )
		pc.asteriskwritetimeout = atoi(value);
	else if (!strcmp(name,"clientwritetimeout") )
		pc.clientwritetimeout = atoi(value);
	else if (!strcmp(name,"sslclienthellotimeout") )
		pc.sslclhellotimeout = atoi(value);
	else if (!strcmp(name,"authrequired") )
		pc.authrequired = strcmp(value,"yes") ? 0 : 1;
	else if (!strcmp(name,"acceptencryptedconnection") )
		pc.acceptencryptedconnection = strcmp(value,"yes") ? 0 : 1;
	else if (!strcmp(name,"acceptunencryptedconnection") )
		pc.acceptunencryptedconnection = strcmp(value,"yes") ? 0 : 1;
	else if (!strcmp(name,"certfile") )
		strcpy(pc.certfile, value);
	else if (!strcmp(name,"proxykey") )
		strcpy(pc.key, value);
	else if (!strcmp(name,"proc_user") )
		strcpy(pc.proc_user, value);
	else if (!strcmp(name,"proc_group") )
		strcpy(pc.proc_group, value);
	else if (!strcmp(name,"logfile") )
		strcpy(pc.logfile, value);
	else if (!strcmp(name,"autofilter") ) {
		if( ! strcmp(value,"on") )
			pc.autofilter = 1;
		else if( ! strcmp(value,"unique") )
			pc.autofilter = 2;
		else
			pc.autofilter = 0;
	} else if (!strcmp(name,"outputformat") )
		strcpy(pc.outputformat, value);
	else if (!strcmp(name,"inputformat") )
		strcpy(pc.inputformat, value);

	return 0;
}

int LoadHandlers() {

	void *dlhandle = NULL;
	const char *error;
	char fmt[20], moddir[80] = MDIR, modfile[80];
	DIR *mods;
	struct dirent *d;
	void *rh, *wh, *och;
	struct iohandler *io = NULL;

	mods = opendir(moddir);
	if (!mods)
		exit(1);

	while((d = readdir(mods))) {
		/* Must end in .so to load it.  */
		if ( (strlen(d->d_name) > 3) && !strcasecmp(d->d_name + strlen(d->d_name) - 3, ".so") ) {

			memset(fmt, 0, sizeof fmt);
			strncpy(fmt, d->d_name, strlen(d->d_name) - 3);

			sprintf(modfile, "%s/%s", moddir, d->d_name);
			if (debug)
				debugmsg("loading: module %s (%s)", fmt, modfile);

			dlhandle = dlopen (modfile, RTLD_LAZY);
			if (!dlhandle) {
				fprintf(stderr, "dlopen failed: %s\n", dlerror());
				exit(1);
			}

			rh = dlsym(dlhandle, "_read");
			if ((error = dlerror()) != NULL)  {
				if (debug)
					debugmsg("loading: note, %s_read does not exist; ignoring", fmt);
			}

			wh = dlsym(dlhandle, "_write");
			if ((error = dlerror()) != NULL)  {
				if (debug)
					debugmsg("loading: note, %s_write does not exist; ignoring", fmt);
			}

			och = dlsym(dlhandle, "_onconnect");
			if ((error = dlerror()) != NULL)  {
				if (debug)
					debugmsg("loading: note, %s_onconnect does not exist; ignoring", fmt);
			}

			if (rh || wh) {
				io = malloc(sizeof(struct iohandler));
				memset(io, 0, sizeof(struct iohandler));
				strcpy(io->formatname, fmt);
				if (rh)
					io->read = rh;
				if (wh)
					io->write = wh;
				if (och)
					io->onconnect = och;

				io->dlhandle = dlhandle;
				io->next = iohandlers;
				iohandlers = io;
			} else
				dlclose(dlhandle);
		}
	}
	closedir(mods);

	if (!iohandlers) {
		fprintf(stderr, "Unable to load *ANY* IO Handlers from %s!\n", MDIR);
		exit(1);
	}

	return 0;
}


int ReadConfig() {
	FILE *FP;
	char buf[1024];
	char cfn[80];


	memset( &pc, 0, sizeof pc );

	/* Set nonzero config defaults */
	pc.asteriskwritetimeout = 100;
	pc.clientwritetimeout = 100;
	pc.sslclhellotimeout = 500;

	sprintf(cfn, "%s/%s", CDIR, CFILE);
	FP = fopen( cfn, "r" );

	if ( !FP ) {
		fprintf(stderr, "Unable to open config file: %s/%s!\n", CDIR, CFILE);
		exit( 1 );
	}

	if (debug)
		debugmsg("config: parsing configuration file: %s", cfn);

	while ( fgets( buf, sizeof buf, FP ) ) {
		if (*buf == ';' || *buf == '\r' || *buf == '\n' || *buf == '#') continue;
		processline(buf);
	}

	fclose(FP);

	/* initialize SSL layer with our server certfile */
	init_secure(pc.certfile);

	return 0;
}

FILE *OpenLogfile() {
	FILE *FP;
	FP = fopen( pc.logfile, "a" );
	if ( !FP ) {
		fprintf(stderr, "Unable to open logfile: %s!\n", pc.logfile);
		exit( 1 );
	}

	return FP;
}

int SetProcUID() {

	struct passwd *pwent;
	struct group *gp;
	uid_t newuid = 0;
	gid_t newgid = 0;

	if ((pwent = (struct passwd *)getpwnam( pc.proc_user )) == NULL) {
		fprintf(stderr, "getpwnam(%s) failed.\n", pc.proc_user);
		return(-1);
	} else
		newuid = pwent->pw_uid;

	if ( newuid == 0 ) {
		fprintf(stderr, "getpwnam(%s) returned root user; aborting!\n", pc.proc_user);
		return(-1);
	}

	if ((gp = (struct group *)getgrnam( pc.proc_group )) == NULL) {
		fprintf(stderr, "getgrnam(%s) failed.\n", pc.proc_group);
		return(-1);
	} else
		newgid = gp->gr_gid;

	if ( chown( pc.logfile, newuid, newgid ) < 0 ) {
		fprintf(stderr, "chown(%d,%d) of %s failed!\n", newuid, newgid, pc.logfile);
		return( -1 );
	}

	if (setgid(newgid) < 0) {
		fprintf(stderr, "setgid(%d) failed.\n", newgid);
		return(-1);
	}

	if (setuid(newuid) < 0) {
		fprintf(stderr, "setuid(%d) failed.\n", newuid);
		return(-1);
	}

	return 0;
}
