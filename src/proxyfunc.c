/*	Asterisk Manager Proxy
	Copyright (c) 2005-2006 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	proxyfunc.c
	Functions specific to the manager proxy, not found in standard Asterisk AMI
*/

#include "astmanproxy.h"
#include "md5.h"

extern struct mansession *sessions;
extern struct iohandler *iohandlers;
extern pthread_mutex_t serverlock;
extern pthread_mutex_t userslock;

void *ProxyListIOHandlers(struct mansession *s) {
	struct message m;
	struct iohandler *i;

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "ProxyResponse: Success");

	i = iohandlers;
	while (i && (m.hdrcount < MAX_HEADERS - 1) ) {
		if (i->read)
			AddHeader(&m, "InputHandler: %s", i->formatname);
		if (i->write)
			AddHeader(&m, "OutputHandler: %s", i->formatname);
		i = i->next;
	}

	s->output->write(s, &m);
	return 0;
}

void *ProxyListSessions(struct mansession *s) {
	struct message m;
	struct mansession *c;
	char iabuf[INET_ADDRSTRLEN];

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "ProxyResponse: Success");

	c = sessions;
	while (c && (m.hdrcount < MAX_HEADERS - 1) ) {
		if (!c->server) {
			AddHeader(&m, "ProxyClientSession: %s", ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr), c->actionid);
			AddHeader(&m, "ProxyClientInputHandler: %s", c->input->formatname);
			AddHeader(&m, "ProxyClientOutputHandler: %s", c->output->formatname);
		} else 
			AddHeader(&m, "ProxyServerSession: %s", ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr));
		c = c->next;
	}
	s->output->write(s, &m);
	return 0;
}

void *ProxySetOutputFormat(struct mansession *s, struct message *m) {
	struct message mo;
	char *value;

	value = astman_get_header(m, "OutputFormat");
	SetIOHandlers(s, s->input->formatname, value);

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "ProxyResponse: Success");
	AddHeader(&mo, "OutputFormat: %s", s->output->formatname );

	s->output->write(s, &mo);

	return 0;
}

int ProxyChallenge(struct mansession *s, struct message *m) {
	struct message mo;

	if ( strcasecmp("MD5", astman_get_header(m, "AuthType")) ) {
		SendError(s, "Must specify AuthType");
		return 1;
	}

	if (!*s->challenge)
		snprintf(s->challenge, sizeof(s->challenge), "%d", rand());

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "Response: Success");
	AddHeader(&mo, "Challenge: %s", s->challenge);

	s->output->write(s, &mo);
	return 0;
}

void *ProxySetAutoFilter(struct mansession *s, struct message *m) {
	struct message mo;
	char *value;
	int i;

	value = astman_get_header(m, "AutoFilter");
	if ( !strcasecmp(value, "on") )
		i = 1;
	else
		i = 0;
	pthread_mutex_lock(&s->lock);
	s->autofilter = i;
	pthread_mutex_unlock(&s->lock);

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "ProxyResponse: Success");
	AddHeader(&mo, "AutoFilter: %d", s->autofilter);

	s->output->write(s, &mo);

	return 0;
}

int AuthMD5(char *key, char *challenge, char *password) {
	int x;
	int len=0;
	char md5key[256] = "";
	struct MD5Context md5;
	unsigned char digest[16];

	if (!*key || !*challenge || !*password )
	return 1;

	if (debug)
		debugmsg("MD5 password=%s, challenge=%s", password, challenge);

	MD5Init(&md5);
	MD5Update(&md5, (unsigned char *) challenge, strlen(challenge));
	MD5Update(&md5, (unsigned char *) password, strlen(password));
	MD5Final(digest, &md5);
	for (x=0;x<16;x++)
			len += sprintf(md5key + len, "%2.2x", digest[x]);
	if( debug ) {
		debugmsg("MD5 computed=%s, received=%s", md5key, key);
	}
	if (!strcmp(md5key, key))
	return 0;
	else
	return 1;
}

void *ProxyLogin(struct mansession *s, struct message *m) {
	struct message mo;
	struct proxy_user *pu;
	char *user, *secret, *key;

	user = astman_get_header(m, "Username");
	secret = astman_get_header(m, "Secret");
	key = astman_get_header(m, "Key");

	memset(&mo, 0, sizeof(struct message));
	if( debug )
		debugmsg("Login attempt as: %s/%s", user, secret);

	pthread_mutex_lock(&userslock);
	pu = pc.userlist;
	while( pu ) {
	if ( !strcmp(user, pu->username) ) {
			if (!AuthMD5(key, s->challenge, pu->secret) || !strcmp(secret, pu->secret) ) {
				AddHeader(&mo, "Response: Success");
				AddHeader(&mo, "Message: Authentication accepted");
				s->output->write(s, &mo);
				pthread_mutex_lock(&s->lock);
				s->authenticated = 1;
				strcpy(s->user.channel, pu->channel);
				strcpy(s->user.icontext, pu->icontext);
				strcpy(s->user.ocontext, pu->ocontext);
				pthread_mutex_unlock(&s->lock);
				if( debug )
					debugmsg("Login as: %s", user);
				break;
			}
		}
		pu = pu->next;
	}
	pthread_mutex_unlock(&userslock);

	if( !pu ) {
		SendError(s, "Authentication failed");
		pthread_mutex_lock(&s->lock);
		s->authenticated = 0;
		pthread_mutex_unlock(&s->lock);
		if( debug )
			debugmsg("Login failed as: %s/%s", user, secret);
	}

	return 0;
}

void *ProxyLogoff(struct mansession *s) {
	struct message m;

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "Goodbye: Y'all come back now, y'hear?");

	s->output->write(s, &m);

	destroy_session(s);
	if (debug)
		debugmsg("Client logged off - exiting thread");
	pthread_exit(NULL);
	return 0;
}

int ProxyAddServer(struct mansession *s, struct message *m) {
	struct message mo;
	struct ast_server *srv;
	int res = 0;

	/* malloc ourselves a server credentials structure */
	srv = malloc(sizeof(struct ast_server));
	if ( !srv ) {
		fprintf(stderr, "Failed to allocate server credentials: %s\n", strerror(errno));
		exit(1);
	}

	memset(srv, 0, sizeof(struct ast_server) );
	memset(&mo, 0, sizeof(struct message));
	strcpy(srv->ast_host, astman_get_header(m, "Server"));
	strcpy(srv->ast_user, astman_get_header(m, "Username"));
	strcpy(srv->ast_pass, astman_get_header(m, "Secret"));
	strcpy(srv->ast_port, astman_get_header(m, "Port"));
	strcpy(srv->ast_events, astman_get_header(m, "Events"));

	if (*srv->ast_host && *srv->ast_user && *srv->ast_pass && *srv->ast_port && *srv->ast_events) {
		pthread_mutex_lock(&serverlock);
		srv->next = pc.serverlist;
		pc.serverlist = srv;
		pthread_mutex_unlock(&serverlock);
		res = StartServer(srv);
	} else
		res = 1;

	if (res) {
		AddHeader(&mo, "ProxyResponse: Failure");
		AddHeader(&mo, "Message: Could not add %s", srv->ast_host);
	} else {
		AddHeader(&mo, "ProxyResponse: Success");
		AddHeader(&mo, "Message: Added %s", srv->ast_host);
	}

	s->output->write(s, &mo);
	return 0;
}

int ProxyDropServer(struct mansession *s, struct message *m) {
	struct message mo;
	struct mansession *srv;
	char *value;
	int res;

	memset(&mo, 0, sizeof(struct message));
	value = astman_get_header(m, "Server");
	srv = sessions;
	while (*value && srv) {
		if (srv->server && !strcmp(srv->server->ast_host, value))
			break;
		srv = srv->next;
	}

	if (srv) {
		destroy_session(srv);
		debugmsg("Dropping Server %s", value);
		AddHeader(&mo, "ProxyResponse: Success");
		AddHeader(&mo, "Message: Dropped %s", value);
		res = 0;
	} else {
		debugmsg("Failed to Drop Server %s -- not found", value);
		AddHeader(&mo, "ProxyResponse: Failure");
		AddHeader(&mo, "Message: Cannot Drop Server %s, Does Not Exist", value);
		res = 1;
	}

	s->output->write(s, &mo);
	return res;
}

void *ProxyListServers(struct mansession *s) {
	struct message m;
	struct mansession *c;
	char iabuf[INET_ADDRSTRLEN];

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "ProxyResponse: Success");

	c = sessions;
	while (c) {
		if (c->server) {
			AddHeader(&m, "ProxyListServer I: %s H: %s U: %s P: %s E: %s ",
			ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr),
			c->server->ast_host, c->server->ast_user,
			c->server->ast_port, c->server->ast_events);
		}

		c = c->next;
	}
	s->output->write(s, &m);
	return 0;
}


void *proxyaction_do(char *proxyaction, struct message *m, struct mansession *s)
{
	if (!strcasecmp(proxyaction,"SetOutputFormat"))
		ProxySetOutputFormat(s, m);
	else if (!strcasecmp(proxyaction,"SetAutoFilter"))
		ProxySetAutoFilter(s, m);
	else if (!strcasecmp(proxyaction,"ListSessions"))
		ProxyListSessions(s);
	else if (!strcasecmp(proxyaction,"AddServer"))
		ProxyAddServer(s, m);
	else if (!strcasecmp(proxyaction,"DropServer"))
		ProxyDropServer(s, m);
	else if (!strcasecmp(proxyaction,"ListServers"))
		ProxyListServers(s);
	else if (!strcasecmp(proxyaction,"ListIOHandlers"))
		ProxyListIOHandlers(s);
	else if (!strcasecmp(proxyaction,"Logoff"))
		ProxyLogoff(s);
	else
	proxyerror_do(s, "Invalid Proxy Action");

	return 0;
}

int proxyerror_do(struct mansession *s, char *err)
{
	struct message mo;

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "ProxyResponse: Error");
	AddHeader(&mo, "Message: %s", err);

	s->output->write(s, &mo);

	return 0;
}

int ValidateAction(struct message *m, struct mansession *s, int inbound) {
	char *channel, *channel1, *channel2;
	char *context;
	char *uchannel;
	char *ucontext;

	if( pc.authrequired && !s->authenticated )
		return 0;

	if( inbound )
		ucontext = s->user.icontext;
	else
		ucontext = s->user.ocontext;
	uchannel = s->user.channel;

	channel = astman_get_header(m, "Channel");
	if( channel[0] != '\0' && uchannel[0] != '\0' )
		if( strncasecmp( channel, uchannel, strlen(uchannel) ) ) {
			if( debug )
				debugmsg("Message filtered (chan): %s != %s", channel, uchannel);
			return 0;
		}

	channel1 = astman_get_header(m, "Channel1");
	channel2 = astman_get_header(m, "Channel2");
	if( (channel1[0] != '\0' || channel2[0] != '\0') && uchannel[0] != '\0' )
		if( !(strncasecmp( channel1, uchannel, strlen(uchannel) ) == 0 ||
			  strncasecmp( channel2, uchannel, strlen(uchannel) ) == 0) ) {
			if( debug )
				debugmsg("Message filtered (chan): %s/%s != %s", channel1, channel2, uchannel);
			return 0;
		}

	context = astman_get_header(m, "Context");
	if( context[0] != '\0' && ucontext[0] != '\0' )
		if( strcasecmp( context, ucontext ) ) {
			if( debug )
				debugmsg("Message filtered (ctxt): %s != %s", context, ucontext);
			return 0;
		}

	return 1;
}

void *SendError(struct mansession *s, char *errmsg) {
	struct message m;

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "Response: Error");
	AddHeader(&m, "Message: %s", errmsg);

	s->output->write(s, &m);

	return 0;
}
