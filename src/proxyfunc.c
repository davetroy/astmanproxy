/*	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

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
	char *actionid;

	actionid = astman_get_header(m, "ActionID");
	if ( strcasecmp("MD5", astman_get_header(m, "AuthType")) ) {
		SendError(s, "Must specify AuthType", actionid);
		return 1;
	}

	if (!*s->challenge)
		snprintf(s->challenge, sizeof(s->challenge), "%d", rand());

	memset(&mo, 0, sizeof(struct message));
	AddHeader(&mo, "Response: Success");
	AddHeader(&mo, "Challenge: %s", s->challenge);
	if( actionid && strlen(actionid) )
		AddHeader(&mo, "ActionID: %s", actionid);

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
	else if ( !strcasecmp(value, "unique") )
		i = 2;
	else
		i = 0;
	pthread_mutex_lock(&s->lock);
	s->autofilter = i;
	if( i == 2 )
	  snprintf(s->actionid, MAX_LEN - 20, "amp%d-", s->fd);
	else
	  s->actionid[0] = '\0';
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
	char *user, *secret, *key, *actionid;

	user = astman_get_header(m, "Username");
	secret = astman_get_header(m, "Secret");
	key = astman_get_header(m, "Key");
	actionid = astman_get_header(m, "ActionID");

	memset(&mo, 0, sizeof(struct message));
	if( actionid && strlen(actionid) > 0 )
		AddHeader(&mo, "ActionID: %s", actionid);
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
				strcpy(s->user.account, pu->account);
				strcpy(s->user.server, pu->server);
				strcpy(s->user.more_events, pu->more_events);
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
		SendError(s, "Authentication failed", actionid);
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

/* [do_]AddToStack - Stores an event in a stack for later repetition.
		indexed on UniqueID.
   If SrcUniqueID / DestUniqueID are present, store against both.
   If a record already exists, do nothing.
   withbody = 1, saves a copy of whole message (server).
   withbody = 0, saves just the key (client).
*/
int do_AddToStack(char *uniqueid, struct message *m, struct mansession *s, int withbody)
{
	struct mstack *prev;
	struct mstack *t;

	pthread_mutex_lock(&s->lock);
	prev = NULL;
	t = s->stack;

	while( t ) {
		if( !strncmp( t->uniqueid, uniqueid, sizeof(t->uniqueid) ) )
		{
			pthread_mutex_unlock(&s->lock);
			return 0;
		}
		prev = t;
		t = t->next;
	}
	if( s->depth >= MAX_STACK ) {
		struct mstack *newtop;

		newtop = s->stack->next;
		if( s->stack->message )
			free( s->stack->message );
		free( s->stack );
		s->stack = newtop;
		s->depth--;
	}
	if( (t = malloc(sizeof(struct mstack))) ) {
		memset(t, 0, sizeof(struct mstack));
		strncpy( t->uniqueid, uniqueid, sizeof(t->uniqueid) );
		s->depth++;
		if( prev )
			prev->next = t;
		else
			s->stack = t;
		if( withbody ) {
			// Save the message, in a reduced form to save memory...
			int m_size;
			int i, j;
			m_size = 1;
			j = 0;
			for( i = 0; i < m->hdrcount; i++ ) {
				m_size += strlen(m->headers[i])+1;
			}
			if( m_size < MAX_STACKDATA && (t->message = malloc(m_size)) ) {
				memset(t->message, 0, m_size);
				for( i = 0; i < m->hdrcount; i++ ) {
					strncpy( t->message + j, m->headers[i], m_size - j );
					*(t->message + j + strlen(m->headers[i])) = '\n';
					j += strlen(m->headers[i]) + 1;
				}
			}
		}
		if( debug ) {
			debugmsg("Added uniqueid: %s to %s stack", uniqueid, withbody?"server":"client");
			if( t->message)
				debugmsg("Cached message: %s", t->message);
		}
	}
	pthread_mutex_unlock(&s->lock);
	return 1;
}
int AddToStack(struct message *m, struct mansession *s, int withbody)
{
	char *uniqueid;
	int ret, absent;

	ret=0;
	absent=0;

	uniqueid = astman_get_header(m, "Uniqueid");
	if( uniqueid[0] != '\0' ) {
		if( do_AddToStack(uniqueid, m, s, withbody) )
			ret |= ATS_UNIQUE;
	} else
		absent++;

	uniqueid = astman_get_header(m, "SrcUniqueID");
	if( uniqueid[0] != '\0' ) {
		if( do_AddToStack(uniqueid, m, s, withbody) )
			ret |= ATS_SRCUNIQUE;
	} else
		absent++;

	uniqueid = astman_get_header(m, "DestUniqueID");
	if( uniqueid[0] != '\0' ) {
		if( do_AddToStack(uniqueid, m, s, withbody) )
			ret |= ATS_DSTUNIQUE;
	} else
		absent++;

	if( s->user.more_events[0] != '\0' && absent == 3 )
		return 1;	// Want more/anonymous events
	return ret;
}


/* DelFromStack - Removes an item from the stack based on the UniqueID field.
*/
void DelFromStack(struct message *m, struct mansession *s)
{
	char *uniqueid;
	struct mstack *prev;
	struct mstack *t;

	uniqueid = astman_get_header(m, "Uniqueid");
	if( uniqueid[0] == '\0' )
		return;

	pthread_mutex_lock(&s->lock);
	prev = NULL;
	t = s->stack;

	while( t ) {
		if( !strncmp( t->uniqueid, uniqueid, sizeof(t->uniqueid) ) )
		{
			if( t->message )
				free( t->message );
			if( prev )
				prev->next = t->next;
			else
				s->stack = t->next;
			free( t );
			s->depth--;
			if( debug )
				debugmsg("Removed uniqueid: %s from stack", uniqueid);
			break;
		}
		prev = t;
		t = t->next;
	}
	pthread_mutex_unlock(&s->lock);
}

/* FreeStack - Removes all items from stack.
 */
void FreeStack(struct mansession *s)
{
	struct mstack *t, *n;

	pthread_mutex_lock(&s->lock);
	t = s->stack;

	while( t ) {
		n = t->next;	// Grab next entry BEFORE we free the slot
		if( t->message )
			free( t->message );
		free( t );
		t = n;
		s->depth--;
	}
	s->stack = NULL;
	if( debug && s->depth > 0 )
		debugmsg("ALERT! Stack may have leaked %d slots!!!", s->depth);
	if( debug )
		debugmsg("Freed entire stack.");
	pthread_mutex_unlock(&s->lock);
}

/* IsInStack - If the message has a UniqueID, and it is in the stack...
 */
int IsInStack(char* uniqueid, struct mansession *s)
{
	struct mstack *t;

	pthread_mutex_lock(&s->lock);
	t = s->stack;

	while( t ) {
		if( !strncmp( t->uniqueid, uniqueid, sizeof(t->uniqueid) ) )
		{
			pthread_mutex_unlock(&s->lock);
			return 1;
		}
		t = t->next;
	}
	pthread_mutex_unlock(&s->lock);
	return 0;
}

/* ResendFromStack - We want to resend a cached message from the stack please...
 * Look for "uniqueid" in cache of session "s", and reconstruct into message "m"
 */
void ResendFromStack(char* uniqueid, struct mansession *s, struct message *m)
{
	struct mstack *t;

	if( !m )
		return;

	if( debug )
		debugmsg("ResendFromStack: %s", uniqueid);

	pthread_mutex_lock(&s->lock);
	t = s->stack;

	while( t ) {
		if( !strncmp( t->uniqueid, uniqueid, sizeof(t->uniqueid) ) )
		{
			// Got message, pull from cache.
			int i, h, j;
			for( i=0,h=0,j=0; i<strlen(t->message) && i < MAX_STACKDATA-1 && h < MAX_HEADERS; i++ ) {
				if( t->message[i] == '\n' || i-j >= 80 ) {
					strncpy( m->headers[h], t->message + j, i-j );
					m->headers[h][79] = '\0';
					j = i + 1;
					if( debug )
						debugmsg("remade: %s", m->headers[h]);
					h++;
				}
			}
			m->hdrcount = h;
			pthread_mutex_unlock(&s->lock);
			return;
		}
		t = t->next;
	}
	pthread_mutex_unlock(&s->lock);
	return;
}

int ValidateAction(struct message *m, struct mansession *s, int inbound) {
	char *channel, *channel1, *channel2;
	char *context;
	char *uchannel;
	char *ucontext;
	char *action;
	char *actionid;
	char *event;
	char *response;
	char *account;
	char *uniqueid;

	if( pc.authrequired && !s->authenticated )
		return 0;

	if( inbound )	// Inbound to client from server
		ucontext = s->user.icontext;
	else		// Outbound from client to server
		ucontext = s->user.ocontext;
	uchannel = s->user.channel;

	// There is no filering, so just return quickly.
	if( uchannel[0] == '\0' && ucontext[0] == '\0' && s->user.account[0] == '\0' )
		return 1;

	event = astman_get_header(m, "Event");
	uniqueid = astman_get_header(m, "Uniqueid");
	if( uniqueid[0] != '\0' && IsInStack(uniqueid, s) ) {
		if( debug )
			debugmsg("Message passed (uniqueid): %s already allowed", uniqueid);
		if( !strcasecmp( event, "Hangup" ) )
			DelFromStack(m, s);
		return 1;
	}
	uniqueid = astman_get_header(m, "Uniqueid1");
	if( uniqueid[0] != '\0' && IsInStack(uniqueid, s) ) {
		if( debug )
			debugmsg("Message passed (uniqueid1): %s already allowed", uniqueid);
		if( !strcasecmp( event, "Hangup" ) )
			DelFromStack(m, s);
		return 1;
	}
	uniqueid = astman_get_header(m, "Uniqueid2");
	if( uniqueid[0] != '\0' && IsInStack(uniqueid, s) ) {
		if( debug )
			debugmsg("Message passed (uniqueid2): %s already allowed", uniqueid);
		if( !strcasecmp( event, "Hangup" ) )
			DelFromStack(m, s);
		return 1;
	}

	// Response packets rarely have any of the following fields included, so
	// we will return a response if the ActionID matches our last known ActionID
	response = astman_get_header(m, "Response");
	actionid = astman_get_header(m, ACTION_ID);
	if( response[0] != '\0' && actionid[0] != '\0' && !strcmp(actionid, s->actionid) ) {
		if (s->autofilter < 2 && !strcmp(actionid, s->actionid))
			return 1;
		else if ( !strncmp(actionid, s->actionid, strlen(s->actionid)) )
			return 1;
	}

	if( uchannel[0] != '\0' ) {
		channel = astman_get_header(m, "Channel");
		if( channel[0] != '\0' ) {	// We have a Channel: header, so filter on it.
			if( strncasecmp( channel, uchannel, strlen(uchannel) ) ) {
				if( debug )
					debugmsg("Message filtered (chan): %s != %s", channel, uchannel);
				return 0;
			}
		} else {			// No Channel: header, what about Channel1: or Channel2: ?
			channel1 = astman_get_header(m, "Channel1");
			channel2 = astman_get_header(m, "Channel2");
			if( channel1[0] != '\0' || channel2[0] != '\0' ) {
				if( !(strncasecmp( channel1, uchannel, strlen(uchannel) ) == 0 ||
					  strncasecmp( channel2, uchannel, strlen(uchannel) ) == 0) ) {
					if( debug )
						debugmsg("Message filtered (chan1/2): %s/%s != %s", channel1, channel2, uchannel);
					return 0;
				}
			} else {		// No? What about Source: and Destination:
				channel1 = astman_get_header(m, "Source");
				channel2 = astman_get_header(m, "Destination");
				if( channel1[0] != '\0' || channel2[0] != '\0' ) {
					if( !(strncasecmp( channel1, uchannel, strlen(uchannel) ) == 0 ||
						  strncasecmp( channel2, uchannel, strlen(uchannel) ) == 0) ) {
						if( debug )
							debugmsg("Message filtered (src/dst chan): %s/%s != %s", channel1, channel2, uchannel);
						return 0;
					}
				}
			}
		}
	}

	context = astman_get_header(m, "Context");
	if( context[0] != '\0' && ucontext[0] != '\0' )
		if( strcasecmp( context, ucontext ) ) {
			if( debug )
				debugmsg("Message filtered (ctxt): %s != %s", context, ucontext);
			return 0;
		}

	if( s->user.account[0] != '\0' ) {
		action = astman_get_header(m, "Action");
		account = astman_get_header(m, "Account");
		if( !strcasecmp( action, "Originate" ) ) {
			if( debug )
				debugmsg("Got Originate. Account: %s, setting to: %s", account, s->user.account);
			if( account[0] == '\0' )
				AddHeader(m, "Account: %s", s->user.account);
			else
				strcpy(account, s->user.account);
		} else if( account[0] != '\0' ) {
			if( debug )
				debugmsg("Got Account: %s, setting to: %s", account, s->user.account);
			strcpy(account, s->user.account);
		}
	}

	if( inbound ) {
		int res;
		res = AddToStack(m, s, 0);
		if( debug > 5 )
			debugmsg("AddToStack returned %d", res);
		return res;
	}
	return 1;
}

void *SendError(struct mansession *s, char *errmsg, char *actionid) {
	struct message m;

	memset(&m, 0, sizeof(struct message));
	AddHeader(&m, "Response: Error");
	AddHeader(&m, "Message: %s", errmsg);
	if( actionid && strlen(actionid) )
		AddHeader(&m, "ActionID: %s", actionid);

	s->output->write(s, &m);

	return 0;
}
