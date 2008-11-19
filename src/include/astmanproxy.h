#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <dlfcn.h>
#ifdef __APPLE__
	#include "poll-compat.h"
#else
	#include <sys/poll.h>
#endif

#define BUFSIZE		 1024
#define MAX_HEADERS	 256
#define MAX_LEN		 1024
#define MAX_STACK	 1024
#define MAX_STACKDATA	 32768

#define ATS_RESERVED    1
#define ATS_UNIQUE      2
#define ATS_SRCUNIQUE   4
#define ATS_DSTUNIQUE   8

#define PROXY_BANNER	"Asterisk Call Manager Proxy"
#define PROXY_SHUTDOWN  "ProxyMessage: Proxy Shutting Down"
#define ACTION_ID		"ActionID"

struct ast_server {
	char nickname[80];
	char ast_host[40];
	char ast_port[10];
	char ast_user[80];
	char ast_pass[80];
	char ast_events[10];
	int use_ssl;		/* Use SSL when Connecting to Server? */
	int status;			/* TODO: have this mean something */
	struct ast_server *next;
};

struct proxy_user {
	char username[80];
	char secret[80];
	char channel[80];
	char icontext[80];
	char ocontext[80];
	char account[80];
	char server[80];
	char more_events[2];
	struct proxy_user *next;
};

struct proxyconfig {
	struct ast_server *serverlist;
	struct proxy_user *userlist;
	char listen_addr[INET_ADDRSTRLEN];
	int listen_port;
	char inputformat[80];
	char outputformat[80];
	int autofilter;			/* enable autofiltering? */
	int authrequired;			/* is authentication required? */
	char key[80];
	char proc_user[40];
	char proc_group[40];
	char logfile[256];
	int retryinterval;
	int maxretries;
	int asteriskwritetimeout;		/* ms to wait when writing to asteriskfor ast_carefulwrite */
	int clientwritetimeout;		/* ms to wait when writing to client ast_carefulwrite */
	int sslclhellotimeout;		/* ssl client hello timeout -- how long to wait before assuming not ssl */
	int acceptencryptedconnection;	/* accept encrypted connections? */
	int acceptunencryptedconnection;	/* accept unencrypted connections? */
	char certfile[256];			/* our SERVER-side SSL certificate file */
};

struct iohandler {
	int (*read) ();
	int (*write) ();
	int (*onconnect) ();
	char formatname[80];
	void *dlhandle;
	struct iohandler *next;
};

struct mstack {
	struct mstack *next;
	char uniqueid[80];
	char *message;
};

struct mansession {
	pthread_t t;
	pthread_mutex_t lock;
	struct sockaddr_in sin;
	int fd;
	char inbuf[MAX_LEN];
	int inlen;
	struct iohandler *input;
	struct iohandler *output;
	int autofilter;
	int authenticated;
	int connected;
	int dead;				/* Whether we are dead */
	int busy;				/* Whether we are busy */
	int inputcomplete;			/* Whether we want any more input from this session (http) */
	int outputcomplete;			/* Whether output to this session is done (http) */
	struct ast_server *server;
	struct proxy_user user;
	char actionid[MAX_LEN];
	char challenge[10];			/*! Authentication challenge */
	int writetimeout;  			/* Timeout for ast_carefulwrite() */
	struct mstack *stack;
	int depth;
	struct mansession *next;
};

struct message {
	int hdrcount;
	char headers[MAX_HEADERS][MAX_LEN];
	int in_command;
	struct mansession *session;
};

struct proxyconfig pc;
extern int debug;

/* Common Function Prototypes */
void debugmsg (const char *, ...);
const char *ast_inet_ntoa(char *buf, int bufsiz, struct in_addr ia);
int AddHeader(struct message *m, const char *fmt, ...);
void debugmsg (const char *fmt, ...);
void logmsg (const char *fmt, ...);

int StartServer(struct ast_server *srv);
int WriteAsterisk(struct message *m);
char *astman_get_header(struct message *m, char *var);
int proxyerror_do(struct mansession *s, char *err);
int get_input(struct mansession *s, char *output);
int SetIOHandlers(struct mansession *s, char *ifmt, char *ofmt);
void destroy_session(struct mansession *s);
int ast_carefulwrite(int fd, char *s, int len, int timeoutms);
extern void *SendError(struct mansession *s, char *errmsg, char *actionid);

int close_sock(int socket);
int ProxyChallenge(struct mansession *s, struct message *m);
int ast_connect(struct mansession *a);
int is_encrypt_request(int sslclhellotimeout, int fd);
int saccept(int s);
int get_real_fd(int fd);
int client_init_secure(void);
int init_secure(char *certfile);
int m_send(int fd, const void *data, size_t len);
int m_recv(int s, void *buf, size_t len, int flags);
