/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2008, Tello Corporation, Inc.
 *
 * Remco Treffkorn(Architect) and Mahesh Karoshi(Senior Software Developer)
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.

   We use negative file descriptors for secure channels. The file descriptor
   -1 is reseved for errors. -2 to -... are secure file descriptors. 0  to ...
   are regular file descriptors.

   NOTE: Commonly error checks for routines returning fd's are done with (value<0).
   You must check for (value==-1) instead, since all other negative fd's now
   are valid fd's.
*/
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "ssl.h"

SSL_CTX *sctx;
SSL_CTX *cctx;
static long rec_bytes;
static long sent_bytes;
static int ssl_initialized;


/*! \brief this has to be called before any other function dealing with ssl.
   Initializes all the ssl related stuff here.  */
int init_secure(char *certfile)
{
	SSL_METHOD *meth;

	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();

	/* server init */
	meth = SSLv23_server_method();
	sctx = SSL_CTX_new(meth);

	if (!sctx) {
		return errexit("Failed to create a server ssl context!");
	}

	if (SSL_CTX_use_certificate_file(sctx, certfile, SSL_FILETYPE_PEM) <= 0) {
		return errexit("Failed to use the certificate file!");
	}

	if (SSL_CTX_use_PrivateKey_file(sctx, certfile, SSL_FILETYPE_PEM) <= 0) {
		return errexit("Failed to use the key file!\n");
	}

	if (!SSL_CTX_check_private_key(sctx)) {
		return errexit("Private key does not match the certificate public key");
	}
	ssl_initialized = 1;
	return 0;
}


/*	  Initializes all the client-side ssl related stuff here.
*/
int client_init_secure(void)
{
	SSL_METHOD *meth;

	/* client init */
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_client_method();
	SSL_load_error_strings();
	cctx = SSL_CTX_new (meth);

	if (!cctx)
		debugmsg("Failed to create a client ssl context!");
	else
		debugmsg("Client SSL Context Initialized");
	return 0;
}

/*! \brief Takes the negative ssl fd and returns the positive fd recieved from the os. 
 * 	It goes through arrray of fixed maximum number of secured channels. 
*/
int get_real_fd(int fd)
{
	if (fd<-1) {
		fd =  -fd - 2;
		if (fd>=0 && fd <SEC_MAX)
				fd = sec_channel[fd].fd;
		else fd = -1;

	}
	return fd;
}

/*! \brief	Returns the SSL pointer from the fd. This structure is filled when we accept 
 *	 the ssl connection and used 
 *	 for reading and writing through ssl.
*/
SSL *get_ssl(int fd)
{
	SSL *ssl = NULL;

	fd = -fd - 2;

	if (fd>=0 && fd <SEC_MAX)
		ssl = sec_channel[fd].ssl;

	return ssl;
}

/*! \brief	Returns the empty ssl slot. Used to save ssl information.
*/
int sec_getslot(void)
{
	int i;

	for (i=0; i<SEC_MAX; i++) {
		if(sec_channel[i].ssl==NULL)
				break;
	}

	if (i==SEC_MAX)
		return -1;
	return i;
}

/*! \brief	 Accepts the ssl connection. Returns the negative fd. negative fd's are 
 *	chosen to differentiate between ssl and non-ssl connections. Positive 
 *	fd's are used for non-ssl connections and negative fd's are used for ssl 
 *	connections. So we purposefully calculate and return negative fds. 
 *	You can always get positive fd by calling get_real_fd(negative fd). 
 *	The positive fd's are required for system calls.
 *
*/
int saccept(int s)
{
	int fd, err;
	SSL* ssl;

	if (!ssl_initialized)
		return s;

	if (((fd=sec_getslot())!=-1))  {
		ssl=SSL_new(sctx);
		SSL_set_fd(ssl, s);
		sec_channel[fd].ssl = ssl;	/* remember ssl */
		sec_channel[fd].fd = s;		/* remember the real fd */
		do {
			err = SSL_accept(ssl);
			err = SSL_get_error(ssl, err);
		} while( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE);

		SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
		debugmsg("ssl_addon: Connection accepted");

		err=1;

		fd = -(fd+2);

		if (err!=1 || !ssl) {
			/* it did not work */
			sec_channel[fd].ssl = NULL;	/* free the slot */
			fd = -1;
		}
	}
	return fd;
}

/*!	
 * \brief Writes through secured ssl connection 
*/
int m_send(int fd, const void *data, size_t len)
{
	sent_bytes += len;

	if (fd < -1) {
		SSL* ssl = get_ssl(fd);
		return SSL_write(ssl, data, len);
	}
	return write(fd, data, len);
}

/*!
 * \brief	Receives data from the SSL connection. 
*/
int m_recv(int s, void *buf, size_t len, int flags)
{
	int ret = 0;

	if (s<-1) {
		SSL* ssl = get_ssl(s);
		ret = SSL_read (ssl, buf, len);
	} else
		ret = recv(s, buf, len, flags);

	if (ret > 0)
		rec_bytes += ret;

	if (debug && s<-1)
		debugmsg("Received %d bytes from SSL socket", ret);
	return ret;
}


/*! \brief
	Needs to be called instead of close() to close a socket.
	It also closes the SSL meta connection.
*/

int close_sock(int socket)
{
	int ret=0;
	SSL* ssl = NULL;

	if (socket < -1) {
		socket = - socket - 2;

		ssl = sec_channel[socket].ssl;
		sec_channel[socket].ssl = NULL;
		socket = sec_channel[socket].fd;
	}

	ret= close(get_real_fd(socket));

	if (ssl)
		SSL_free (ssl);

	return(ret);
}

/*! \brief This process cannot continue without fixing this error. 
*/
int errexit(char s[])
{
		debugmsg("SSL critical error: %s", s);
	return -1;
}

/*!  \brief Checks whether the client is requesting an ssl encrypted connection or not. If its encrypted
 *   request we expect "Client Hello" in the beginning of the message and ssl version 2.
 *   This can be verified by checking buf[0x02], buf[0x03] and buf[0x04]. If the contents are
 *   0x01, 0x00, 0x02, then its an ssl packet with content "Client Hello", "SSL version 2".
 *   For SSL version 3, we might need to check for 0x01, 0x00, 0x03.
 *
*/
int is_encrypt_request(int sslclhellotimeout, int fd)
{
	fd_set listeners;
	struct timeval tv;
	char buf[1024];
	int ready_fdescriptors;
	int ret;

	tv.tv_sec = 0;
	tv.tv_usec = sslclhellotimeout * 1000;

	FD_ZERO(&listeners);
	FD_SET(fd, &listeners);

	ready_fdescriptors = select (fd + 1, &listeners, NULL, NULL, &tv);

	if (ready_fdescriptors < 0 ) {
		debugmsg("is_encrypt_request: select returned error, This should not happen:");
		return 0;
	} else if (ready_fdescriptors == 0) {
		return 0;
	}
	ret = recv(fd, buf, 100, MSG_PEEK);
	if(ret > 0) {
			/* check for sslv3  or tls*/
			if ((buf[0x00] == 0x16) && (buf[0x01] == 0x03) &&
			/* for tls buf[0x02] = 0x01 and ssl v3 buf[0x02] = 0x02 */
			((buf[0x02] == 0x00) || (buf[0x02] == 0x01))) {
			if (debug)
					debugmsg("Received a SSL request");
			return 1;
		/* check for sslv23_client_method */
		} else if ((buf[0x02] == 0x01) && (buf[0x03] == 0x03) && (buf[0x04] == 0x01)) {
			if (debug)
					debugmsg("Received a SSL request for SSLv23_client_method()");
			return 1;
		}
		/* check for sslv2 and return -1 */
		else if ((buf[0x02] == 0x01) && (buf[0x03] == 0x00) && (buf[0x04] == 0x02)) {
			if (debug)
					debugmsg("Received a SSLv2 request()");
				return -1;
		}
	}
	return 0;
}


/* Connects to an asterisk server either plain or SSL as appropriate
*/
int ast_connect(struct mansession *a) {
	int s, err=-1, fd;
	SSL* ssl;

	fd = connect_nonb(a);
	if ( fd < 0 )
	return -1;

	if (a->server->use_ssl) {
	debugmsg("initiating ssl connection");
	if ((s=sec_getslot())!=-1) {	/* find a slot for the ssl handle */
		sec_channel[s].fd = fd;	 /* remember the real fd */

		if((ssl=SSL_new(cctx))) {	   /* get a new ssl */
		sec_channel[s].ssl = ssl;
		SSL_set_fd(ssl, fd);	/* and attach the real fd */
		err = SSL_connect(ssl); /* now try and connect */
		} else
		debugmsg("couldn't create ssl client context");
		fd = -(s+2);			/* offset by two and negate */
					/* this tells us it is a ssl fd */
	} else
		debugmsg("couldn't get SSL slot!");

	if (err==-1) {
		close_sock(fd);		 /* that frees the ssl too */
		fd = -1;
	}
	}

	debugmsg("returning ast_connect with %d", fd);
	pthread_mutex_lock(&a->lock);
	a->fd = fd;
	pthread_mutex_unlock(&a->lock);

	return fd;
}

int connect_nonb(struct mansession *a)
{
	int				 flags, n, error;
	socklen_t		   len;
	fd_set		  rset, wset;
	struct timeval  tval;
	int nsec = 1, sockfd;

	sockfd = get_real_fd(a->fd);

	flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	error = 0;
	if ( (n = connect(sockfd, (struct sockaddr *) &a->sin, sizeof(a->sin)) ) < 0 ) {
		/* TODO: This seems like the nine pound hammer to me... */
		/* perhaps something a bit more elegant; errno seems to change too */
		if (errno == EISCONN || errno == 103 || errno==111) {
			debugmsg("connect_nonb: error %d, closing old fd and grabbing a new one...", errno);
			/* looks like our old socket died, let's round up a new one and try again */
			close_sock(a->fd);
			pthread_mutex_lock(&a->lock);
			a->fd = socket(AF_INET, SOCK_STREAM, 0);
			pthread_mutex_unlock(&a->lock);
			return(-1);
		}
		if (errno != EINPROGRESS)
			return(-1);
	}

	/* Do whatever we want while the connect is taking place. */

	if (n == 0)
		goto done;	  /* connect completed immediately */

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tval.tv_sec = nsec;
	tval.tv_usec = 0;

	if ( (n = select(sockfd+1, &rset, &wset, NULL,
					 nsec ? &tval : NULL)) == 0) {
		/*close(sockfd);*/		  /* we want to retry */
		errno = ETIMEDOUT;
		return(-1);
	}

	if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
		len = sizeof(error);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return(-1);			 /* Solaris pending error */
	} else {
		/*err_quit("select error: sockfd not set");*/
		logmsg("select error: sockfd not set");
		return(-1);
	}

done:
	fcntl(sockfd, F_SETFL, flags);  /* restore file status flags */

	if (error) {
		/* close(sockfd); */	/* disable for now, we want to retry... */
		errno = error;
		return(-1);
	}
	return(sockfd);
}
