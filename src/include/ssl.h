/*
 * ssl_addon: Encrypts the asterisk management interface
 *
 * Copyrights:
 * Copyright (C) 2005-2008, Tello Corporation, Inc.
 *
 * Contributors:
 * Remco Treffkorn(Architect) and Mahesh Karoshi
 *
 * This program is free software, distributed under the terms of
 * the GNU Lesser (Library) General Public License
 *
 * Copyright on this file is disclaimed to Digium for inclusion in Asterisk
 */

#ifndef _SSL_ADDON_H_
#define _SSL_ADDON_H_

#include <openssl/ssl.h>
#include "astmanproxy.h"

int connect_nonb(struct mansession *a);

/*! \brief
   This data structure holds the additional SSL data needed to use the ssl functions.
   The negative fd is used as an index into this data structure (after processing).
   Choose SEC_MAX to be impossibly large for the application.
*/
#define SEC_MAX 16
struct {
    int fd;
    SSL* ssl;
} sec_channel[SEC_MAX];

/*! \brief
   this has to be called before any other function dealing with ssl.
*/
int init_secure(char* certfile);

/*! \brief
   Returns the real fd, that is received from os, when we accept the connection.
*/
int get_real_fd(int fd);

/*!  \brief
   Returns the ssl structure from the fd.  
*/
SSL *get_ssl(int fd);

/*! \brief
   Returns the availabe security slot. This restricts the maximun number of security connection, 
   the asterisk server can have for AMI. 
*/
int sec_getslot(void);

/*! \brief
   Accepts the connection, if the security is enabled it returns the negative fd. -1 is flase, -2, -3 
   etc are ssl connections. 
*/ 
int saccept(int s);

/*!  \brief
   Sends the data over secured or unsecured connections. 
*/ 
int m_send(int fd, const void *data, size_t len);


/*! \brief
   Receives the connection from either ssl or fd.
*/
int m_recv(int s, void *buf, size_t len, int flags);


/*! \brief
  Needs to be called instead of close() to close a socket.
  It also closes the ssl meta connection.
*/

int close_sock(int socket);

int errexit(char s[]);

int is_encrypt_request(int sslclhellotimeout, int fd);
#ifdef __cplusplus
}
#endif


#endif
