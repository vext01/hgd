/*
 * Copyright (c) 2011, Edd Barrett <vext01@gmail.com>
 * Copyright (c) 2011, Martin Ellis <ellism88@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __NET_H
#define __NET_H

#define HGD_PROTO_VERSION_MAJOR	16
#define HGD_PROTO_VERSION_MINOR 0

/* networking */
#define HGD_DFL_PORT		6633
#define HGD_DFL_HOST		"127.0.0.1"
#define HGD_DFL_BACKLOG		10
#define HGD_DFL_MAX_UPLOAD	(HGD_MB * 100L)
#define HGD_MAX_LINE		256
#define HGD_MAX_BAD_COMMANDS	3
#define HGD_BINARY_CHUNK	4096
#define HGD_BINARY_RECV_SZ	16384
#define	HGD_MAX_PROTO_TOKS	3

/*
 * hgd-netd error, hello and goodbye responses.
 * If these change, major bump the network protocol.
 *
 * please do not pluralise these.
 */
#define HGD_RESP_O_GREET	"HGD-" HGD_VERSION
#define HGD_RESP_O_BYE		"Catch you later d00d!"

#define HGD_RESP_E_INT		"E_INT"		/* Internal error */
#define HGD_RESP_E_DENY		"E_DENY"	/* Access denied */
#define HGD_RESP_E_FLSIZE	"E_FLSIZE"	/* File size invalid */
#define HGD_RESP_E_FLOOD	"E_FLOOD"	/* Flood protect triggered */
#define HGD_RESP_E_NOPLAY	"E_NOPLAY"	/* No track is playing */
#define HGD_RESP_E_WRTRK	"E_WRTRK"	/* Wrong track */
#define HGD_RESP_E_DUPVOTE	"E_DUPVOTE"	/* Duplicate vote */
#define HGD_RESP_E_SSLAGN	"E_SSLAGN"	/* Duplicate SSL negotiation */
#define HGD_RESP_E_SSLNOAVAIL	"E_SSLNOAVAIL"	/* SSL not available */
#define HGD_RESP_E_INVCMD	"E_INVCMD"	/* Invalid command */
#define HGD_RESP_E_SSLREQ	"E_SSLREQ"	/* SSL required */
#define HGD_RESP_E_SHTDWN	"E_SHTDWN"	/* Server is going down */
#define HGD_RESP_E_KICK		"E_KICK"	/* Client misbehaving */
#define HGD_RESP_E_PERMNOCHG	"E_PERMNOCHG"	/* Perms did not change */
#define HGD_RESP_E_USREXIST	"E_USREXIST"	/* User already exists */
#define HGD_RESP_E_USRNOEXIST	"E_USRNOEXIST"	/* User does not exist */

/* SSL */
#define HGD_DFL_CERT_FILE	HGD_DFL_SVR_CONF_DIR "/certificate.crt"
#define HGD_DFL_KEY_FILE	HGD_DFL_SVR_CONF_DIR "/privkey.key"

#define	HGD_CRYPTO_PREF_ALWAYS	0
#define HGD_CRYPTO_PREF_IF_POSS	1
#define HGD_CRYPTO_PREF_NEVER	2

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PRINT_SSL_ERR(level, msg)					\
	do {								\
		char error[255];					\
		unsigned long err;					\
		err = ERR_get_error();					\
		ERR_error_string_n(err, error, sizeof(error));		\
		DPRINTF(level, "%s: %s", msg, error);		\
	} while(0)

void				 hgd_cleanup_ssl(SSL_CTX **ssl);
void				 hgd_sock_send(int fd, char *msg);
void				 hgd_sock_send_line(int fd, SSL* ssl,
				     char *msg);
char				*hgd_sock_recv_bin(int fd, SSL* ssl,
				     ssize_t len);
char				*hgd_sock_recv_line(int fd, SSL* ssl);
void				 hgd_sock_send_bin(int fd, SSL* ssl,
				     char *, ssize_t);
int				 hgd_setup_ssl_ctx(SSL_METHOD **method,
				     SSL_CTX **ctx, int server,
				     char *, char *);
uint8_t				 hgd_is_ip_addr(char *str);

#endif
