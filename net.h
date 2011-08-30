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

#define HGD_PROTO_VERSION_MAJOR	5
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
#define HGD_GREET		"ok|HGD-" HGD_VERSION
#define HGD_BYE			"ok|Catch you later d00d!"

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
