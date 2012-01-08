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

#define _GNU_SOURCE	/* linux */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <libgen.h>

#ifdef __linux__
#include <bsd/readpassphrase.h>
#else
#include <readpassphrase.h>
#endif

#include "client.h"
#include "config.h"
#include "hgd.h"
#include "net.h"
#include "user.h"
#ifdef HAVE_LIBCONFIG
#include "cfg.h"
#endif

char			*user = NULL, *host = NULL, *password = NULL;
int			 port = HGD_DFL_PORT;
int			 sock_fd = -1;
uint8_t			 max_playlist_items = 0;

SSL			*ssl = NULL;
SSL_METHOD		*method;
SSL_CTX			*ctx;
uint8_t			 crypto_pref = HGD_CRYPTO_PREF_IF_POSS;
uint8_t			 server_ssl_capable = 0;
uint8_t			 authenticated = 0;
uint8_t			 hud_refresh_speed = 5;
uint8_t			 colours_on = 1;

struct hgd_resp_err hgd_resp_errs[] = {
	{ "E_INT",		"Internal error" },
	{ "E_DENY",		"Access denied" },
	{ "E_FLSIZE",		"File size invalid" },
	{ "E_FLOOD",		"Flood protect triggered" },
	{ "E_NOPLAY",		"No track is playing" },
	{ "E_WRTRK",		"Wrong track" },
	{ "E_DUPVOTE",		"Duplicate vote" },
	{ "E_SSLAGN",		"Duplicate SSL negotiation" },
	{ "E_SSLNOAVAIL",	"SSL not available" },
	{ "E_INVCMD",		"Invalid command" },
	{ "E_SSLREQ",		"SSL required" },
	{ "E_SHTDWN",		"Server is going down" },
	{ "E_KICK",		"Client misbehaving" },
	{ "E_PERMNOCHG",	"Perms did not change" },
	{ "E_USREXIST",		"User already exists" },
	{ "E_USRNOEXIST",	"User does not exist" },
	{ 0,			0 }
};

int
hgd_client_edit_config()
{
	char			*path = NULL, *edit_cmd = NULL;
	char			*editor = getenv("EDITOR");
	int			 ret = HGD_FAIL;

	if (editor == NULL)
		editor = HGD_DFL_EDITOR;

	xasprintf(&path, "%s/%s/%s", getenv("HOME"),
	    HGD_USR_CFG_DIR, HGD_CLI_CFG);

	xasprintf(&edit_cmd, "%s %s", editor, path);

	if (system(edit_cmd) != 0)
		goto clean;

	ret = HGD_OK;
clean:
	free(edit_cmd);
	free(path);

	return (ret);
}

int
hgd_client_login(int fd, SSL *ssl, char *username)
{
	char			*resp, *user_cmd, pass[HGD_MAX_PASS_SZ];
	int			 login_ok = -1;
	char			*prompt;

	/* XXX can't use getpassphrase in curses */
	if (password == NULL) {
		xasprintf(&prompt, "Password for %s@%s: ", user, host);
		if (readpassphrase(prompt, pass, HGD_MAX_PASS_SZ,
		    RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
			DPRINTF(HGD_D_ERROR, "Problem reading password from user");
			memset(pass, 0, HGD_MAX_PASS_SZ);
			free(prompt);
			return (HGD_FAIL);
		}
		free(prompt);
	} else {
		strncpy(pass, password, HGD_MAX_PASS_SZ);
		if (HGD_MAX_PASS_SZ > 0)
			pass[HGD_MAX_PASS_SZ-1] = '\0';
	}

	/* send password */
	xasprintf(&user_cmd, "user|%s|%s", username, pass);
	hgd_sock_send_line(fd, ssl, user_cmd);
	memset(pass, 0, HGD_MAX_PASS_SZ);
	free(user_cmd);

	resp = hgd_sock_recv_line(fd, ssl);
	login_ok = hgd_check_svr_response(resp, 0);

	free(resp);

	if (login_ok == HGD_OK) {
		authenticated = 1;
		DPRINTF(HGD_D_DEBUG, "Identified as %s", user);
	} else
		DPRINTF(HGD_D_WARN, "Login as %s failed", user);

	return (login_ok);
}

int
hgd_setup_socket()
{
	struct sockaddr_in	addr;
	char*			resp;
	struct hostent		*he;
	int			sockopt = 1, ret = HGD_OK;

	DPRINTF(HGD_D_DEBUG, "Connecting to %s", host);

	/* if they gave a hostname, we look up the IP */
	if (!hgd_is_ip_addr(host)) {
		DPRINTF(HGD_D_DEBUG, "Looking up host '%s'", host);
		he = gethostbyname(host);
		if (he == NULL) {
			DPRINTF(HGD_D_ERROR,
			    "Failure in hostname resolution: '%s'", host);
			ret = HGD_FAIL;
			goto clean;
		}

		free(host);
		host = xstrdup(
		    inet_ntoa( *(struct in_addr*)(he->h_addr_list[0])));
		DPRINTF(HGD_D_DEBUG, "Found IP %s", host);
	}

	DPRINTF(HGD_D_DEBUG, "Connecting to IP %s:%d", host, port);

	/* set up socket address */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(port);

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		DPRINTF(HGD_D_ERROR, "can't make socket: %s", SERROR);
		ret = HGD_FAIL;
		goto clean;
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
		    &sockopt, sizeof(sockopt)) < 0) {
		DPRINTF(HGD_D_WARN, "Can't set SO_REUSEADDR");
	}

	if (connect(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sock_fd);
		DPRINTF(HGD_D_ERROR, "Can't connect to %s", host);
		ret = HGD_FAIL;
		goto clean;
	}

	/* expect a hello message */
	resp = hgd_sock_recv_line(sock_fd, ssl);
	hgd_check_svr_response(resp, 1);
	free(resp);

	DPRINTF(HGD_D_DEBUG, "Connected to %s", host);

	/* identify ourselves */
	if (user == NULL) {
		/* If the user did not set their name use thier system login */
		user = getenv("USER");
	}
	if (user == NULL) {
		DPRINTF(HGD_D_ERROR, "can't get username");
		ret = HGD_FAIL;
		goto clean;
	}

	hgd_negotiate_crypto();
	if ((server_ssl_capable) && (crypto_pref != HGD_CRYPTO_PREF_NEVER)) {
		if (hgd_encrypt(sock_fd) != HGD_OK) {
			ret = HGD_FAIL;
			goto clean;
		}
	}

	/* annoying error message for those too lazy to set up crypto */
	if (ssl == NULL)
		DPRINTF(HGD_D_WARN, "Connection is not encrypted");

clean:
	return (ret);
}

/*
 * if x == 1 you do not need to check the return value of this method as
 * hgd will have exited before this returns.
 */
int
hgd_check_svr_response(char *resp, uint8_t x)
{
	int			err = HGD_OK;
	char			*trunc = NULL;

	if (resp == NULL) {
		DPRINTF(HGD_D_ERROR, "failed to read server response");
		err = HGD_FAIL;
		goto clean;
	}

	if (hgd_debug) {
		trunc = xstrdup(resp);
		DPRINTF(HGD_D_DEBUG, "Check reponse '%s'", trunc);
		free(trunc);
	}

	if (strncmp(resp, "ok", 2) == 0) {
		/* great */
	} else if (strncmp(resp, "err", 3)) {
		DPRINTF(HGD_D_ERROR, "Malformed server response");
	} else {
		/* we got an 'err' */
		hgd_print_pretty_server_response(resp);
		err = HGD_FAIL;
	}

clean:
	/* frees reposonse on error and exit */
	if ((err == HGD_FAIL) && (x)) {
		free(resp);
		hgd_exit_nicely();
	}

	return (err);
}

/*
 * see if the server supports encryption
 * return: 1 = yes, 0 = no, -1 = error
 */
int
hgd_negotiate_crypto()
{
	int			n_toks = 0, ret = HGD_OK;
	char			*first, *next;
	char			*ok_tokens[2] = {"", ""};

	if (crypto_pref == HGD_CRYPTO_PREF_NEVER)
		return (0);	/* fine, no crypto then */

	hgd_sock_send_line(sock_fd, NULL, "encrypt?");
	first = next = hgd_sock_recv_line(sock_fd, NULL);

	hgd_check_svr_response(next, 1);

	do {
		ok_tokens[n_toks] = strsep(&next, "|");
		n_toks++;
	} while ((n_toks < 2) && (next != NULL));

	if (strcmp(ok_tokens[1], "tlsv1") == 0) {
		server_ssl_capable = 1;
		DPRINTF(HGD_D_INFO, "Server supports %s crypto", ok_tokens[1]);
	}

	if ((!server_ssl_capable) && (crypto_pref == HGD_CRYPTO_PREF_ALWAYS)) {
		DPRINTF(HGD_D_ERROR,
		    "User forced crypto, but server is incapable");
		ret = HGD_FAIL;
	}

	free(first);

	return (ret);
}

int
hgd_encrypt(int fd)
{
	int			 ssl_res = 0;
	char			*ok_str = NULL;
	X509			*cert;

	/* XXX For semi-implemented certificate verification - FAO mex */
#if 0
	X509_NAME		*cert_name;
	EVP_PKEY		*public_key;
	BIO			*bio;
#endif
	hgd_sock_send_line(fd, NULL, "encrypt");

	if (hgd_setup_ssl_ctx(&method, &ctx, 0, 0, 0) != 0) {
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "Setting up SSL_new");
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		PRINT_SSL_ERR (HGD_D_ERROR, "SSL_new");
		return (HGD_FAIL);
	}

	ssl_res = SSL_set_fd(ssl, fd);
	if (ssl_res == 0) {
		PRINT_SSL_ERR (HGD_D_ERROR, "SSL_set_fd");
		return (HGD_FAIL);
	}

	ssl_res = SSL_connect(ssl);
	if (ssl_res != 1) {
		PRINT_SSL_ERR (HGD_D_ERROR, "SSL_connect");
		return (HGD_FAIL);
	}

	cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		DPRINTF(HGD_D_ERROR, "could not get remote cert");
		exit (HGD_FAIL);
	}

/*
 * unfinished work on checking SSL certs.  Need to work out how to get the
 * hash from the cert to know where to write the cert to. XXX
 */
#if 0
	if(SSL_get_verify_result(ssl) != X509_V_OK)
	{
		PRINT_SSL_ERR ("SSL_connect");

		cert = SSL_get_peer_certificate(ssl);

		cert->
		/* PEM_write_x509(fp!,cert);- */

		return (-1);
	}
#endif
	ok_str = hgd_sock_recv_line(fd, ssl);
	hgd_check_svr_response(ok_str, 1);
	free(ok_str);

	DPRINTF(HGD_D_INFO, "SSL connection established");

	return (HGD_OK);
}

int
hgd_print_pretty_server_response(char *resp_line)
{
	char			*p;
	struct hgd_resp_err	*resp, *chosen = NULL;

	p = strchr(resp_line, '|');
	if (p == NULL) {
		DPRINTF(HGD_D_ERROR, "Unspecified server error reponse");
		return (HGD_FAIL);
	}

	p++;
	for (resp = hgd_resp_errs; resp->code != 0; resp++) {
		if (strcmp(p, resp->code) == 0) {
			chosen = resp;
			break;
		}
	}

	if (chosen == NULL) {
		DPRINTF(HGD_D_ERROR, "Unknown server error reponse");
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_ERROR,
	    "Server reponded with error '%s': %s", p, chosen->meaning);

	return (HGD_OK);
}

/*
 * check protocol version is correct
 */
int
hgd_check_svr_proto()
{
	char			*v, *resp = NULL;
	int			 major = -1, minor = -1, ret = HGD_OK;
	char			*split = "|";
	char			*saveptr1;

	hgd_sock_send_line(sock_fd, ssl, "proto");
	resp = hgd_sock_recv_line(sock_fd, ssl);

	if (hgd_check_svr_response(resp, 0) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Could not check server proto version");
		ret = HGD_FAIL;
		goto clean;
	}

	v = strtok_r(resp, split, &saveptr1);
	(void) v;

	/* major */
	v = strtok_r(NULL, split, &saveptr1);
	if (v == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not find protocol MAJOR version");
		ret = HGD_FAIL;
		goto clean;
	}

	major = atoi(v);

	/* minor */
	v = strtok_r(NULL, split, &saveptr1);
	if (v == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not find protocol MINOR version");
		ret = HGD_FAIL;
		goto clean;
	}

	minor = atoi(v);

	if (major == HGD_PROTO_VERSION_MAJOR && minor >= HGD_PROTO_VERSION_MINOR) {
		if (minor > HGD_PROTO_VERSION_MINOR) {
			DPRINTF(HGD_D_INFO, "Server is running a newer minor version"
			    "of the server.Server=%d,%d, Client=%d,%d", major, minor,
			    HGD_PROTO_VERSION_MAJOR, HGD_PROTO_VERSION_MINOR);
		}
	} else {
		DPRINTF(HGD_D_ERROR, "Protocol mismatch: "
		    "Server=%d,%d, Client=%d,%d", major, minor,
		    HGD_PROTO_VERSION_MAJOR, HGD_PROTO_VERSION_MINOR);
		ret = HGD_FAIL;
		goto clean;
	}


	DPRINTF(HGD_D_DEBUG, "Protocol version matches server");

clean:
	if (resp)
		free(resp);

	return (ret);
}

int
hgd_cli_populate_track(struct hgd_playlist_item **it, char *resp)
{
	char			*tokens[HGD_NUM_TRACK_FIELDS];
	int			 n_toks = 0;

	do {
		tokens[n_toks] = xstrdup(strsep(&resp, "|"));
	} while ((n_toks++ < HGD_NUM_TRACK_FIELDS) && (resp != NULL));

	if (n_toks != HGD_NUM_TRACK_FIELDS) {
		DPRINTF(HGD_D_ERROR, "Wrong number of tokens from server");
		return (HGD_OK);
	}

	/* OK, response looked good, now populate struct */
	*it = xmalloc(sizeof(struct hgd_playlist_item));

	(*it)->id = atoi(tokens[0]);
	(*it)->filename = tokens[1];
	(*it)->user = xstrdup(tokens[4]);
	(*it)->playing = 0;	/* unused here */
	(*it)->finished = 0;	/* unused here */
	(*it)->tags.artist = xstrdup(tokens[2]);
	(*it)->tags.title = xstrdup(tokens[3]);
	(*it)->tags.album = xstrdup(tokens[5]);
	(*it)->tags.genre = xstrdup(tokens[6]);
	(*it)->tags.duration = atoi(tokens[7]);
	(*it)->tags.bitrate = atoi(tokens[8]);
	(*it)->tags.samplerate = atoi(tokens[9]);
	(*it)->tags.channels = atoi(tokens[10]);
	(*it)->tags.year = atoi(tokens[11]);
	(*it)->votes_needed = atoi(tokens[12]);
	(*it)->has_voted = atoi(tokens[13]);

	/* NOTE: votesneeded and voted? are not stored in this struct */

	return (HGD_OK);
}

int
hgd_cli_get_playlist(struct hgd_playlist **list)
{
	char		*p, *resp, *track_resp;
	int		 n_items, i;

	hgd_sock_send_line(sock_fd, ssl, "ls");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		free(resp);
		return (HGD_FAIL);
	}


	/* find the first pipe */
	for (p = resp; (*p != 0 && *p != '|'); p ++);
	if (*p != '|') {
		DPRINTF(HGD_D_ERROR, "didn't find a argument separator");
		free(resp);
		return (HGD_FAIL);
	}

	/* allocate playlist*/
	/* XXX dont allocate here */
	*list = xcalloc(1, sizeof(struct hgd_playlist));
	(*list)->n_items = atoi(++p);
	(*list)->items = xcalloc(
	    (*list)->n_items, sizeof(struct hgd_playlist_item *));

	free(resp);

	/* populate items */
	DPRINTF(HGD_D_DEBUG, "expecting %d items in playlist", n_items);
	for (i = 0; i < (*list)->n_items; i++) {
		track_resp = hgd_sock_recv_line(sock_fd, ssl);

		if (hgd_cli_populate_track(
		    &(*list)->items[i], track_resp) != HGD_OK) {
			free(track_resp);
			return (HGD_FAIL);
		}

		free(track_resp);
	}

	return (HGD_OK);
}


/*
 * queue a track, after each HGD_Q_CALLBACK_INTVL chunks are sent,
 * the callback is fired and client has the ability to update it's ui.
 */
#define HGD_Q_CALLBACK_INTVL		500
int
hgd_cli_queue_track(char *filename,
    void *arg, int(*cb)(void *arg, float progress))
{
	FILE			*f;
	struct stat		st;
	ssize_t			written = 0, fsize, chunk_sz;
	char			chunk[HGD_BINARY_CHUNK];
	char			*q_req = 0, *resp1 = 0, *resp2 = 0;
	char			 stars_buf[81];
	int			 iters = 0, barspace, percent, ret = HGD_FAIL;
	float			 n_stars;


	DPRINTF(HGD_D_INFO, "Uploading file '%s'", filename);

	if (stat(filename, &st) < 0) {
		DPRINTF(HGD_D_ERROR, "Can't stat '%s'", filename);
		ret = HGD_FAIL;
		goto clean;
	}

	if (st.st_mode & S_IFDIR) {
		DPRINTF(HGD_D_ERROR, "Can't upload directories");
		ret = HGD_FAIL;
		goto clean;
	}

	fsize = st.st_size;

	/* send request to upload */
	xasprintf(&q_req, "q|%s|%d", filename, fsize);
	hgd_sock_send_line(sock_fd, ssl, q_req);

	/* check we are allowed */
	resp1 = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp1, 0) == HGD_FAIL)
		goto clean;

	DPRINTF(HGD_D_DEBUG, "opening '%s' for reading", filename);
	f = fopen(filename, "r");
	if (f == NULL) {
		DPRINTF(HGD_D_ERROR, "fopen %s: %s", filename, SERROR);
		ret = HGD_FAIL;
		goto clean;
	}

	/*
	 * start sending the file
	 */
	written = 0;
	while (written != fsize) {

		if (iters % HGD_Q_CALLBACK_INTVL == 0)
			cb(arg, ((float) written/fsize));
		iters++;

		if (fsize - written < HGD_BINARY_CHUNK)
			chunk_sz = fsize - written;
		else
			chunk_sz = HGD_BINARY_CHUNK;

		if (fread(chunk, chunk_sz, 1, f) != 1) {
			DPRINTF(HGD_D_WARN, "Retrying fread");
			continue;
		}

		hgd_sock_send_bin(sock_fd, ssl, chunk, chunk_sz);

		written += chunk_sz;
		DPRINTF(HGD_D_DEBUG, "Progress %d/%d bytes",
		    (int)  written, (int) fsize);
	}

	fclose(f);

	resp2 = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp2, 0) == HGD_FAIL) {
		ret = HGD_FAIL;
		goto clean;
	}

	DPRINTF(HGD_D_INFO, "Transfer complete");

	ret = HGD_OK;
clean:
	if (resp1)
		free(resp1);
	if (resp2)
		free(resp2);
	if (q_req)
		free(q_req);

	return (ret);
}
