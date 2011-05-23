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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <libconfig.h>


#ifdef __linux__
#include <bsd/readpassphrase.h>
#else
#include <readpassphrase.h>
#endif
#include <libconfig.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "hgd.h"


char			*user = NULL, *host = NULL, *password = NULL;
int			 port = HGD_DFL_PORT;
int			 sock_fd = -1;

SSL			*ssl = NULL;
SSL_METHOD		*method;
SSL_CTX			*ctx;
uint8_t			 crypto_pref = HGD_CRYPTO_PREF_IF_POSS;
uint8_t			 server_ssl_capable = 0;
uint8_t			 authenticated = 0;

/* protos */
int			 hgd_check_svr_response(char *resp, uint8_t x);

void
hgd_exit_nicely()
{
	uint8_t			ssl_dead = 0;

	if (!exit_ok)
		DPRINTF(HGD_D_INFO,
		    "hgdc was interrupted or crashed - cleaning up");

	if (ssl) {
		/* clean up ssl structures */
		while (!ssl_dead)
			ssl_dead = SSL_shutdown(ssl);
		SSL_free(ssl);
	}

	if (ctx)
		SSL_CTX_free(ctx);

	if (host)
		free(host);

	if (sock_fd > 0) {
		/* try to close connection */
#ifndef __APPLE__
		/*
		 * MAC OSX sockets behave differently!
		 *
		 * If one side of the socket closes, the connection in
		 * one direction, the corresponding socket on the other side
		 * will fail to shutdown(). This is hinted at in the python
		 * manual:
		 * http://docs.python.org/library/socket.html
		 *
		 * Long story short:
		 * On OSX the server will do the shutdown for us.
		 */
		if (shutdown(sock_fd, SHUT_RDWR) == -1)
			DPRINTF(HGD_D_WARN, "Couldn't shutdown socket");
#endif
		close(sock_fd);
	}

	_exit(!exit_ok);
}

/*
 * see if the server supports encryption
 * return: 1 = yes, 0 = no, -1 = error
 */
int
hgd_negotiate_crypto()
{
	int			n_toks = 0;
	char			*first, *next;
	char			*ok_tokens[2];

	if (crypto_pref == HGD_CRYPTO_PREF_NEVER)
		return (0);	/* fine, no crypto then */

	hgd_sock_send_line(sock_fd, NULL, "encrypt?");
	first = next = hgd_sock_recv_line(sock_fd, NULL);

	hgd_check_svr_response(next, 1);

	do {
		ok_tokens[n_toks] = xstrdup(strsep(&next, "|"));
	} while ((n_toks++ < 2) && (next != NULL));
	free(first);

	if (strcmp(ok_tokens[1], "tlsv1") == 0) {
		server_ssl_capable = 1;
		DPRINTF(HGD_D_INFO, "Server supports %s crypto", ok_tokens[1]);
	}

	if ((!server_ssl_capable) && (crypto_pref == HGD_CRYPTO_PREF_ALWAYS)) {
		DPRINTF(HGD_D_ERROR,
		    "User forced crypto, but server is incapable");
		hgd_exit_nicely();
	}

	while (n_toks > 0)
		free(ok_tokens[--n_toks]);

	return (0);
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
		PRINT_SSL_ERR ("SSL_new");
		return (HGD_FAIL);
	}

	ssl_res = SSL_set_fd(ssl, fd);
	if (ssl_res == 0) {
		PRINT_SSL_ERR ("SSL_set_fd");
		return (HGD_FAIL);
	}

	ssl_res = SSL_connect(ssl);
	if (ssl_res != 1) {
		PRINT_SSL_ERR ("SSL_connect");
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

/*
 * if x == 1 you do not need to check the return value of this method as
 * hgd will have exited before this returns.
 */
int
hgd_check_svr_response(char *resp, uint8_t x)
{
	int			len, err = HGD_OK;
	char			*trunc = NULL;

	if (resp == NULL) {
		DPRINTF(HGD_D_ERROR, "failed to read server response, "
		    "did the server die?");
		hgd_exit_nicely();
	}

	len = strlen(resp);

	if (hgd_debug) {
		trunc = xstrdup(resp);
		DPRINTF(HGD_D_DEBUG, "Check reponse '%s'", trunc);
		free(trunc);
	} else
		trunc = trunc; /* silence compiler */

	if (len < 2) {
		DPRINTF(HGD_D_ERROR, "Malformed server response");
		err = HGD_FAIL;
	} else if ((resp[0] != 'o') || (resp[1] != 'k')) {
		if (len < 5)
			DPRINTF(HGD_D_ERROR, "Malformed server response");
		else
			DPRINTF(HGD_D_ERROR, "Failure: %s", &resp[4]);
		err = HGD_FAIL;
	}

	if ((err == HGD_FAIL) && (x)) {
		free(resp);
		hgd_exit_nicely();
	}

	return (err);
}

int
hgd_client_login(int fd, SSL *ssl, char *username)
{
	char			*resp, *user_cmd, pass[HGD_MAX_PASS_SZ];
	int			 login_ok = -1;
	char			*prompt;

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

	if (login_ok == HGD_OK)
		DPRINTF(HGD_D_DEBUG, "Identified as %s", user);
	else
		DPRINTF(HGD_D_WARN, "Login as %s failed", user);

	return (login_ok);
}

void
hgd_setup_socket()
{
	struct sockaddr_in	addr;
	char*			resp;
	struct hostent		*he;
	int			sockopt = 1;

	DPRINTF(HGD_D_DEBUG, "Connecting to %s", host);

	/* if they gave a hostname, we look up the IP */
	if (!hgd_is_ip_addr(host)) {
		DPRINTF(HGD_D_DEBUG, "Looking up host '%s'", host);
		he = gethostbyname(host);
		if (he == NULL) {
			DPRINTF(HGD_D_ERROR,
			    "Failiure in hostname resolution: '%s'", host);
			hgd_exit_nicely();
		}

		free(host);
		host = xstrdup(
		    inet_ntoa( *(struct in_addr*)(he->h_addr_list[0])));
		DPRINTF(HGD_D_DEBUG, "Found IP %s", host);
	}

	DPRINTF(HGD_D_DEBUG, "Connecting to IP %s", host);

	/* set up socket address */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(port);

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		DPRINTF(HGD_D_ERROR, "can't make socket: %s", SERROR);
		hgd_exit_nicely();
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
		    &sockopt, sizeof(sockopt)) < 0) {
		DPRINTF(HGD_D_WARN, "Can't set SO_REUSEADDR");
	}

	if (connect(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sock_fd);
		DPRINTF(HGD_D_ERROR, "Can't connect to %s", host);
		hgd_exit_nicely();
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
		hgd_exit_nicely();
	}

	hgd_negotiate_crypto();
	if ((server_ssl_capable) && (crypto_pref != HGD_CRYPTO_PREF_NEVER)) {
		if (hgd_encrypt(sock_fd) != HGD_OK)
			hgd_exit_nicely();
	}

	/* annoying error message for those too lazy to set up crypto */
	if (ssl == NULL)
		DPRINTF(HGD_D_WARN, "Connection is not encrypted");
}

/* NOTE! -c is reserved for 'config file path' */
void
hgd_usage()
{
	printf("Usage: hgdc [opts] command [args]\n\n");
	printf("  Commands include:\n");
	printf("    hud\t\t\tHeads up display\n");
	printf("    q <filename>\tQueue a track\n");
	printf("    vo\t\t\tVote-off current track\n");
	printf("    ls\t\t\tShow playlist\n\n");
	printf("  Options include:\n");
	printf("    -c\t\t\tSet config location\n");
	printf("    -e\t\t\tAlways require encryption\n");
	printf("    -E\t\t\tRefuse to use encryption\n");
	printf("    -h\t\t\tShow this message and exit\n");
	printf("    -p port\t\tSet connection port\n");
	printf("    -s host/ip\t\tSet connection address\n");
	printf("    -u username\t\tSet username\n");
	printf("    -x level\t\tSet debug level (0-3)\n");
	printf("    -v\t\t\tShow version and exit\n");
	printf("    -e\t\t\tEnable encryption\n");
}

/* upload and queue a file to the playlist */
int
hgd_req_queue(char **args)
{
	FILE			*f;
	struct stat		st;
	ssize_t			written = 0, fsize, chunk_sz;
	char			chunk[HGD_BINARY_CHUNK], *filename = args[0];
	char			*q_req, *resp;
	int			 bar = 0, iters = 0;

	DPRINTF(HGD_D_DEBUG, "Will queue '%s'", args[0]);

	if (stat(filename, &st) < 0) {
		DPRINTF(HGD_D_ERROR, "Can't stat '%s'", filename);
		hgd_exit_nicely();
	}

	if (st.st_mode & S_IFDIR) {
		DPRINTF(HGD_D_ERROR, "Can't upload directories");
		hgd_exit_nicely();
	}

	fsize = st.st_size;

	/* send request to upload */
	xasprintf(&q_req, "q|%s|%d", filename, fsize);
	hgd_sock_send_line(sock_fd, ssl, q_req);
	free(q_req);

	/* check we are allowed */
	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		free(resp);
		return (HGD_FAIL);
	}
	free(resp);

	DPRINTF(HGD_D_DEBUG, "opening '%s' for reading", filename);
	f = fopen(filename, "r");
	if (f == NULL) {
		DPRINTF(HGD_D_ERROR, "fopen %s: %s", filename, SERROR);
		return (HGD_FAIL);
	}

	/*
	 * start sending the file
	 */
	while (written != fsize) {

		if ((iters % 50 == 0) && (hgd_debug <= 1)) {
			bar = ((float) written/fsize) * 100;
			printf("\r%3d%%", bar);
			fflush(stdout);
		}
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
	printf("\r     \r");
	fflush(stdout);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		free(resp);
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "Transfer complete");
	free(resp);

	return (HGD_OK);
}

void
hgd_print_track(char *resp)
{
	int			n_toks = 0, i;
	char			*tokens[3] = {NULL, NULL, NULL};

	do {
		tokens[n_toks] = xstrdup(strsep(&resp, "|"));
	} while ((n_toks++ < 3) && (resp != NULL));

	if (n_toks == 3)
		printf(" [ #%04d ] '%s' from '%s'\n",
		    atoi(tokens[0]), tokens[1], tokens[2]);
	else
		fprintf(stderr,
		    "%s: wrong number of tokens from server\n",
		    __func__);

	for (i = 0; i < n_toks; i ++)
		free(tokens[i]);
}

void
hgd_hline()
{
	int			i;

	for (i = 0; i < 78; i ++)
		printf("-");
	printf("\n");
}

int
hgd_req_vote_off(char **args)
{
	char			*resp;

	args = args; /* sssh */

	hgd_sock_send_line(sock_fd, ssl, "vo");

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "Vote off failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_playlist(char **args)
{
	char			*resp, *track_resp, *p;
	int			n_items, i;

	args = args; /* shhh */

	hgd_sock_send_line(sock_fd, ssl, "ls");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		free(resp);
		return (HGD_FAIL);
	}

	for (p = resp; (*p != 0 && *p != '|'); p ++);
	if (*p != '|') {
		DPRINTF(HGD_D_ERROR, "didn't find a argument separator");
		free(resp);
		return (HGD_FAIL);
	}

	n_items = atoi(++p);
	free(resp);

	DPRINTF(HGD_D_DEBUG, "expecting %d items in playlist", n_items);
	for (i = 0; i < n_items; i++) {
		track_resp = hgd_sock_recv_line(sock_fd, ssl);
		if (i == 0) {
			hgd_hline();
			hgd_print_track(track_resp);
			/* printf("           0 votes-offs.\n"); */
			hgd_hline();
		} else
			hgd_print_track(track_resp);

		free(track_resp);
	}

	return (HGD_OK);
}

/*
 * Heads up display mode
 * May make this more spctacular at some stage...
 */
int
hgd_req_hud(char **args)
{
	args = args; /* silence */

	/* pretty clunky ;) */
	while (1) {
		system("clear");
		printf("HGD Server @ %s -- Playlist:\n\n", host);

		if (hgd_req_playlist(NULL) != HGD_OK)
			return (HGD_FAIL);

		sleep(1);
	}

	return (HGD_OK);
}

/* lookup for request despatch */
struct hgd_req_despatch req_desps[] = {
/*	cmd,		n_args,	need_auth,	handler */
	{"ls",		0,	0,		hgd_req_playlist},
	{"hud",		0,	0,		hgd_req_hud},
	{"vo",		0,	1,		hgd_req_vote_off},
	{"q",		1,	1,		hgd_req_queue},
	{NULL,		0,	0,		NULL} /* terminate */
};

/*
 * check protocol version is correct
 */
int
hgd_check_svr_proto()
{
	char			*v, *resp = NULL;
	int			 vv = -1, ret = HGD_OK;

	hgd_sock_send_line(sock_fd, ssl, "proto");
	resp = hgd_sock_recv_line(sock_fd, ssl);

	if (hgd_check_svr_response(resp, 0) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Could not check server proto version");
		ret = HGD_FAIL;
		goto clean;
	}

	v = strchr(resp, '|');
	if ((v == 0) || (*(v + 1) == 0)) {
		DPRINTF(HGD_D_ERROR, "Could not find protocol version");
		ret = HGD_FAIL;
		goto clean;
	}

	vv = atoi(v + 1);
	if (vv != HGD_PROTO_VERSION) {
		DPRINTF(HGD_D_ERROR, "Protocol mismatch: "
		    "Server=%d, Client=%d", HGD_PROTO_VERSION, vv);
		ret = HGD_FAIL;
		goto clean;
	}

	DPRINTF(HGD_D_DEBUG, "Protocol version matches server");

clean:
	if (resp)
		free(resp);

	return (ret);
}

/* parse command line args */
void
hgd_exec_req(int argc, char **argv)
{
	struct hgd_req_despatch	*desp, *correct_desp = NULL;

	if (argc == 0) {
		hgd_usage();
		exit_ok = 1;
		hgd_exit_nicely();
	}

	for (desp = req_desps; desp->req != NULL; desp++) {
		if (strcmp(desp->req, argv[0]) != 0)
			continue;
		if (argc - 1 != desp->n_args)
			continue;

		correct_desp = desp; /* found it */
		break;
	}

	if (correct_desp == NULL) {
		hgd_usage();
		exit_ok = 1;
		hgd_exit_nicely();
	}

	/* once we know that the hgdc is used properly, open connection */
	hgd_setup_socket();

	/* check protocol matches the server before we continue */
	if (hgd_check_svr_proto() != HGD_OK)
		return;

	DPRINTF(HGD_D_DEBUG, "Despatching request '%s'", correct_desp->req);
	if ((!authenticated) && (correct_desp->need_auth)) {
		if (hgd_client_login(sock_fd, ssl, user) != HGD_OK)
			hgd_exit_nicely();
	}
	correct_desp->handler(&argv[1]);
}

int
hgd_read_config(char **config_locations)
{
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 * see hgd-playd.c for how to remove need for stat.
	 */
	config_t		 cfg, *cf;
	char			*cypto_pref, *tmp_host, *tmp_user;
	char			*tmp_password;
	int			 ret = HGD_OK;
	struct stat		 st;

	/* temp variables */
	long long int		tmp_dbglevel, tmp_port;

	cf = &cfg;
	config_init(cf);

	while (*config_locations != NULL) {
		/* Try and open usr config */
		DPRINTF(HGD_D_INFO, "Trying to read config from: %s",
		    *config_locations);

		if ( stat (*config_locations, &st) < 0 ) {
			DPRINTF(HGD_D_INFO, "Could not stat %s",
			    *config_locations);
			config_locations--;
			continue;
		}

		/* if we find a config, use it */
		if (config_read_file(cf, *config_locations))
			break;

		/* otherwise look for another */
		DPRINTF(HGD_D_ERROR, "%s (line: %d)",
		    config_error_text(cf), config_error_line(cf));
		config_locations--;
	}

	/* if no configs found */
	if (*config_locations == NULL) {
		config_destroy(cf);
		return (HGD_OK);
	}

	/* -e -E */
	if (config_lookup_string(cf, "crypto", (const char **) &cypto_pref)) {

		if (strcmp(cypto_pref, "always") == 0) {
			DPRINTF(HGD_D_DEBUG, "Client will insist upon cryto");
			crypto_pref = HGD_CRYPTO_PREF_ALWAYS;
		} else if (strcmp(cypto_pref, "never") == 0) {
			DPRINTF(HGD_D_DEBUG, "Client will insist upon "
			   " no crypto");
			crypto_pref = HGD_CRYPTO_PREF_NEVER;
		} else if (strcmp(cypto_pref, "if_avaliable") == 0) {
			DPRINTF(HGD_D_DEBUG,
			    "Client will use crypto if avaliable");
		} else {
			DPRINTF(HGD_D_WARN,
			    "Invalid crypto option, using default");
		}
	}

	/* -s */
	if (config_lookup_string(cf, "hostname", (const char **) &tmp_host)) {
		free(host);
		host = xstrdup(tmp_host);
		DPRINTF(HGD_D_DEBUG, "host=%s", host);
	}

	/* -p */
	if (config_lookup_int64(cf, "port", &tmp_port)) {
		port = tmp_port;
		DPRINTF(HGD_D_DEBUG, "port=%d", port);
	}

	/* password */
	if (config_lookup_string(cf, "password", (const char**) &tmp_password)) {
		if (st.st_mode & (S_IRWXG | S_IRWXO)) {
			DPRINTF(HGD_D_ERROR, 
				"Config file with your password in is readable by"
				" other people.  Please chmod it.");
			hgd_exit_nicely();	

		}

		password = xstrdup(tmp_password);
		DPRINTF(HGD_D_DEBUG, "Set password from config");
	}

	/* -u */
	if (config_lookup_string(cf, "username", (const char**) &tmp_user)) {
		free(user);
		user = strdup(tmp_user);
		DPRINTF(HGD_D_DEBUG, "user='%s'", user);
	}

	/* -x */
	if (config_lookup_int64(cf, "debug", &tmp_dbglevel)) {
		hgd_debug = tmp_dbglevel;
		DPRINTF(HGD_D_DEBUG, "debug level=%d", hgd_debug);
	}

	config_destroy(cf);
	return (ret);
}

int
main(int argc, char **argv)
{
	char			*resp, ch;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			num_config = 2;

	host = xstrdup(HGD_DFL_HOST);
	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_CLI_CFG );
	xasprintf(&config_path[2], "%s%s", getenv("HOME"),
	    HGD_USR_CFG_DIR HGD_CLI_CFG );

	/*
	 * Need to do getopt twice because x and c need to be done before
	 * reading the config
	 */
	while ((ch = getopt(argc, argv, "c:Eehp:s:u:vx:")) != -1) {
		switch (ch) {
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG, "set debug to %d", hgd_debug);
			break;
		case 'c':
			if (num_config < 3) {
				num_config++;
				DPRINTF(HGD_D_DEBUG, "added config %d %s",
				    num_config, optarg);
				config_path[num_config] = optarg;
			} else {
				DPRINTF(HGD_D_WARN,
				    "Too many config files specified");
				hgd_exit_nicely();
			}
			break;
		default:
			break; /* catch badness on next getopt */
		}
	}

	hgd_read_config(config_path + num_config);

	RESET_GETOPT();

	while ((ch = getopt(argc, argv, "c:Eehp:s:u:vx:")) != -1) {
		switch (ch) {
		case 'c':
			break; /* already handled */
		case 'e':
			DPRINTF(HGD_D_DEBUG, "Client will insist upon cryto");
			crypto_pref = HGD_CRYPTO_PREF_ALWAYS;
			break;
		case 'E':
			DPRINTF(HGD_D_DEBUG, "Client will insist upon "
			   " no crypto");
			crypto_pref = HGD_CRYPTO_PREF_NEVER;
			break;
		case 's':
			DPRINTF(HGD_D_DEBUG, "Set server to %s", optarg);
			free(host);
			host = xstrdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "set port to %d", port);
			break;
		case 'u':
			free(user);
			user = strdup(optarg);
			DPRINTF(HGD_D_DEBUG, "set username to %s", user);
			break;
		case 'v':
			hgd_print_version();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		case 'x':
			DPRINTF(HGD_D_DEBUG, "set debug to %d", atoi(optarg));
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			break; /* already set but over-rideable */
		case 'h':
		default:
			hgd_usage();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		};
	}

	argc -= optind;
	argv += optind;

	/* secure mask */
	umask(~S_IRWXU);

	/* do whatever the user wants */
	hgd_exec_req(argc, argv);

	/* sign off */
	hgd_sock_send_line(sock_fd, ssl, "bye");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	hgd_check_svr_response(resp, 1);
	free(resp);

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
