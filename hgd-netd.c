/*
 * Copyright (c) 2011, Edd Barrett <vext01@gmail.com>
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
#include <string.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <sys/wait.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "hgd.h"
#include "db.h"

#include <openssl/ssl.h>

int				port = HGD_DFL_PORT;
int				sock_backlog = HGD_DFL_BACKLOG;
int				svr_fd = -1;
size_t				max_upload_size = HGD_DFL_MAX_UPLOAD;
uint8_t				num_bad_commands = 0;

int				req_votes = HGD_DFL_REQ_VOTES;
uint8_t				single_client = 0;

char				*vote_sound = NULL;

SSL_METHOD			*method;
SSL_CTX				*ctx = NULL;

int				 encryption_enabled = 1;
char				*ssl_cert_path = HGD_DFL_CERT_FILE;
char				*ssl_key_path = HGD_DFL_KEY_FILE;

/*
 * clean up and exit, if the flag 'exit_ok' is not 1, upon call,
 * this indicates an error occured or kill signal was caught
 */
void
hgd_exit_nicely()
{
	if (!exit_ok)
		DPRINTF(HGD_D_ERROR, "hgd-netd was interrupted or crashed");

	/* XXX remove mplayer PID if existing */
	/* XXX close ssl socket */

	if (svr_fd >= 0) {
		if (shutdown(svr_fd, SHUT_RDWR) == -1)
			DPRINTF(HGD_D_WARN,
			    "Can't shutdown socket: %s",SERROR);
		close(svr_fd);
	}
	if (db_path)
		free(db_path);
	if (filestore_path)
		free(filestore_path);
	if (hgd_dir)
		free(hgd_dir);
	if (db)
		sqlite3_close(db);

	_exit (!EXIT_SUCCESS);
}

/* return some kind of host identifier, free when done */
char *
hgd_identify_client(struct sockaddr_in *cli_addr)
{
	char			cli_host[NI_MAXHOST];
	char			cli_serv[NI_MAXSERV];
	char			*ret = NULL;
	int			found_name;

	DPRINTF(HGD_D_DEBUG, "Servicing client");

	found_name = getnameinfo((struct sockaddr *) cli_addr,
	    sizeof(struct sockaddr_in), cli_host, sizeof(cli_host), cli_serv,
	    sizeof(cli_serv), NI_NAMEREQD | NI_NOFQDN);

	if (found_name == 0)
		goto found; /* found a hostname */

	DPRINTF(HGD_D_WARN, "Client hostname *not* found: %s",
	    gai_strerror(found_name));

	found_name = getnameinfo((struct sockaddr *) cli_addr,
	    sizeof(struct sockaddr_in), cli_host, sizeof(cli_host),
	    cli_serv, sizeof(cli_serv), NI_NUMERICHOST);

	if (found_name == 0)
		goto found; /* found an IP address */

	DPRINTF(HGD_D_WARN, "Can't identify client ip: %s",
	    gai_strerror(found_name));

	return (NULL);

found:
	/* good, we got an identifier name/ip */
	xasprintf(&ret, "%s", cli_host);
	return (ret);
}

/*
 * respond to client what is currently playing.
 *
 * response:
 * ok|0				nothing playing
 * ok|1|id|filename|user	track is playing
 * err|...			failure
 */
int
hgd_cmd_now_playing(struct hgd_session *sess, char **args)
{
	struct hgd_playlist_item	 playing;
	char				*reply;

	args = args; /* silence compiler */

	memset(&playing, 0, sizeof(playing));
	if (hgd_get_playing_item(&playing) == -1) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|internal");
		hgd_free_playlist_item(&playing);
		return (-1);
	}

	if (playing.filename == NULL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok|0");
	} else {
		xasprintf(&reply, "ok|1|%d|%s|%s",
		    playing.id, playing.filename, playing.user);
		hgd_sock_send_line(sess->sock_fd, sess->ssl, reply);

		free(reply);
	}

	hgd_free_playlist_item(&playing);

	return (0);
}

/*
 * Identify yourself to the server
 *
 * args: username
 */
int
hgd_cmd_user(struct hgd_session *sess, char **args)
{
	DPRINTF(HGD_D_DEBUG, "User on host '%s' identified as '%s'",
	    sess->cli_str, args[0]);

	sess->user = strdup(args[0]);
	hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");

	return (0);
}

/*
 * queue a track
 *
 * args: filename|size
 * reponses
 * ok...			ok and waiting for payload
 * ok				ok and payload accepted
 * err|size			size arg was weird
 * err|user_not_identified	user did not identify
 * err|internal			something else went wrong
 *
 * after 'ok...'
 * client then sends 'size' bytes of the media to queue
 */
int
hgd_cmd_queue(struct hgd_session *sess, char **args)
{
	char			*filename_p = args[0], *payload = NULL;
	size_t			bytes = atoi(args[1]);
	char			*unique_fn = NULL;
	int			f = -1, ret = 0;
	size_t			bytes_recvd = 0, to_write;
	ssize_t			write_ret;
	char			*filename;

	/* strip path, we don't care about that */
	filename = basename(filename_p);

	if ((bytes == 0) || (bytes > max_upload_size)) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|size");
		ret = -1;
		goto clean;
	}

	if (sess->user == NULL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|user_not_identified");
		ret = -1;
		goto clean;
	}

	/* prepare to recieve the media file and stash away */
	xasprintf(&unique_fn, "%s/%s.XXXXXXXX", filestore_path, filename);
	DPRINTF(HGD_D_DEBUG, "Template for filestore is '%s'", unique_fn);

	f = mkstemp(unique_fn);
	if (f < 0) {
		DPRINTF(HGD_D_ERROR, "mkstemp: %s: %s",
		    filestore_path, SERROR);
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|internal");
		ret = -1;
		goto clean;
	}

	hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok...");

	DPRINTF(HGD_D_INFO, "Recving %d byte payload '%s' from %s into %s",
	    (int) bytes, filename, sess->user, unique_fn);

	/* recieve bytes in small chunks so that we dont use moar RAM */
	while (bytes_recvd != bytes) {

		if (bytes - bytes_recvd < HGD_BINARY_RECV_SZ)
			to_write = bytes - bytes_recvd;
		else
			to_write = HGD_BINARY_RECV_SZ;

		payload = NULL;

		DPRINTF(HGD_D_DEBUG, "Waiting for chunk of length %d bytes",
		    (int) to_write);

		payload = hgd_sock_recv_bin(sess->sock_fd,
		    sess->ssl, to_write);
		if (payload == NULL) {
			DPRINTF(HGD_D_ERROR, "failed to recv binary");
			hgd_sock_send_line(sess->sock_fd,
			    sess->ssl, "err|internal");

			unlink(filename); /* don't much care if this fails */
			ret = -1;
			goto clean;
		}
		write_ret = write(f, payload, to_write);

		/* XXX what if write returns less than the chunk? */
		if (write_ret < 0) {
			DPRINTF(HGD_D_ERROR, "Failed to write %d bytes: %s",
			    (int) to_write, SERROR);
			hgd_sock_send_line(sess->sock_fd,
			    sess->ssl, "err|internal");
			unlink(filename); /* don't much care if this fails */
			ret = -1;
			goto clean;
		}

		bytes_recvd += to_write;
		DPRINTF(HGD_D_DEBUG, "Recvd binary chunk of length %d bytes",
		    (int) to_write);
		DPRINTF(HGD_D_DEBUG, "Expecting a further %d bytes",
		    (int) (bytes - bytes_recvd));

		free(payload);
	}
	payload = NULL;

	/* insert track into db */
	if (hgd_insert_track(basename(unique_fn), sess->user) == -1) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|sql");
		goto clean;
	}

	hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");
	DPRINTF(HGD_D_INFO, "Transfer of '%s' complete", filename);
clean:
	if (f == -1)
		close(f);
	if (payload)
		free(payload);
	if (unique_fn)
		free(unique_fn);

	if (bytes_recvd != bytes)
		ret = -1;

	return (ret);
}

/*
 * report back items in the playlist
 */
int
hgd_cmd_playlist(struct hgd_session *sess, char **args)
{
	char			*resp;
	struct hgd_playlist	 list;
	unsigned int		 i;

	/* shhh */
	args = args;

	if (hgd_get_playlist(&list) == -1) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|sql");
		return (-1);
	}

	/* and respond to client */
	xasprintf(&resp, "ok|%d", list.n_items);
	hgd_sock_send_line(sess->sock_fd, sess->ssl, resp);
	free(resp);

	for (i = 0; i < list.n_items; i++) {
		xasprintf(&resp, "%d|%s|%s", list.items[i]->id,
		    list.items[i]->filename, list.items[i]->user);
		hgd_sock_send_line(sess->sock_fd, sess->ssl, resp);
		free(resp);
	}

	hgd_free_playlist(&list);

	return (0);
}

int
hgd_cmd_vote_off(struct hgd_session *sess, char **args)
{
	struct hgd_playlist_item	 playing;
	char				*pid_path, pid_str[HGD_PID_STR_SZ];
	char				*scmd;
	pid_t				pid;
	FILE				*pid_file;
	size_t				read;
	int				tid = -1, scmd_ret;

	DPRINTF(HGD_D_INFO, "%s wants to kill track %d", sess->user, tid);

	if (sess->user == NULL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|user_not_identified");
		return (-1);
	}

	memset(&playing, 0, sizeof(playing));
	if (hgd_get_playing_item(&playing) == -1) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|internal");
		return (-1);
	}

	/* is *anything* playing? */
	if (playing.filename == NULL) {
		DPRINTF(HGD_D_INFO, "No track is playing, can't vote off");
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|not_playing");
		return (-1);
	}

	/* is the file they are voting off playing? */
	if (args != NULL) { /* null if call from hgd_cmd_vote_off_noargs */
		tid = atoi(args[0]);
		if (playing.id != tid) {
			DPRINTF(HGD_D_INFO, "Track to voteoff isn't playing");
			hgd_sock_send_line(sess->sock_fd, sess->ssl,
			    "err|wrong_track");
			hgd_free_playlist_item(&playing);
			return (-1);
		}
	}
	hgd_free_playlist_item(&playing);

	/* insert vote */
	switch (hgd_insert_vote(sess->user)) {
	case 0:
		break; /* good */
	case 1:
		/* duplicate vote */
		DPRINTF(HGD_D_INFO, "User '%s' already voted", sess->user);
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|duplicate_vote");
		return (0);
		break;
	default:
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|sql");
		return (-1);
	};

	/* play a sound on skipping? */
	if (vote_sound != NULL) {
		DPRINTF(HGD_D_DEBUG, "Play voteoff sound: '%s'", vote_sound);
		xasprintf(&scmd, "mplayer -really-quiet %s", vote_sound);
		scmd_ret = system(scmd);

		/* unreachable as mplayer doesn't return non-zero :\ */
		if (scmd_ret != 0) {
			DPRINTF(HGD_D_WARN,
			    "Vote-off noise failed to play (ret %d): %s",
			    scmd_ret, vote_sound);
		}

		free(scmd);
	}

	/* are we at the vote limit yet? */
	if (hgd_get_num_votes() < req_votes) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");
		return (0);
	}

	DPRINTF(HGD_D_INFO, "Vote limit exceeded - kill track");

	/* kill mplayer then */
	xasprintf(&pid_path, "%s/%s", hgd_dir, HGD_MPLAYER_PID_NAME);
	pid_file = fopen(pid_path, "r");
	if (pid_file == NULL) {
		DPRINTF(HGD_D_WARN,
		    "Can't find mplayer pid file: %s: %s", pid_path, SERROR);
		free(pid_path);
		return (-1);
	}

	free(pid_path);
	read = fread(pid_str, HGD_PID_STR_SZ, 1, pid_file);
	if (read == 0) {
		if (!feof(pid_file)) {
			DPRINTF(HGD_D_WARN, "Can't find pid in pid file");
			fclose(pid_file);
			return (-1);
		}
	}
	fclose(pid_file);

	pid = atoi(pid_str);
	DPRINTF(HGD_D_DEBUG, "Killing mplayer");
	if (kill(pid, SIGINT) < 0)
		DPRINTF(HGD_D_WARN, "Can't kill mplayer: %s", SERROR);

	/* Note: player daemon will empty the votes table */
	hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");

	return (0);
}

int
hgd_cmd_vote_off_noarg(struct hgd_session *sess, char **unused)
{
	unused = unused;
	return (hgd_cmd_vote_off(sess, NULL));
}

int
hgd_cmd_encrypt(struct hgd_session *sess, char **unused)
{
	int			ssl_err = 0, ret = -1;

	unused = unused;

	if (!encryption_enabled) {
		DPRINTF(HGD_D_WARN,
		    "User tried to enable SSL when it is turned off");
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|nossl");
		return -1;
	}

	DPRINTF(HGD_D_INFO, "Setting up SSL connection");

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	method = (SSL_METHOD *) TLSv1_server_method();
	if (method == NULL) {
		PRINT_SSL_ERR("TLSv1_server_method");
		goto clean;
	}

	ctx = SSL_CTX_new(method);         /* create context */
	if (ctx == NULL) {
		PRINT_SSL_ERR("SSL_CTX_new");
		goto clean;
	}

	/* set the local certificate from CertFile */
	DPRINTF(HGD_D_DEBUG, "Loading SSL certificate");
	if (!SSL_CTX_use_certificate_file(
	    ctx, ssl_cert_path, SSL_FILETYPE_PEM)) {
		DPRINTF(HGD_D_ERROR, "Can't load TLS cert: %s", ssl_cert_path);
		PRINT_SSL_ERR("SSL_CTX_use_certificate_file");
		goto clean;
	}

	/* set the private key from KeyFile */
	DPRINTF(HGD_D_DEBUG, "Loading SSL private key");
	if (!SSL_CTX_use_PrivateKey_file(
	    ctx, ssl_key_path, SSL_FILETYPE_PEM)) {
		DPRINTF(HGD_D_ERROR, "Can't load TLS key: %s", ssl_key_path);
		PRINT_SSL_ERR("SSL_CTX_use_PrivateKey_file");
		goto clean;
	}

	/* verify private key */
	DPRINTF(HGD_D_DEBUG, "Verify SSL private certificate");
	if (!SSL_CTX_check_private_key(ctx)) {
		DPRINTF(HGD_D_ERROR, "Can't verify TLS key: %s", ssl_key_path);
		PRINT_SSL_ERR("SSL_CTX_check_private_key");
		goto clean;
	}

	DPRINTF(HGD_D_DEBUG, "Verify SSL private certificate");
	sess->ssl = SSL_new(ctx);
	if (sess->ssl == NULL) {
		PRINT_SSL_ERR("SSL_new");
		goto clean;
	}

	DPRINTF(HGD_D_DEBUG, "SSL_set_fd");
	ssl_err = SSL_set_fd(sess->ssl, sess->sock_fd);
	if (ssl_err == 0) {
		PRINT_SSL_ERR("SSL_set_fd");
		goto clean;
	}

	DPRINTF(HGD_D_DEBUG, "SSL_accept");
	ssl_err = SSL_accept(sess->ssl);
	if (ssl_err != 1) {
		PRINT_SSL_ERR("SSL_accept");
		goto clean;
	}

	/* This cannot fail so no error check */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	ret = 0; /* all is well */
clean:

	if (ret == -1) {
		DPRINTF(HGD_D_INFO, "SSL connection failed");
		 /* XXX do we clean anything up on failure? */
		hgd_exit_nicely(); /* be paranoid and kick client */
	} else {
		DPRINTF(HGD_D_INFO, "SSL connection established");
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");
	}

	return (ret);
}

/* lookup table for command handlers */
struct hgd_cmd_despatch		cmd_despatches[] = {
	/* cmd,		n_args,	handler_function	*/
	{"np",		0,	hgd_cmd_now_playing},
	{"vo",		1,	hgd_cmd_vote_off},
	{"vo",		0,	hgd_cmd_vote_off_noarg},
	{"ls",		0,	hgd_cmd_playlist},
	{"user",	1,	hgd_cmd_user},
	{"q",		2,	hgd_cmd_queue},
	{"encrypt",	0,	hgd_cmd_encrypt},
	{"bye",		0,	NULL},	/* bye is special */
	{NULL,		0,	NULL}	/* terminate */
};

/* enusure atleast 1 more than the commamd with the most args */
uint8_t
hgd_parse_line(struct hgd_session *sess, char *line)
{
	char			*tokens[HGD_MAX_PROTO_TOKS];
	char			*next = line, *p;
	uint8_t			n_toks = 0;
	struct hgd_cmd_despatch *desp, *correct_desp;
	uint8_t			bye = 0;

	/* strip the line of \r\n */
	for (p = line; *p != 0; p++) {
		if ((*p == '\r') || (*p == '\n'))
			*p = 0;
	}

	/* tokenise */
	do {
		tokens[n_toks] = strdup(strsep(&next, "|"));
		DPRINTF(HGD_D_DEBUG, "tok %d: \"%s\"", n_toks, tokens[n_toks]);
	} while ((n_toks++ < HGD_MAX_PROTO_TOKS) && (next != NULL));

	DPRINTF(HGD_D_DEBUG, "Got %d tokens", n_toks);
	if ((n_toks == 0) || (strlen(tokens[0]) == 0)) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|no_tokens_sent");
		num_bad_commands++;
		return 0;
	}

	/* now we look up which function to call */
	correct_desp = NULL;
	for (desp = cmd_despatches; desp->cmd != NULL; desp ++) {

		if (strcmp(desp->cmd, tokens[0]) != 0)
			continue;

		if (n_toks - 1 != desp->n_args)
			continue;

		/* command is valid \o/ */
		correct_desp = desp;
		break;
	}

	/* command not found */
	if (correct_desp == NULL) {
		DPRINTF(HGD_D_DEBUG, "Despatching '%s' handler", tokens[0]);

		DPRINTF(HGD_D_WARN, "Invalid command");
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|invalid_command");
		num_bad_commands++;

		goto clean;
	}

	/* bye has special meaning */
	if (strcmp(correct_desp->cmd, "bye") == 0) {
		bye = 1;
		goto clean;
	}

	/* otherwise despatch */
	if (correct_desp->handler(sess, &tokens[1]) < 0) {
		/*
		 * this happens often, ie when a client tries to
		 * vote off twice, and that is fine, so we put the message
		 * in INFO rather than WARN
		 */
		DPRINTF(HGD_D_INFO, "despatch of '%s' for '%s' returned -1",
		    tokens[0], sess->cli_str);
		num_bad_commands++;
	} else
		num_bad_commands = 0;

clean:
	/* free tokens */
	for (; n_toks > 0; )
		free(tokens[--n_toks]);

	return bye;
}

void
hgd_service_client(int cli_fd, struct sockaddr_in *cli_addr)
{
	struct hgd_session	 sess;
	char			*recv_line;
	uint8_t			 exit;

	sess.cli_str = hgd_identify_client(cli_addr);
	sess.sock_fd = cli_fd;
	sess.cli_addr = cli_addr;
	sess.user = NULL;
	sess.ssl = NULL;

	if (sess.cli_str == NULL)
		xasprintf(&sess.cli_str, "unknown"); /* shouldn't happen */

	DPRINTF(HGD_D_INFO, "Client connection: '%s'", sess.cli_str);

	/* oh hai */
	hgd_sock_send_line(cli_fd, sess.ssl, HGD_GREET);

	/* main command recieve loop */
	exit = 0;
	do {
		recv_line = hgd_sock_recv_line(sess.sock_fd, sess.ssl);
		exit = hgd_parse_line(&sess, recv_line);
		free(recv_line);
		if (num_bad_commands >= HGD_MAX_BAD_COMMANDS) {
			DPRINTF(HGD_D_WARN,"Client abused server, "
			    "kicking '%s'", sess.cli_str);
			close(sess.sock_fd);
			exit_ok = 1;
			hgd_exit_nicely();
		}
	} while (!exit && !dying);

	/* laters */
	hgd_sock_send_line(cli_fd, sess.ssl, HGD_BYE);

	/* free up the hgd_session members */
	free(sess.cli_str);
	if (sess.user)
		free(sess.user);
}

void
hgd_sigchld(int sig)
{
	/* XXX is this safe? */
	sig = sig; /* quiet */
	waitpid(-1, NULL, 0); /* clear up exit status from proc table */
	signal(SIGCHLD, hgd_sigchld);
}

/* main loop that deals with network requests */
void
hgd_listen_loop()
{
	struct sockaddr_in	addr, cli_addr;
	int			cli_fd, child_pid = 0;
	socklen_t		cli_addr_len;
	int			sockopt = 1, data_ready;
	struct pollfd		pfd;

start:

	DPRINTF(HGD_D_DEBUG, "Setting up socket");

	if ((svr_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		DPRINTF(HGD_D_ERROR, "socket(): %s", SERROR);
		hgd_exit_nicely();
	}

	/* allow socket to be re-used right away after we exit */
	if (setsockopt(svr_fd, SOL_SOCKET, SO_REUSEADDR,
		     &sockopt, sizeof(sockopt)) < 0) {
		DPRINTF(HGD_D_WARN, "Can't set SO_REUSEADDR");
	}

	/* configure socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(svr_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		DPRINTF(HGD_D_ERROR, "Bind to port %d: %s", port, SERROR);
		hgd_exit_nicely();
	}

	if (listen(svr_fd, sock_backlog) < 0) {
		DPRINTF(HGD_D_ERROR, "Listen: %s", SERROR);
		hgd_exit_nicely();
	}

	DPRINTF(HGD_D_INFO, "Socket ready and listening on port %d", port);

	/* setup signal handler */
	signal(SIGCHLD, hgd_sigchld);

	while (1) {
		DPRINTF(HGD_D_INFO, "waiting for client connection");

		/* spin until something is ready */
		pfd.fd = svr_fd;
		pfd.events = POLLIN;
		data_ready = 0;

		while (!dying && !data_ready) {
			data_ready = poll(&pfd, 1, INFTIM);
			if (data_ready == -1) {
				if (errno != EINTR) {
					DPRINTF(HGD_D_ERROR, "Poll error");
					dying = 1;
				}
				data_ready = 0;
			}
		}

		if (dying) {
			exit_ok = 0;
			hgd_exit_nicely();
		}

		cli_addr_len = sizeof(cli_addr);
		cli_fd = accept(svr_fd, (struct sockaddr *) &cli_addr,
		    &cli_addr_len);

		if (cli_fd < 0) {
			DPRINTF(HGD_D_WARN, "Server failed to accept");
			close(svr_fd);
			/*
			 * accept will fail next time aswell :\
			 * it seems the fix is to re-initialise the socket
			 */
			goto start;
		}

		if (setsockopt(cli_fd, SOL_SOCKET, SO_REUSEADDR,
			    &sockopt, sizeof(sockopt)) < 0) {
			DPRINTF(HGD_D_WARN, "Can't set SO_REUSEADDR");
		}

		/* ok, let's deal with that request then */
		if (!single_client)
			child_pid = fork();

		if (!child_pid) {

			db = hgd_open_db(db_path);
			if (db == NULL)
				hgd_exit_nicely();

			hgd_service_client(cli_fd, &cli_addr);
			DPRINTF(HGD_D_DEBUG, "client service complete");

			/* and we are done with this client */
			if (shutdown(cli_fd, SHUT_RDWR) == -1)
				DPRINTF(HGD_D_WARN, "Can't shutdown socket");
			close(cli_fd);

			close(svr_fd);
			svr_fd = -1; /* prevent shutdown of svr_fd */
			exit_ok = 1;
			hgd_exit_nicely();
		} /* child block ends */

		close (cli_fd);
		DPRINTF(HGD_D_DEBUG, "client servicer PID = '%d'", child_pid);
		/* otherwise, back round for the next client */
	}
	/* NOREACH */
}

/* NOTE! -c is reserved for 'config file path' */
void
hgd_usage()
{
	printf("usage: hgd-netd <options>\n");
	printf("  -c		Set path to TLS certificate file\n");
	printf("  -d		Set hgd state directory\n");
	printf("  -E		Disable TLS encryption support\n");
	printf("  -f		Don't fork - service single client (debug)\n");
	printf("  -h		Show this message and exit\n");
	printf("  -k		Set path to TLS private key file\n");
	printf("  -n		Set number of votes required to vote-off\n");
	printf("  -p		Set network port number\n");
	printf("  -s		Set maximum upload size (in MB)\n");
	printf("  -v		Show version and exit\n");
	printf("  -x		Set debug level (0-3)\n");
	printf("  -y		Set path to noise to play when voting off\n");
}

int
main(int argc, char **argv)
{
	char			ch;

	/* if killed, die nicely */
	hgd_register_sig_handlers();

	hgd_dir = strdup(HGD_DFL_DIR);

	DPRINTF(HGD_D_DEBUG, "Parsing options");
	while ((ch = getopt(argc, argv, "c:d:Efhk:n:p:s:vx:y:")) != -1) {
		switch (ch) {
		case 'c':
			ssl_cert_path = optarg;
			DPRINTF(HGD_D_DEBUG,
			    "set ssl cert path to %s", ssl_cert_path);
			break;
		case 'd':
			free(hgd_dir);
			hgd_dir = strdup(optarg);
			DPRINTF(HGD_D_DEBUG, "Set hgd dir to '%s'", hgd_dir);
			break;
		case 'E':
			encryption_enabled = 0;
			DPRINTF(HGD_D_DEBUG,
			    "disabled encyption");
			break;
		case 'f':
			single_client = 1;
			DPRINTF(HGD_D_DEBUG, "Single client debug mode on");
			break;
		case 'k':
			ssl_key_path = optarg;
			DPRINTF(HGD_D_DEBUG,
			    "set ssl private key path to %s", ssl_key_path);
			break;
		case 'n':
			req_votes = atoi(optarg);
			DPRINTF(HGD_D_DEBUG,
			    "Set required-votes to %d", req_votes);
			break;
		case 'p':
			port = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "Set port to %d", port);
			break;
		case 's':
			max_upload_size = atoi(optarg) * (1024 * 1024);
			DPRINTF(HGD_D_DEBUG, "Set max upload size to %d",
			    (int) max_upload_size);
			break;
		case 'v':
			hgd_print_version();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG, "set debug to %d", hgd_debug);
			break;
		case 'y':
			vote_sound = optarg;
			DPRINTF(HGD_D_DEBUG,
			    "set voteoff sound %s", vote_sound);
			break;
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

	/* set up paths */
	xasprintf(&db_path, "%s/%s", hgd_dir, HGD_DB_NAME);
	xasprintf(&filestore_path, "%s/%s", hgd_dir, HGD_FILESTORE_NAME);
	hgd_mk_state_dir();

	/* Created tables if needed */
	db = hgd_open_db(db_path);
	if (db == NULL)
		hgd_exit_nicely();

	sqlite3_close(db);
	db = NULL;

	hgd_listen_loop();

	exit_ok = 1;
	hgd_exit_nicely();
	return (EXIT_SUCCESS); /* NOREACH */
}
