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

#include "config.h"
#include "cfg.h"

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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef HAVE_LIBCONFIG
#include <libconfig.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/wait.h>

#include "hgd.h"
#include "db.h"
#include "net.h"
#include "mplayer.h"

#include <openssl/ssl.h>
#ifdef HAVE_TAGLIB
#include <tag_c.h>
#endif

const char			*hgd_component = "hgd-netd";

int				port = HGD_DFL_PORT;
int				sock_backlog = HGD_DFL_BACKLOG;
int				svr_fd = -1;
int				flood_limit = HGD_MAX_USER_QUEUE;
int				background = 1;
long int			max_upload_size = HGD_DFL_MAX_UPLOAD;
uint8_t				num_bad_commands = 0;
uint8_t				lookup_client_dns = 1;

int				req_votes = HGD_DFL_REQ_VOTES;
uint8_t				single_client = 0;

char				*vote_sound = NULL;

SSL_METHOD			*method = NULL;
SSL_CTX				*ctx = NULL;

uint8_t				 crypto_pref = HGD_CRYPTO_PREF_IF_POSS;
uint8_t				 ssl_capable = 0;
char				*ssl_cert_path = NULL;
char				*ssl_key_path = NULL;

/*
 * clean up and exit, if the flag 'exit_ok' is not 1, upon call,
 * this indicates an error occured or kill signal was caught
 */
void
hgd_exit_nicely()
{
	if (!exit_ok)
		DPRINTF(HGD_D_ERROR, "hgd-netd was interrupted or crashed");

	if (svr_fd >= 0) {
		if (shutdown(svr_fd, SHUT_RDWR) == -1)
			DPRINTF(HGD_D_WARN,
			    "Can't shutdown socket: %s", SERROR);
		close(svr_fd);
	}
	if (db_path)
		free(db_path);
	if (filestore_path)
		free(filestore_path);
	if (state_path)
		free(state_path);
	if (db)
		sqlite3_close(db);

	hgd_cleanup_ssl(&ctx);

	if (restarting)
		hgd_restart_myself();

	/* after restart, so that we can report a SIGHUP */
	HGD_CLOSE_SYSLOG();

	_exit (!exit_ok);
}

#ifdef HAVE_TAGLIB
int
hgd_get_tag_metadata(char *filename, char **artist, char **title)
{
	TagLib_File		*file;
	TagLib_Tag		*tag;

	DPRINTF(HGD_D_DEBUG, "Attempting to read tags for '%s'", filename);

	*artist = xstrdup("");
	*title = xstrdup("");

	file = taglib_file_new(filename);
	if (file == NULL) {
		DPRINTF(HGD_D_DEBUG, "taglib could not open '%s'", filename);
		return (HGD_FAIL);
	}

	if (!taglib_file_is_valid(file)) {
		DPRINTF(HGD_D_WARN, "invalid tag in '%s'", filename);
		return (HGD_FAIL);
	}

	tag = taglib_file_tag(file);
	if (tag == NULL) {
		DPRINTF(HGD_D_WARN, "failed to get tag of '%s'", filename);
		return (HGD_FAIL);
	}

	/* all went well */
	free(*artist);
	free(*title);

	*artist = xstrdup(taglib_tag_artist(tag));
	*title = xstrdup(taglib_tag_title(tag));

	DPRINTF(HGD_D_DEBUG, "Got tag from '%s': '%s' by '%s'\n",
	    filename, *title, *artist);

	taglib_tag_free_strings();

	return (HGD_OK);
}
#else
int
hgd_get_tag_metadata(char *filename, char **artist, char **title)
{
	*artist = xstrdup("");
	*title = xstrdup("");

	return (HGD_FAIL);
}
#endif

/* return some kind of host identifier, free when done */
char *
hgd_identify_client(struct sockaddr_in *cli_addr)
{
	char			cli_host[NI_MAXHOST];
	char			cli_serv[NI_MAXSERV];
	char			*ret = NULL;
	int			found_name;

	DPRINTF(HGD_D_DEBUG, "Servicing client");

	/* first try to get a valid DNS name for the client */
	if (lookup_client_dns) {
		found_name = getnameinfo((struct sockaddr *) cli_addr,
		    sizeof(struct sockaddr_in),
		    cli_host, sizeof(cli_host), cli_serv,
		    sizeof(cli_serv), NI_NAMEREQD | NI_NOFQDN);

		if (found_name == 0)
			goto found; /* found a hostname */

		DPRINTF(HGD_D_WARN, "Client hostname *not* found: %s",
		    gai_strerror(found_name));
	}

	/* fallback on an ip address to identify the client */
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
	if (hgd_get_playing_item(&playing) == HGD_FAIL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|internal");
		hgd_free_playlist_item(&playing);
		return (HGD_FAIL);
	}

	if (playing.filename == NULL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok|0");
	} else {
		xasprintf(&reply, "ok|1|%d|%s|%s|%s|%s",
		    playing.id, playing.filename + strlen(HGD_UNIQ_FILE_PFX),
		    playing.tag_artist, playing.tag_title, playing.user);
		hgd_sock_send_line(sess->sock_fd, sess->ssl, reply);

		free(reply);
	}

	hgd_free_playlist_item(&playing);

	return (HGD_OK);
}

/*
 * Identify yourself to the server
 *
 * args: username, pass
 */
int
hgd_cmd_user(struct hgd_session *sess, char **args)
{
	struct hgd_user		*info;

	DPRINTF(HGD_D_INFO, "User on host '%s' authenticating as '%s'",
	    sess->cli_str, args[0]);

	/* get salt */
	info = hgd_authenticate_user(args[0], args[1]);
	if (info == NULL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|denied");
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_INFO, "User '%s' successfully authenticated", args[0]);

	/* only if successful do we assign the info struct */
	sess->user = info;
	hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");

	return (HGD_OK);
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
	int			f = -1, ret = HGD_OK;
	size_t			bytes_recvd = 0, to_write;
	ssize_t			write_ret;
	char			*filename, *tag_artist, *tag_title;

	if (sess->user == NULL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|user_not_identified");
		ret = HGD_FAIL;
		goto clean;
	}

	if ((flood_limit >= 0) &&
	    (hgd_num_tracks_user(sess->user->name) >= flood_limit)) {

		DPRINTF(HGD_D_WARN,
		    "User '%s' trigger flood protection", sess->user->name);
		hgd_sock_send_line(sess->sock_fd,
		    sess->ssl, "err|floodprotection");

		return (HGD_FAIL);
	}

	/* strip path, we don't care about that */
	filename = basename(filename_p);

	if ((bytes == 0) || ((long int) bytes > max_upload_size)) {
		DPRINTF(HGD_D_WARN, "Incorrect file size");
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|size");
		ret = HGD_FAIL;
		goto clean;
	}

	/* prepare to recieve the media file and stash away */
	xasprintf(&unique_fn, "%s/" HGD_UNIQ_FILE_PFX "%s", filestore_path, filename);
	DPRINTF(HGD_D_DEBUG, "Template for filestore is '%s'", unique_fn);

	f = mkstemps(unique_fn, strlen(filename) + 1); /* +1 for hyphen */
	if (f < 0) {
		DPRINTF(HGD_D_ERROR, "mkstemp: %s: %s",
		    filestore_path, SERROR);
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|internal");
		ret = HGD_FAIL;
		goto clean;
	}

	hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok|...");

	DPRINTF(HGD_D_INFO, "Recving %d byte payload '%s' from %s into %s",
	    (int) bytes, filename, sess->user->name, unique_fn);

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

			/* try to clean up a partial upload */
			if (fsync(f) < 0)
				DPRINTF(HGD_D_WARN,
				    "can't sync partial file: %s", SERROR);

			if (close(f) < 0)
				DPRINTF(HGD_D_WARN,
				    "can't close partial file: %s", SERROR);
			f = -1;

			if (unlink(unique_fn) < 0) {
				DPRINTF(HGD_D_WARN,
				    "can't unlink partial upload: '%s': %s",
				    unique_fn, SERROR);
			}

			ret = HGD_FAIL;
			goto clean;
		}
		write_ret = write(f, payload, to_write);

		/* XXX what if write returns less than the chunk? */
		if (write_ret < 0) {
			DPRINTF(HGD_D_ERROR, "Failed to write %d bytes: %s",
			    (int) to_write, SERROR);
			hgd_sock_send_line(sess->sock_fd,
			    sess->ssl, "err|internal");
			unlink(unique_fn); /* don't much care if this fails */
			ret = HGD_FAIL;
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

	/*
	 * get tag metadata
	 * no error that there is no #ifdef HAVE_TAGLIB
	 */
	hgd_get_tag_metadata(unique_fn, &tag_artist, &tag_title);

	/* insert track into db */
	if (hgd_insert_track(basename(unique_fn),
		    tag_artist, tag_title, sess->user->name) != HGD_OK) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|sql");
		goto clean;
	}

	/* always free, as we allocate "unknown" if it goes brown trousers */
	free(tag_artist);
	free(tag_title);

	hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");
	DPRINTF(HGD_D_INFO, "Transfer of '%s' complete", filename);
clean:
	if (f != -1)
		close(f);
	if (payload)
		free(payload);
	if (unique_fn)
		free(unique_fn);

	if (bytes_recvd != bytes)
		ret = HGD_FAIL;

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

	if (hgd_get_playlist(&list) == HGD_FAIL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|sql");
		return (HGD_FAIL);
	}

	/* and respond to client */
	xasprintf(&resp, "ok|%d", list.n_items);
	hgd_sock_send_line(sess->sock_fd, sess->ssl, resp);
	free(resp);

	for (i = 0; i < list.n_items; i++) {
		xasprintf(&resp, "%d|%s|%s|%s|%s", list.items[i]->id,
		    list.items[i]->filename + strlen(HGD_UNIQ_FILE_PFX),
		    list.items[i]->tag_artist, list.items[i]->tag_title,
		    list.items[i]->user);
		hgd_sock_send_line(sess->sock_fd, sess->ssl, resp);
		DPRINTF(HGD_D_DEBUG, "%s\n", resp);
		free(resp);
	}

	hgd_free_playlist(&list);

	return (HGD_OK);
}

int
hgd_cmd_vote_off(struct hgd_session *sess, char **args)
{
	struct hgd_playlist_item	 playing;
	char				*pid_path, pid_str[HGD_PID_STR_SZ];
	char				*scmd, id_str[HGD_ID_STR_SZ], *read;
	pid_t				 pid;
	FILE				*pid_file;
	int				 tid = -1, scmd_ret;
	struct flock			 fl;

	fl.l_type   = F_RDLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
	fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
	fl.l_start  = 0;        /* Offset from l_whence         */
	fl.l_len    = 0;        /* length, 0 = to EOF           */
	fl.l_pid    = getpid(); /* our PID                      */


	DPRINTF(HGD_D_INFO, "%s wants to kill track", sess->user->name);

	if (sess->user == NULL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|user_not_identified");
		return (HGD_FAIL);
	}

	memset(&playing, 0, sizeof(playing));
	if (hgd_get_playing_item(&playing) == HGD_FAIL) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|internal");
		return (HGD_FAIL);
	}

	/* is *anything* playing? */
	if (playing.filename == NULL) {
		DPRINTF(HGD_D_INFO, "No track is playing, can't vote off");
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|not_playing");
		return (HGD_FAIL);
	}

	/* is the file they are voting off playing? */
	if (args != NULL) { /* null if call from hgd_cmd_vote_off_noargs */
		tid = atoi(args[0]);
		if (playing.id != tid) {
			DPRINTF(HGD_D_INFO, "Track to voteoff isn't playing");
			hgd_sock_send_line(sess->sock_fd, sess->ssl,
			    "err|wrong_track");
			hgd_free_playlist_item(&playing);
			return (HGD_FAIL);
		}
	}
	hgd_free_playlist_item(&playing);

	/* insert vote */
	switch (hgd_insert_vote(sess->user->name)) {
	case HGD_OK:
		break; /* good */
	case 1:
		/* duplicate vote */
		DPRINTF(HGD_D_INFO, "User '%s' already voted",
		    sess->user->name);
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|duplicate_vote");
		return (HGD_OK);
		break;
	case HGD_FAIL:
	default:
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|sql");
		return (HGD_FAIL);
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
		return (HGD_OK);
	}

	DPRINTF(HGD_D_INFO, "Vote limit exceeded - kill track");

	/* kill mplayer then */
	/* XXX some of this needs to go in mplayer.c */
	xasprintf(&pid_path, "%s/%s", state_path, HGD_MPLAYER_PID_NAME);

	pid_file = fopen(pid_path, "r");
	if (pid_file == NULL) {
		DPRINTF(HGD_D_WARN,
		    "Can't find mplayer pid file: %s: %s", pid_path, SERROR);
		free(pid_path);
		return (HGD_FAIL);
	}

	if (fcntl(fileno(pid_file), F_SETLKW, &fl) == -1) {
		DPRINTF(HGD_D_ERROR, "failed to get lock on pid file");
		fclose(pid_file);
		return (HGD_FAIL);
	}

	free(pid_path);

	/* Read the pid from the pidfile */
	read = fgets(pid_str, HGD_PID_STR_SZ, pid_file);
	if (read == NULL) {
		if (!feof(pid_file)) {
			DPRINTF(HGD_D_WARN, "Can't find pid in pid file");
			fclose(pid_file);
			return (HGD_FAIL);
		}
	}

	/* Read the track id from the pid file */
	read = fgets(id_str, HGD_ID_STR_SZ, pid_file);
	if (read == NULL) {
		if (!feof(pid_file)) {
			DPRINTF(HGD_D_WARN, "Can't find pid in pid file");
			fclose(pid_file);
			return (HGD_FAIL);
		}
	}

	fl.l_type = F_UNLCK;
	fcntl(fileno(pid_file), F_SETLK, &fl);  /* F_GETLK, F_SETLK, F_SETLKW */

	fclose(pid_file);

	if (atoi(id_str) == playing.id) {
		pid = atoi(pid_str);
		DPRINTF(HGD_D_DEBUG, "Killing mplayer");
		if (kill(pid, SIGINT) < 0)
			DPRINTF(HGD_D_WARN, "Can't kill mplayer: %s", SERROR);

		/* Note: player daemon will empty the votes table */
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");
		return (HGD_OK);
	} else {
		DPRINTF(HGD_D_WARN,
		    "Hmm that was racey! wanted to kill %d but %s was playing",
		    playing.id, id_str);
		return(HGD_FAIL);
	}
}

int
hgd_cmd_vote_off_noarg(struct hgd_session *sess, char **unused)
{
	unused = unused;
	return (hgd_cmd_vote_off(sess, NULL));
}

int
hgd_cmd_encrypt_questionmark(struct hgd_session *sess, char **unused)
{

	unused = unused; /* lalalala */

	if ((crypto_pref != HGD_CRYPTO_PREF_NEVER) && (ssl_capable))
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok|tlsv1");
	else
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok|nocrypto");

	return (HGD_OK);
}

int
hgd_cmd_proto(struct hgd_session *sess, char **unused)
{
	char			*reply;

	unused = unused; /* lalalala */
	xasprintf(&reply, "ok|%d|%d", HGD_PROTO_VERSION_MAJOR,
	    HGD_PROTO_VERSION_MINOR);
	hgd_sock_send_line(sess->sock_fd, sess->ssl, reply);
	free(reply);

	return (HGD_OK);
}

int
hgd_cmd_encrypt(struct hgd_session *sess, char **unused)
{
	int			ssl_err = 0, ret = -1;

	unused = unused;

	if (sess->ssl != NULL) {
		DPRINTF(HGD_D_WARN, "User tried to enable encyption twice");
		return (HGD_FAIL);
	}

	if ((!ssl_capable) || (crypto_pref == HGD_CRYPTO_PREF_NEVER)) {
		DPRINTF(HGD_D_WARN, "User tried encrypt, when not possible");
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|nossl");
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "New SSL for session");
	sess->ssl = SSL_new(ctx);
	if (sess->ssl == NULL) {
		PRINT_SSL_ERR(HGD_D_ERROR, "SSL_new");
		goto clean;
	}

	DPRINTF(HGD_D_DEBUG, "SSL_set_fd");
	ssl_err = SSL_set_fd(sess->ssl, sess->sock_fd);
	if (ssl_err == 0) {
		PRINT_SSL_ERR(HGD_D_ERROR, "SSL_set_fd");
		goto clean;
	}

	DPRINTF(HGD_D_DEBUG, "SSL_accept");
	ssl_err = SSL_accept(sess->ssl);
	if (ssl_err != 1) {
		PRINT_SSL_ERR(HGD_D_ERROR, "SSL_accept");
		goto clean;
	}

	/* This cannot fail so no error check */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	ret = HGD_OK; /* all is well */
clean:

	if (ret == HGD_FAIL) {
		DPRINTF(HGD_D_INFO, "SSL connection failed");
		hgd_exit_nicely(); /* be paranoid and kick client */
	} else {
		DPRINTF(HGD_D_INFO, "SSL connection established");
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "ok");
	}

	return (ret);
}

/* lookup table for command handlers */
struct hgd_cmd_despatch		cmd_despatches[] = {
	/* cmd,		n_args,	secure,	handler_function */
	{"bye",		0,	0,	NULL},	/* bye is special */
	{"encrypt",	0,	0,	hgd_cmd_encrypt},
	{"encrypt?",	0,	0,	hgd_cmd_encrypt_questionmark},
	{"ls",		0,	1,	hgd_cmd_playlist},
	{"pl",		0,	1,	hgd_cmd_playlist},
	{"np",		0,	1,	hgd_cmd_now_playing},
	{"proto",	0,	0,	hgd_cmd_proto},
	{"q",		2,	1,	hgd_cmd_queue},
	{"user",	2,	1,	hgd_cmd_user},
	{"vo",		0,	1,	hgd_cmd_vote_off_noarg},
	{"vo",		1,	1,	hgd_cmd_vote_off},
	{NULL,		0,	0,	NULL}	/* terminate */
};

/* enusure atleast 1 more than the commamd with the most args */
uint8_t
hgd_parse_line(struct hgd_session *sess, char *line)
{
	char			*tokens[HGD_MAX_PROTO_TOKS];
	char			*next = line;
	uint8_t			n_toks = 0;
	struct hgd_cmd_despatch *desp, *correct_desp;
	uint8_t			bye = 0;

	DPRINTF(HGD_D_DEBUG, "Parsing line: %s", line);
	if (line == NULL) return HGD_FAIL;

	/* tokenise */
	do {
		tokens[n_toks] = xstrdup(strsep(&next, "|"));
		DPRINTF(HGD_D_DEBUG, "tok %d: \"%s\"", n_toks, tokens[n_toks]);
	} while ((n_toks++ < HGD_MAX_PROTO_TOKS) && (next != NULL));

	DPRINTF(HGD_D_DEBUG, "Got %d tokens", n_toks);
	if ((n_toks == 0) || (strlen(tokens[0]) == 0)) {
		hgd_sock_send_line(sess->sock_fd, sess->ssl,
		    "err|no_tokens_sent");
		num_bad_commands++;
		return (HGD_FAIL);
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

	/* if the server is *only* accepting SSL connections, a number
	 * of commands will be out of bounds until encryption is
	 * established.
	 */
	if ((crypto_pref == HGD_CRYPTO_PREF_ALWAYS) &&
	    (correct_desp->secure) &&
	    (sess->ssl == NULL)) {
		DPRINTF(HGD_D_WARN, "Client '%s' is trying to bypass SSL",
		    sess->cli_str);
		hgd_sock_send_line(sess->sock_fd, sess->ssl, "err|ssl_only");
		num_bad_commands++;
		goto clean;
	}

	/* otherwise despatch */
	if (correct_desp->handler(sess, &tokens[1]) != HGD_OK) {
		/*
		 * This happens often, ie when a client tries to
		 * vote off twice, and that is fine, so we put the message
		 * in INFO rather than WARN.
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

	return (bye);
}

void
hgd_service_client(int cli_fd, struct sockaddr_in *cli_addr)
{
	struct hgd_session	 sess;
	char			*recv_line;
	uint8_t			 exit, ssl_dead = 0;

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
	} while (!exit && !dying && !restarting);

	/*
	 * client service procs should not respawn as liesteners,
	 * that would suck. This may need tweaking later, as the exit
	 * message may be misinterpreted (?) Handling HUP is hard.
	 */
	if (restarting) {
		dying = 1;
		restarting = 0;
		exit_ok = 1;
	}

	/* laters */
	hgd_sock_send_line(cli_fd, sess.ssl, HGD_BYE);

	/* free up the hgd_session members */
	if (sess.cli_str != NULL)
		free(sess.cli_str);

	if (sess.ssl != NULL) {
		while (!ssl_dead)
			ssl_dead = SSL_shutdown(sess.ssl);

		SSL_free(sess.ssl);
	}

	if (sess.user) {
		if (sess.user->name)
			free(sess.user->name);
		free(sess.user);
	}
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

		while (!dying && !restarting && !data_ready) {
			data_ready = poll(&pfd, 1, INFTIM);
			if (data_ready == -1) {
				if (errno != EINTR) {
					DPRINTF(HGD_D_ERROR, "Poll error");
					dying = 1;
				}
				data_ready = 0;
			}
		}

		if (dying || restarting) {
			if (restarting)
				exit_ok = 1;
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

			/* turn off HUP handler */
			//signal(SIGHUP, SIG_DFL);

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

int
hgd_read_config(char **config_locations)
{
#ifdef HAVE_LIBCONFIG
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 * See hgd-playd.c for how to remove the stat when deb get into gear
	 */
	config_t		 cfg, *cf;

	cf = &cfg;

	if (hgd_load_config(cf, config_locations) == HGD_FAIL) {
		return (HGD_OK);
	}

	hgd_cfg_daemonise(cf, "netd", &background);
	hgd_cfg_netd_rdns(cf, &lookup_client_dns); 
	hgd_cfg_statepath(cf, &state_path);
	hgd_cfg_crypto(cf, "netd", &crypto_pref);	
	hgd_cfg_fork(cf, "netd", &single_client);
	hgd_cfg_netd_flood_limit(cf, &flood_limit);
	hgd_cf_netd_ssl_privkey(cf, &ssl_key_path);
	hgd_cfg_netd_votesound(cf, &req_votes);
	hgd_cfg_netd_port(cf, &port);
	hgd_cfg_netd_max_filesize(cf, &max_upload_size);
	hgd_cfg_netd_sslcert(cf, &ssl_cert_path);
	hgd_cfg_debug(cf, "netd", &hgd_debug);
	hgd_cfg_netd_voteoff_sound(cf, &vote_sound);

	/* we can destory config here because we copy all heap alloc'd stuff */
	config_destroy(cf);
#endif

	return (HGD_OK);
}

void
hgd_usage()
{
	printf("usage: hgd-netd <options>\n");
	printf("    -B			Do not daemonise, run in foreground\n");
#ifdef HAVE_LIBCONFIG
	printf("    -c <path>		Path to a config file to use\n");
#endif
	printf("    -D			Disable reverse DNS lookups for clients\n");
	printf("    -d <path>		Set hgd state directory\n");
	printf("    -E			Disable SSL encryption support\n");
	printf("    -e			Require SSL encryption from clients\n");
	printf("    -f			Don't fork - service single client (debug)\n");
	printf("    -F			Flood limit (-1 for no limit)\n");
	printf("    -h			Show this message and exit\n");
	printf("    -k <path>		Set path to SSL private key file\n");
	printf("    -n <num>		Set number of votes required to vote-off\n");
	printf("    -p <port>		Set network port number\n");
	printf("    -s <mbs>		Set maximum upload size (in MB)\n");
	printf("    -S <path>		Set path to SSL certificate file\n");
	printf("    -v			Show version and exit\n");
	printf("    -x <level>		Set debug level (0-3)\n");
	printf("    -y <path>		Set path to noise to play when voting off\n");
}

int
main(int argc, char **argv)
{
	char			 ch, *xdg_config_home;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2;

	/* as early as possible */
	HGD_INIT_SYSLOG_DAEMON();

	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_SERV_CFG );

	xdg_config_home =  getenv("XDG_CONFIG_HOME");
	if (xdg_config_home == NULL) {
		xasprintf(&config_path[2], "%s%s", getenv("HOME"),
		    HGD_USR_CFG_DIR HGD_SERV_CFG );
	} else {
		xasprintf(&config_path[2], "%s%s",
		    xdg_config_home , "/hgd" HGD_SERV_CFG);
	}

	/* if killed, die nicely */
	hgd_register_sig_handlers();

	state_path = xstrdup(HGD_DFL_DIR);
	ssl_key_path = xstrdup(HGD_DFL_KEY_FILE);
	ssl_cert_path = xstrdup(HGD_DFL_CERT_FILE);

	DPRINTF(HGD_D_DEBUG, "Parsing options:1");
	while ((ch = getopt(argc, argv, "Bc:Dd:EefF:hk:n:p:s:S:vx:y:")) != -1) {
		switch (ch) {
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
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG, "set debug to %d", hgd_debug);
			break;
		default:
			break; /* next getopt will catch errors */
		}
	}


	RESET_GETOPT();

	/* cache HUP info */
	if (hgd_cache_exec_context(argv) != HGD_OK)
		hgd_exit_nicely();

	hgd_read_config(config_path + num_config);

	DPRINTF(HGD_D_DEBUG, "Parsing options:2");
	while ((ch = getopt(argc, argv, "Bc:Dd:EefF:hk:n:p:s:S:vx:y:")) != -1) {
		switch (ch) {
		case 'B':
			background = 0;
			DPRINTF(HGD_D_DEBUG, "Not \"backgrounding\" daemon.");
			break;
		case 'c':
			break; /* already handled */
		case 'D':
			DPRINTF(HGD_D_DEBUG, "No client DNS lookups");
			lookup_client_dns = 0;
			break;
		case 'd':
			free(state_path);
			state_path = xstrdup(optarg);
			DPRINTF(HGD_D_DEBUG, "Set hgd dir to '%s'", state_path);
			break;
		case 'e':
			crypto_pref = HGD_CRYPTO_PREF_ALWAYS;
			DPRINTF(HGD_D_DEBUG, "Server will insist on crypto");
			break;
		case 'E':
			crypto_pref = HGD_CRYPTO_PREF_NEVER;
			DPRINTF(HGD_D_WARN, "Encryption disabled manually");
			break;
		case 'f':
			single_client = 1;
			DPRINTF(HGD_D_DEBUG, "Single client debug mode on");
			break;
		case 'F':
			flood_limit = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "Set flood limit to %d",
			    flood_limit);
			break;
		case 'k':
			free(ssl_key_path);
			ssl_key_path = optarg;
			DPRINTF(HGD_D_DEBUG,
			    "set ssl private key path to '%s'", ssl_key_path);
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
			/* XXX overflow? */
			max_upload_size = atoi(optarg) * HGD_MB;
			DPRINTF(HGD_D_DEBUG, "Set max upload size to %d",
			    (int) max_upload_size);
			break;
		case 'S':
			free(ssl_cert_path);
			ssl_cert_path = optarg;
			DPRINTF(HGD_D_DEBUG,
			    "set ssl cert path to '%s'", ssl_cert_path);
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
		case 'y':
			free(vote_sound);
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
	xasprintf(&db_path, "%s/%s", state_path, HGD_DB_NAME);
	xasprintf(&filestore_path, "%s/%s", state_path, HGD_FILESTORE_NAME);

	umask(~S_IRWXU);
	hgd_mk_state_dir();

	/* Created tables if needed */
	db = hgd_open_db(db_path);
	if (db == NULL)
		hgd_exit_nicely();

	sqlite3_close(db); /* re-opened later */
	db = NULL;

	/* unless the user actively disables SSL, we try to be capable */
	if (crypto_pref != HGD_CRYPTO_PREF_NEVER) {
		if (hgd_setup_ssl_ctx(&method, &ctx, 1,
		    ssl_cert_path, ssl_key_path) == 0) {
			DPRINTF(HGD_D_INFO, "Server is SSL capable");
			ssl_capable = 1;
		} else {
			DPRINTF(HGD_D_WARN, "Server is SSL incapable");
		}
	} else {
		DPRINTF(HGD_D_INFO, "Server was forced SSL incapable");
	}

	/* if -e, but something screwed up in the above, bail */
	if ((crypto_pref == HGD_CRYPTO_PREF_ALWAYS) && (ssl_capable != 1)) {
		DPRINTF(HGD_D_ERROR,
		    "Crypto was forced on, but server is incapable");
		hgd_exit_nicely();
	}

	/* alright, everything looks good, lets be a daemon and background */
	if (background) hgd_daemonise();

	hgd_listen_loop();

	exit_ok = 1;
	hgd_exit_nicely();
	return (EXIT_SUCCESS); /* NOREACH */
}
