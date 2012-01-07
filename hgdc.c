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

#include "config.h"
#include "client.h"
#include "hgd.h"
#include "net.h"
#include "user.h"
#ifdef HAVE_LIBCONFIG
#include "cfg.h"
#endif

const char		*hgd_component = HGD_COMPONENT_HGDC;

/* protos */
int			 hgd_check_svr_response(char *resp, uint8_t x);

void
hgd_exit_nicely()
{
	uint8_t			ssl_ret = 0, i;

	if (!exit_ok)
		DPRINTF(HGD_D_ERROR,
		    "hgdc was interrupted or crashed - cleaning up");

	if (ssl) {
		/* as per SSL_shutdown() manual, we call at most twice */
		for (i = 0; i < 2; i++) {
			ssl_ret = SSL_shutdown(ssl);
			if (ssl_ret == 1)
				break;
		}

		if (ssl_ret != 1)
			DPRINTF(HGD_D_WARN, "couldn't shutdown SSL");

		SSL_free(ssl);
	}

	if (ctx)
		hgd_cleanup_ssl(&ctx);

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

	HGD_CLOSE_SYSLOG();
	_exit(!exit_ok);
}


void
hgd_usage()
{
	printf("Usage: hgdc [opts] command [args]\n\n");
	printf("  Commands include:\n");
	printf("    cfg\t\t\tEdit config file with ${EDITOR}\n");
	printf("    hud\t\t\tHeads up display\n");
	printf("    id\t\t\tShow user account details and vote info\n");
	printf("    ls\t\t\tShow playlist\n");
	printf("    np\t\t\tNow playing\n");
	printf("    q <file1> [...]\tQueue track(s)\n");
	printf("    vo\t\t\tVote-off current track\n");

	printf("\n  Admin Commands include:\n");
	printf("    pause\t\t\tPause the current song\n");
	printf("    skip\t\t\tSkip the current song\n");
	printf("    user-add <user> [password]\tAdd a user\n");
	printf("    user-del <user>\t\tRemove a user\n");
	printf("    user-list\t\t\tList Users\n");
	printf("    user-mkadmin <user>\t\tGrant user admin rights\n");
	printf("    user-noadmin <user>\t\tRevoke user admin rights\n");

	printf("\n  Options include:\n");
	printf("    -A\t\t\tColours off\n");
	printf("    -a\t\t\tColours on\n");
#ifdef HAVE_LIBCONFIG
	printf("    -c\t\t\tSet config location\n");
#endif
	printf("    -E\t\t\tRefuse to use encryption\n");
	printf("    -e\t\t\tForce encryption\n");
	printf("    -h\t\t\tShow this message and exit\n");
	printf("    -m <num>\t\tMax num items to show in playlist\n");
	printf("    -p <port>\t\tSet connection port\n");
	printf("    -r <secs>\t\trefresh rate (only in hud mode)\n");
	printf("    -s <host/ip>\tSet connection address\n");
	printf("    -u <username>\tSet username\n");
	printf("    -x <level>\t\tSet debug level (0-3)\n");
	printf("    -v\t\t\tShow version and exit\n");
}

#define HGD_PROG_BAR_WIDTH	33
#define HGD_PROG_FILE_WIDTH	"40"
void
hgd_print_progress(char *filename, float progress)
{
	char			*trunc_filename = NULL;
	char			 bar[HGD_PROG_BAR_WIDTH + 1];
	int			 upto = HGD_PROG_BAR_WIDTH * progress;
	int			 i;
	char			*p;

	if (progress < 1) {
		/* fill in progress bar */
		memset(bar, ' ', HGD_PROG_BAR_WIDTH);
		bar[HGD_PROG_BAR_WIDTH] = '\0';
		for (i = 0, p = bar; i < upto; i++)
			*p++ = '*';

		bar[0] = '|';
		bar[HGD_PROG_BAR_WIDTH - 1] = '|';
		hgd_set_line_colour(ANSI_YELLOW);

	} else {
		memset(bar, '*', HGD_PROG_BAR_WIDTH);
		bar[HGD_PROG_BAR_WIDTH] = '\0';

		bar[0] = '|';
		bar[HGD_PROG_BAR_WIDTH - 1] = '|';
		hgd_set_line_colour(ANSI_GREEN);
	}

	trunc_filename = xstrdup(basename(filename));
	hgd_truncate_string(trunc_filename, 40);

	printf("\r%s %-" HGD_PROG_FILE_WIDTH "s %3d%%",
	    bar, trunc_filename, (int) (progress * 100));
	free(trunc_filename);

	/* reset colours */
	hgd_set_line_colour(ANSI_WHITE);
}

int
hgd_queue_track_cb(void *arg, float progress)
{
	char			*filename = (char *) arg;

	hgd_print_progress(filename, progress);

	return (HGD_OK);
}

int
hgd_queue_track(char *filename)
{
	if (hgd_cli_queue_track(filename, filename, hgd_queue_track_cb)
	    != HGD_OK)
		return (HGD_FAIL);

	hgd_print_progress(filename, 1);
	printf("\n");

	return (HGD_OK);
}

/* upload and queue a file to the playlist */
int
hgd_req_queue(int n_args, char **args)
{
	int			tnum, ret = HGD_OK;

	DPRINTF(HGD_D_DEBUG, "Will queue %d tracks", n_args);

	/* one iteration per track which will be uploaded */
	for (tnum = 0; tnum < n_args; tnum++)
		if (hgd_queue_track(args[tnum]) != HGD_OK) {
			ret = HGD_FAIL;
		}

	if (ret != HGD_OK)
		DPRINTF(HGD_D_INFO, "Some tracks failed to upload");
	else
		DPRINTF(HGD_D_INFO, "Finished uploading tracks");

	return (ret);
}

int
hgd_print_track(struct hgd_playlist_item *it, uint8_t first)
{
	int			 ret = HGD_OK;

	if (first)
		hgd_set_line_colour(ANSI_GREEN);
	else
		hgd_set_line_colour(ANSI_RED);

	printf(" [ #%04d queued by '%s' ]\n", it->id, it->user);

	printf("   Filename: '%s'\n",
	    hgd_truncate_string(it->filename,
	    HGD_TERM_WIDTH - strlen("   Filename: ''")));

	printf("   Artist:   ");
	if (strcmp(it->tags.artist, "") != 0)
		printf("'%s'\n", hgd_truncate_string(it->tags.artist,
			    HGD_TERM_WIDTH - strlen("   Artist:   ''")));
	else
		printf("<unknown>\n");

	printf("   Title:    ");
	if (strcmp(it->tags.title, "") != 0)
		printf("'%s'\n",
		    hgd_truncate_string(it->tags.title,
		    HGD_TERM_WIDTH - strlen("   Title:    ''")));
	else
		printf("<unknown>\n");


	/* thats it for compact entries */
	if (!first)
		goto skip_full;

	printf("   Album:    ");
	if (strcmp(it->tags.album, "") != 0)
		printf("'%s'\n", hgd_truncate_string(it->tags.album,
		    HGD_TERM_WIDTH - strlen("   Album:    ''")));
	else
		printf("<unknown>\n");

	printf("   Genre:    ");
	if (strcmp(it->tags.genre, "") != 0)
		printf("'%s'\n", hgd_truncate_string(it->tags.genre,
			    HGD_TERM_WIDTH - strlen("   Genre:    ''")));
	else
		printf("<unknown>\n");

	printf("   Year:     ");
	if (it->tags.year != 0)
		printf("%d\n", it->tags.year);
	else
		printf("<unknown>\n");

	/* audio properties all on one line */
	printf("   Audio:    ");

	if (it->tags.duration != 0)
		printf("%4ds", it->tags.duration);
	else
		printf("%4ss", "????");

	if (it->tags.samplerate != 0)
		printf("   %5dhz", it->tags.samplerate);
	else
		printf("   %5shz", "?");

	if (it->tags.bitrate != 0)
		printf("   %3dkbps", it->tags.bitrate);
	else
		printf("   %3skbps", "?");

	if (it->tags.channels != 0)
		printf("   %d channels\n", it->tags.channels);
	else
		printf("   %s channels\n", "?");

	/* vote off info */
	printf("   Votes needed to skip:    %d\n", it->votes_needed);

	switch (it->has_voted) {
	case 0:
		printf("   You may vote off this track.\n");
		break;
	case 1:
		hgd_set_line_colour(ANSI_CYAN);
		printf("   You HAVE voted-off this track.\n");
		break;
	case -1:
		printf("   Could not auhtenticate. "
		    "Log in to enable vote-off functionality.\n");
		break;
	default:
		DPRINTF(HGD_D_ERROR, "Bogus 'has_voted' field");
		ret = HGD_FAIL;
	};

skip_full:
	hgd_set_line_colour(ANSI_WHITE);

	return (ret);
}

void
hgd_hline()
{
	int			i;

	for (i = 0; i < HGD_TERM_WIDTH; i++)
		printf("-");
	printf("\n");
}

int
hgd_req_vote_off(int n_args, char **args)
{
	char			*resp;

	(void) args;
	(void) n_args;

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
hgd_req_playlist(int n_args, char **args)
{
	struct hgd_playlist		*list;
	int				 i = 0;

	(void) args;
	(void) n_args;

	/*
	 * we try to log in to get info about vote-off. If it fails,
	 * so be it. We just won't show any vote info for the user.
	 */
	if (!authenticated)
		hgd_client_login(sock_fd, ssl, user);

	if (hgd_cli_get_playlist(&list) != HGD_OK)
		return (HGD_FAIL);

	if (list->n_items == 0) {
		printf("Playlist empty.\n");
	} else {
		for (i = 0; i < list->n_items; i++) {

			if ((max_playlist_items != 0) &&
			    (i >= max_playlist_items))
				break;

			hgd_hline();
			hgd_print_track(list->items[i], i == 0);
		}
	}

	hgd_hline();

	hgd_free_playlist(list);
	free(list);

	return (HGD_OK);
}

/*
 * Heads up display mode
 * May make this more spctacular at some stage...
 */
int
hgd_req_hud(int n_args, char **args)
{
	int			status;

	(void) args;
	(void) n_args;

	/* pretty clunky ;) */
	while (1) {
		status = system("clear");
		if (status != 0)
			DPRINTF(HGD_D_WARN, "clear screen failed");

		hgd_set_line_colour(ANSI_YELLOW);
		printf("HGD Server @ %s -- Playlist:\n\n", host);
		hgd_set_line_colour(ANSI_WHITE);

		if (hgd_req_playlist(0, NULL) != HGD_OK)
			return (HGD_FAIL);

		sleep(hud_refresh_speed);
	}

	return (HGD_OK);
}

int
hgd_req_skip(int n_args, char **args)
{
	char			*resp;

	(void) args;
	(void) n_args;

	hgd_sock_send_line(sock_fd, ssl, "skip");

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "Skip failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_pause(int n_args, char **args)
{
	char			*resp;

	(void) args;
	(void) n_args;

	hgd_sock_send_line(sock_fd, ssl, "pause");

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "Pause failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_user_add(int n_args, char **args)
{
	char			*resp;
	char			*msg;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-add|%s|%s", args[0], args[1]);

	hgd_sock_send_line(sock_fd, ssl, msg);

	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "Add user failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_user_add_prompt(int n_args, char **args)
{
	char	*pass = calloc (HGD_MAX_PASS_SZ, sizeof(char));
	char	*args2[2];

	(void) n_args;

	hgd_readpassphrase_confirmed(pass, "New user's password: ");
	args2[0] = args[0];
	args2[1] = pass;

	return hgd_req_user_add(2, args2);
}

int
hgd_req_user_list(int n_args, char **args)
{
	char			*resp, *permstr;
	char			*msg, *p;
	int			n_items, i;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-list");
	hgd_sock_send_line(sock_fd, ssl, msg);
	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "list users failed");
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

	DPRINTF(HGD_D_DEBUG, "expecting %d users in list", n_items);

	for (i = 0; i < n_items; i++) {
		DPRINTF(HGD_D_DEBUG, "getting user %d", i);
		resp = hgd_sock_recv_line(sock_fd, ssl);

		if ((p = strchr(resp, '|')) == NULL) {
			DPRINTF(HGD_D_WARN, "could not find perms field");
		} else {
			*p++ = 0;
			hgd_gen_perms_str(atoi(p), &permstr);
			printf("%-20s %s\n", resp, permstr);
			free(permstr);
		}

		free(resp);
	}

	return (HGD_OK);
}

int
hgd_req_user_del(int n_args, char **args)
{
	char			*resp;
	char			*msg;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-del|%s", args[0]);

	hgd_sock_send_line(sock_fd, ssl, msg);

	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "del user failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}


int
hgd_req_user_mkadmin(int n_args, char **args)
{
	char			*resp;
	char			*msg;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-mkadmin|%s", args[0]);

	hgd_sock_send_line(sock_fd, ssl, msg);

	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "mkadmin failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_user_noadmin(int n_args, char **args)
{
	char			*resp;
	char			*msg;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-noadmin|%s", args[0]);

	hgd_sock_send_line(sock_fd, ssl, msg);

	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "noadmin failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_np(int n_args, char **args)
{
	char				*resp = NULL, *p;
	int			 	 ret = HGD_FAIL;
	struct hgd_playlist_item 	*it = NULL;

	(void) n_args;
	(void) args;

	/*
	 * we try to log in to get info about vote-off. If it fails,
	 * so be it. We just won't show any vote info for the user.
	 */
	if (!authenticated)
		hgd_client_login(sock_fd, ssl, user);

	hgd_sock_send_line(sock_fd, ssl, "np");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL)
		return (HGD_FAIL);

	/* find 1st | */
	p = strchr(resp, '|');
	if (!p) {
		DPRINTF(HGD_D_ERROR, "Failed to find separator1");
		goto fail;
	}

	/* check that something is even playing */
	if (*(p+1) != '1')
		printf("Nothing playing right now.\n");
	else {
		/* find 2nd | */
		p = strchr(p + 1, '|');
		if (!p) {
			DPRINTF(HGD_D_ERROR, "Failed to find separator2");
			goto fail;
		}

		it = xmalloc(sizeof(*it));
		if (hgd_cli_populate_track(&it, p + 1) != HGD_OK) {
			ret = HGD_FAIL;
			goto fail;
		}
		hgd_print_track(it, 1);
	}

	ret = HGD_OK;
fail:
	if (resp)
		free(resp);

	if (it) {
		hgd_free_playlist_item(it);
		free(it);
	}

	return (ret);
}

int
hgd_req_id(int n_args, char **args)
{
	char			*resp = NULL, *toks[4] = {"", "", "", ""};
	char			*next, *perms_str = NULL;
	int			 ret = HGD_FAIL, n_toks = 0;

	(void) n_args;
	(void) args;

	hgd_sock_send_line(sock_fd, ssl, "id");
	resp = next = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL)
		goto fail;

	do {
		toks[n_toks] = strsep(&next, "|");
		n_toks++;
	} while ((n_toks < 4) && (next != NULL));

	/* build permissions string, if we add more this changes */
	if (atoi(toks[2]) & HGD_AUTH_ADMIN)
		perms_str = "ADMIN";
	else
		perms_str = "NONE";

	printf("  You are %s, permissions: %s, voted: %d\n",
	    toks[1], perms_str, atoi(toks[3]));

	ret = HGD_OK;
fail:
	if (resp)
		free(resp);

	return (ret);
}

int
hgd_req_edit_config(int n_args, char **args)
{
	return (hgd_client_edit_config());
}

/* lookup for request despatch */
struct hgd_req_despatch req_desps[] = {
/*	cmd,		n_args,	need_auth,	handler,		varargs */
	{"cfg",		0,	0,		hgd_req_edit_config,	0},
	{"id",		0,	1,		hgd_req_id,		0},
	{"ls",		0,	0,		hgd_req_playlist,	0},
	{"hud",		0,	0,		hgd_req_hud,		0},
	{"vo",		0,	1,		hgd_req_vote_off,	0},
	{"np",		0,	0,		hgd_req_np,		0},
	{"q",		1,	1,		hgd_req_queue,		1},
	/* play control */
	{"skip",	0,	1,		hgd_req_skip,		0},
	{"pause",	0,	1,		hgd_req_pause,		0},
	/* users */
	{"user-add",	2,	1,		hgd_req_user_add,	0},
	{"user-add",	1,	1,		hgd_req_user_add_prompt,0},
	{"user-list",	0,	1,		hgd_req_user_list,	0},
	{"user-del",	1,	1,		hgd_req_user_del,	0},
	{"user-mkadmin",1,	1,		hgd_req_user_mkadmin,	0},
	{"user-noadmin",1,	1,		hgd_req_user_noadmin,	0},
	{NULL,		0,	0,		NULL,			0} /* end */
};


/* parse command line args */
int
hgd_exec_req(int argc, char **argv)
{
	struct hgd_req_despatch		*desp, *correct_desp = NULL;

	DPRINTF(HGD_D_DEBUG, "Try to execute a '%s' command with %d args",
	    argv[0], argc - 1);

	if (argc == 0) {
		hgd_usage();
		exit_ok = 1;
		hgd_exit_nicely();
		return (HGD_FAIL); /* UNREACH, to keep clang-sa happy */
	}

	for (desp = req_desps; desp->req != NULL; desp++) {
		if (strcmp(desp->req, argv[0]) != 0)
			continue;

		if ((desp->varargs) && (argc - 1 < desp->n_args))
			continue;
		else if ((!desp->varargs) && (argc - 1 != desp->n_args))
			continue;

		correct_desp = desp; /* found it */
		break;
	}

	if (correct_desp == NULL) {
		hgd_usage();
		exit_ok = 1;
		hgd_exit_nicely();
		return (HGD_FAIL); /* UNREACH, to keep clang-sa happy */
	}

	/* once we know that the hgdc is used properly, open connection */
	if (hgd_setup_socket() != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Cannot setup socket");
		return (HGD_FAIL);
	}

	/* check protocol matches the server before we continue */
	if (hgd_check_svr_proto() != HGD_OK)
		return (HGD_FAIL);

	DPRINTF(HGD_D_DEBUG, "Despatching request '%s'", correct_desp->req);
	if ((!authenticated) && (correct_desp->need_auth)) {
		if (hgd_client_login(sock_fd, ssl, user) != HGD_OK) {
			return (HGD_FAIL);
		}
	}

	correct_desp->handler(argc - 1, &argv[1]);

	return (HGD_OK);
}

int
hgd_read_config(char **config_locations)
{
#ifdef HAVE_LIBCONFIG
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 * see hgd-playd.c for how to remove need for stat.
	 */
	config_t		 cfg, *cf;
	int			 ret = HGD_OK;

	cf = &cfg;

	if (hgd_load_config(cf, config_locations) == HGD_FAIL) {
		DPRINTF(HGD_D_WARN, "Failed to load config files");
		return (HGD_OK);
	}

	hgd_cfg_c_colours(cf, &colours_on);
	hgd_cfg_crypto(cf, "hgdc", &crypto_pref);
	hgd_cfg_c_maxitems(cf, &max_playlist_items);
	hgd_cfg_c_hostname(cf, &host);
	hgd_cfg_c_port(cf, &port);
	hgd_cfg_c_password(cf, &password, *config_locations);
	hgd_cfg_c_refreshrate(cf, &hud_refresh_speed);
	hgd_cfg_c_username(cf, &user);
	hgd_cfg_c_debug(cf, &hgd_debug);

	config_destroy(cf);
	return (ret);
#else
	return(HGD_OK);
#endif
}

int
main(int argc, char **argv)
{
	char			*resp;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2, ch;

	/* open syslog as soon as possible */
	HGD_INIT_SYSLOG();

	host = xstrdup(HGD_DFL_HOST);
#ifdef HAVE_LIBCONFIG
	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_CLI_CFG );
	config_path[2] = hgd_get_XDG_userprefs_location(hgdc);
#endif

	/*
	 * Need to do getopt twice because x and c need to be done before
	 * reading the config
	 */
	while ((ch = getopt(argc, argv, "aAc:Eehm:p:r:s:u:vx:")) != -1) {
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
				config_path[num_config] = xstrdup(optarg);
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

	while(num_config > 0) {
		if (config_path[num_config] != NULL) {
			free (config_path[num_config]);
			config_path[num_config] = NULL;
		}
		num_config--;
	}


	RESET_GETOPT();

	while ((ch = getopt(argc, argv, "aAc:Eehm:p:r:s:u:vx:")) != -1) {
		switch (ch) {
		case 'a':
			DPRINTF(HGD_D_DEBUG, "ANSI colours on");
			colours_on = 1;
			break;
		case 'A':
			DPRINTF(HGD_D_DEBUG, "ANSI colours off");
			colours_on = 0;
			break;
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
		case 'm':
			max_playlist_items = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "Set max playlist items to %d",
			    max_playlist_items);
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
		case 'r':
			hud_refresh_speed = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "Set hud refresh rate to %d",
			    hud_refresh_speed);
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
	if (hgd_exec_req(argc, argv) == HGD_OK)
		exit_ok = 1;
	else {
		exit_ok = 0;
		goto kthxbye;
	}

	/* try to sign off */
	hgd_sock_send_line(sock_fd, ssl, "bye");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	hgd_check_svr_response(resp, 1);
	free(resp);

	exit_ok = 1;

kthxbye:
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
