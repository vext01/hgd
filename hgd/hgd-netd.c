#define _GNU_SOURCE	/* linux */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "hgd.h"

#define HGD_DFL_PORT		6633
#define HGD_DFL_BACKLOG		5

/* XXX autogunk this at some stage */
#define HGD_VERSION		"0.1"
#define HGD_GREET		"HGD-" HGD_VERSION " :: " __DATE__ " " __TIME__
#define HGD_BYE			"Catch you later d00d!"

int				port = HGD_DFL_PORT;
int				sock_backlog = HGD_DFL_BACKLOG;
int				svr_fd = -1;

sqlite3				*db;
char				*db_path = HGD_DFL_DB_PATH;
char				*filestore_path = HGD_DFL_FILESTORE_PATH;

/* die nicely, closing socket */
void
hgd_kill_sighandler(int sig)
{
	sig = sig;

	sqlite3_close(db);
	shutdown(svr_fd, SHUT_RDWR);
	if (svr_fd >= 0)
		close(svr_fd);

	exit (EXIT_SUCCESS);
}

/* return some kind of host identifier, free when done */
char *
hgd_identify_client(struct sockaddr_in *cli_addr)
{
	char			cli_host[NI_MAXHOST];
	char			cli_serv[NI_MAXSERV];
	char			*ret = NULL;
	int			found_name;

	DPRINTF("%s: servicing client\n", __func__);

	found_name = getnameinfo((struct sockaddr *) cli_addr,
	    sizeof(struct sockaddr_in), cli_host, sizeof(cli_host), cli_serv,
	    sizeof(cli_serv), NI_NAMEREQD | NI_NOFQDN);

	if (found_name == 0)
		goto found; /* found a hostname */

	DPRINTF("%s: client hostname *not* found: %s\n",
	    __func__, gai_strerror(found_name));

	found_name = getnameinfo((struct sockaddr *) cli_addr,
	    sizeof(struct sockaddr_in), cli_host, sizeof(cli_host),
	    cli_serv, sizeof(cli_serv), NI_NUMERICHOST);

	if (found_name == 0)
		goto found; /* found an IP address */

	fprintf(stderr, "%s: cannot identify client ip: %s\n",
	    __func__,  gai_strerror(found_name));
	return NULL;

found:
	/* good, we got an identifier name/ip */
	xasprintf(&ret, "%s", cli_host);
	return ret;
}

int
hgd_get_playing_track_cb(void *arg, int argc, char **data, char **names)
{
	struct hgd_playlist_item	**ret, *t;

	/* silence compiler */
	argc = argc;
	names = names;

	/* populate a struct that we pick up later */
	t = xmalloc(sizeof(t));
	t->id = atoi(data[0]);
	t->filename = strdup(data[1]);
	t->user = strdup(data[2]);
	t->playing = 0;
	t->finished = 0;

	ret = (struct hgd_playlist_item **) arg;
	*ret = t;

	return SQLITE_OK;
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
	struct hgd_playlist_item *playing = NULL;
	char			*sql_err, *reply;
	int			 sql_res;

	DPRINTF("%s:\n", __func__);
	args = args; /* silence compiler */

	sql_res = sqlite3_exec(db,
	    "SELECT id, filename, user "
	    "FROM playlist WHERE playing=1 LIMIT 1",
	    hgd_get_playing_track_cb, &playing, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't get playing track: %s\n",
		    __func__, sqlite3_errmsg(db));
		hgd_sock_send_line(sess->sock_fd, "err|sql");
		return SQLITE_ERROR;
	}

	if (playing == NULL)
		hgd_sock_send_line(sess->sock_fd, "ok|0");
	else {
		xasprintf(&reply, "ok|1|%d|%s|%s",
		    playing->id, playing->filename, playing->user);
		hgd_sock_send_line(sess->sock_fd, reply);
		free(reply);
	}

	return 0;
}

int
hgd_cmd_user(struct hgd_session *sess, char **args)
{
	DPRINTF("%s: user on host '%s' identified as %s\n",
	    __func__, sess->cli_str, args[0]);

	sess->user = strdup(args[0]);
	hgd_sock_send_line(sess->sock_fd, "ok");

	return 0;
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
	char			*filename = args[0], *payload;
	size_t			bytes = atoi(args[1]);
	char			*unique_fn;
	int			f = -1;

	if (bytes == 0) {
		hgd_sock_send_line(sess->sock_fd, "err|size");
		return -1;
	}

	if (sess->user == NULL) {
		hgd_sock_send_line(sess->sock_fd, "err|user_not_identified");
		return -1;
	}

	/* prepare to recieve the media file and stash away */
	xasprintf(&unique_fn, "%s/%s.XXXXXXXX", filestore_path, filename);


	hgd_sock_send_line(sess->sock_fd, "ok...");
	payload = hgd_sock_recv(sess->sock_fd, bytes);

	f = mkstemp(unique_fn);
	if (!f) {
		warn("%s: mkstemp()", __func__);
		hgd_sock_send_line(sess->sock_fd, "err|internal");
		goto clean;
	}

	DPRINTF("%s: recieving %d byte payload '%s' from %s into %s\n",
	    __func__, (int) bytes, filename, sess->user, unique_fn);

	if (write(f, payload, bytes) == -1) {
		fprintf(stderr, "%s: failed to write %d bytes\n",
		    __func__, (int) bytes);
		hgd_sock_send_line(sess->sock_fd, "err|internal");
		goto clean;
	}

	/* XXX insert into database */

	hgd_sock_send_line(sess->sock_fd, "ok");

	DPRINTF("%s: transfer complete\n", __func__);

clean:
	if (f == -1)
		close(f);
	free(payload);
	free(unique_fn);

	return 0;
}

/* lookup table for command handlers */
struct hgd_cmd_despatch		cmd_despatches[] = {
	/* cmd,		n_args,	handler_function	*/
	{"np",		0,	hgd_cmd_now_playing},
	/*{"vo",	0,	hgd_cmd_vote_off},	*/
	/*{"ls",	0,	hgd_cmd_playlist},	*/
	{"user",	1,	hgd_cmd_user},
	{"q",		2,	hgd_cmd_queue},
	{"bye",		0,	NULL},	/* bye is special */
	{NULL,		0,	NULL}	/* terminate */
};

/* enusure atleast 1 more than the commamd with the most args */
#define	HGD_MAX_PROTO_TOKS	3
uint8_t
hgd_parse_line(struct hgd_session *sess, char *line)
{
	char			*tokens[HGD_MAX_PROTO_TOKS];
	char			*next = line, *p;
	uint8_t			n_toks = 0;
	struct hgd_cmd_despatch *desp, *correct_desp;
	uint8_t			bye = 0;

	/* strip the line of \r\n */
	for (p = line; *p != NULL; p++) {
		if ((*p == '\r') || (*p == '\n'))
			*p = NULL;
	}

	/* tokenise */
	do {
		tokens[n_toks] = strdup(strsep(&next, "|"));
		DPRINTF("%s: tok %d: %s\n", __func__, n_toks, tokens[n_toks]);
	} while ((n_toks++ < HGD_MAX_PROTO_TOKS) && (next != NULL));

	DPRINTF("%s: got %d tokens\n", __func__, n_toks);
	if ((n_toks == 0) || (strlen(tokens[0]) == 0)) {
		hgd_sock_send_line(sess->sock_fd, "err|no_tokens_sent");
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

	if (correct_desp != NULL) {
		DPRINTF("%s: despatching '%s' handler\n", __func__, tokens[0]);
		if (strcmp(correct_desp->cmd, "bye") != 0)
			correct_desp->handler(sess, &tokens[1]);
		else
			bye = 1;
	} else
		hgd_sock_send_line(sess->sock_fd, "err|invalid_command");


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

	if (sess.cli_str == NULL)
		xasprintf(&sess.cli_str, "unknown"); /* shouldn't happen */

	DPRINTF("%s: client connection: '%s'\n", __func__, sess.cli_str);

	/* oh hai */
	hgd_sock_send_line(cli_fd, HGD_GREET);

	/* main command recieve loop */
	exit = 0;
	do {
		recv_line = hgd_sock_recv_line(sess.sock_fd);
		exit = hgd_parse_line(&sess, recv_line);
		free(recv_line);
	} while (!exit);

	/* laters */
	hgd_sock_send_line(cli_fd, HGD_BYE);

	/* free up the hgd_session members */
	free(sess.cli_str);
	if (sess.user)
		free(sess.user);
}

/* main loop that deals with network requests */
void
hgd_listen_loop()
{
	struct sockaddr_in	addr, cli_addr;
	int			cli_fd, child_pid = 0;
	socklen_t		cli_addr_len;
	int			sockopt = 1;

	DPRINTF("%s: setting up socket\n", __func__);

	/* if killed, die nicely */
	signal(SIGKILL, hgd_kill_sighandler);

	if ((svr_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		errx(EXIT_FAILURE, "%s: socket(): ", __func__);

	/* allow socket to be re-used right away after we exit */
	if (setsockopt(svr_fd, SOL_SOCKET, SO_REUSEADDR,
		     &sockopt, sizeof(sockopt)) < 0) {
		warn("%s: cannot set SO_REUSEADDR", __func__);
	}

	/* configure socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(svr_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		errx(EXIT_FAILURE, "%s: bind to port %d", __func__, port);

	if (listen(svr_fd, sock_backlog) < 0)
		errx(EXIT_FAILURE, "%s: listen", __func__);

	DPRINTF("%s: socket ready and listening on port %d\n", __func__, port);

	while (1) {

		DPRINTF("%s: waiting for client connection\n", __func__);

		cli_addr_len = sizeof(cli_addr);
		cli_fd = accept(svr_fd, (struct sockaddr *) &cli_addr,
		    &cli_addr_len);

		if (cli_fd < 0) {
			warn("%s: server failed to accept", __func__);
			continue;
		}

		/* ok, let's deal with that request then */
		child_pid = fork();

		if (!child_pid) {
			hgd_service_client(cli_fd, &cli_addr);
			DPRINTF("%s: client service complete\n", __func__);
			shutdown(cli_fd, SHUT_RDWR);
			close(cli_fd);
			exit (EXIT_SUCCESS); /* client is done */
		}
		DPRINTF("%s: client servicer PID = '%d'\n",
		    __func__, child_pid);
		/* otherwise, back round for the next client */
	}

	/* NOREACH ATM */
	close(svr_fd);
}

int
main(int argc, char **argv)
{
	argc = argc; argv = argv;

	/* getopt XXX */
	if (argc > 1)
		port = atoi(argv[1]);

	db = hgd_open_db(db_path);
	if (db == NULL)
		return (EXIT_FAILURE);

	hgd_listen_loop();
	sqlite3_close(db);

	return (EXIT_SUCCESS);
}
