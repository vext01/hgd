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

#define HGD_GREET		"ok|HGD-" HGD_VERSION
#define HGD_BYE			"ok|Catch you later d00d!"

int				port = HGD_DFL_PORT;
int				sock_backlog = HGD_DFL_BACKLOG;
int				svr_fd = -1;

char				*hgd_dir = NULL;
char				*db_path = NULL;
char				*filestore_path = NULL;
sqlite3				*db = NULL;

int				req_votes = HGD_DFL_REQ_VOTES;

/*
 * clean up and exit, if the flag 'exit_ok' is not 1, upon call,
 * this indicates an error occured or kill signal was caught
 */
void
hgd_exit_nicely()
{
	if (!exit_ok)
		fprintf(stderr,
		    "\n%s: hgd-netd was interrupted or crashed\n", __func__);

	/* XXX remove mplayer PID if existing */

	if (svr_fd >= 0) {
		if (shutdown(svr_fd, SHUT_RDWR) == -1)
			fprintf(stderr,
			    "%s: can't shutdown socket\n", __func__);
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

	DPRINTF(HGD_DEBUG_DEBUG, "%s: servicing client\n", __func__);

	found_name = getnameinfo((struct sockaddr *) cli_addr,
	    sizeof(struct sockaddr_in), cli_host, sizeof(cli_host), cli_serv,
	    sizeof(cli_serv), NI_NAMEREQD | NI_NOFQDN);

	if (found_name == 0)
		goto found; /* found a hostname */

	DPRINTF(HGD_DEBUG_WARN, "%s: client hostname *not* found: %s\n",
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
hgd_get_playing_item_cb(void *arg, int argc, char **data, char **names)
{
	struct hgd_playlist_item	*t;

	DPRINTF(HGD_DEBUG_DEBUG, "%s: a track is playing\n", __func__);

	/* silence compiler */
	argc = argc;
	names = names;

	t = (struct hgd_playlist_item *) arg;

	/* populate a struct that we pick up later */
	t->id = atoi(data[0]);
	t->filename = strdup(data[1]);
	t->user = strdup(data[2]);

	return SQLITE_OK;
}

struct hgd_playlist_item *
hgd_get_playing_item()
{
	struct hgd_playlist_item	*playing = NULL;
	int				 sql_res;
	char				*sql_err;

	playing = hgd_new_playlist_item();

	sql_res = sqlite3_exec(db,
	    "SELECT id, filename, user "
	    "FROM playlist WHERE playing=1 LIMIT 1",
	    hgd_get_playing_item_cb, playing, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't get playing track: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_free(sql_err);
		hgd_free_playlist_item(playing);
		return NULL;
	}

	if (playing->filename == NULL) {
		hgd_free_playlist_item(playing);
		return NULL;
	}

	return playing;
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
	struct hgd_playlist_item	*playing = NULL;
	char				*reply;

	DPRINTF(HGD_DEBUG_DEBUG, "%s:\n", __func__);
	args = args; /* silence compiler */

	/*
	 * XXX
	 * can't distinguish between error and nothing playing unfortunately
	 */
	playing = hgd_get_playing_item();
	if (playing == NULL)
		hgd_sock_send_line(sess->sock_fd, "ok|0");
	else {
		xasprintf(&reply, "ok|1|%d|%s|%s",
		    playing->id, playing->filename, playing->user);
		hgd_sock_send_line(sess->sock_fd, reply);
		free(reply);
		free(playing);
	}

	return 0;
}

int
hgd_cmd_user(struct hgd_session *sess, char **args)
{
	DPRINTF(HGD_DEBUG_DEBUG, "%s: user on host '%s' identified as %s\n",
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
#define HGD_BINARY_RECV_SZ	(2 << 8)
int
hgd_cmd_queue(struct hgd_session *sess, char **args)
{
	char			*filename_p = args[0], *payload = NULL;
	size_t			bytes = atoi(args[1]);
	char			*unique_fn, *sql, *sql_err;
	int			f = -1, sql_res;
	size_t			bytes_recvd = 0, to_write;
	ssize_t			write_ret;
	char			*filename;

	/* strip path, we don't care about that */
	filename = basename(filename_p);

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
	DPRINTF(HGD_DEBUG_DEBUG, "%s: template for filestore is '%s'\n", __func__, unique_fn);

	f = mkstemp(unique_fn);
	if (f < 0) {
		warn("%s: mkstemp: %s", __func__, filestore_path);
		hgd_sock_send_line(sess->sock_fd, "err|internal");
		goto clean;
	}

	hgd_sock_send_line(sess->sock_fd, "ok...");

	DPRINTF(HGD_DEBUG_DEBUG, "%s: recieving %d byte payload '%s' from %s into %s\n",
	    __func__, (int) bytes, filename, sess->user, unique_fn);

	/* recieve bytes in small chunks so that we dont use moar RAM */
	while (bytes_recvd != bytes) {

		if (bytes - bytes_recvd < HGD_BINARY_RECV_SZ)
			to_write = bytes - bytes_recvd;
		else
			to_write = HGD_BINARY_RECV_SZ;

		payload = NULL;

		DPRINTF(HGD_DEBUG_DEBUG, "%s: waiting for chunk of length %d bytes\n",
		    __func__, (int) to_write);

		payload = hgd_sock_recv_bin(sess->sock_fd, to_write);

		write_ret = write(f, payload, to_write);

		/* what if write returns less than the chunk XXX? */
		if (write_ret < 0) {
			warn("%s: failed to write %d bytes",
			    __func__, (int) to_write);
			hgd_sock_send_line(sess->sock_fd, "err|internal");
			goto clean;
		}

		bytes_recvd += to_write;
		DPRINTF(HGD_DEBUG_DEBUG, "%s: recieved binary chunk of length %d bytes\n",
		    __func__, (int) to_write);
		DPRINTF(HGD_DEBUG_DEBUG, "%s: expecting a further %d bytes\n",
		    __func__, (int) (bytes - bytes_recvd));

		free(payload);
	}
	payload = NULL;

	xasprintf(&sql,
	    "INSERT INTO playlist (filename, user, playing, finished)"
	    "VALUES ('%s', '%s', 0, 0)", basename(unique_fn), sess->user);

	/* insert into database */
	sql_res = sqlite3_exec(db, sql, NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't get playing track: %s\n",
		    __func__, sqlite3_errmsg(db));
		hgd_sock_send_line(sess->sock_fd, "err|sql");
		sqlite3_free(sql_err);
		goto clean;
	}

	hgd_sock_send_line(sess->sock_fd, "ok");

	DPRINTF(HGD_DEBUG_DEBUG, "%s: transfer complete\n", __func__);

clean:
	if (f == -1)
		close(f);
	if (payload)
		free(payload);
	free(payload);
	free(unique_fn);

	return 0;
}

struct hgd_playlist {
	unsigned int n_items;
	struct hgd_playlist_item **items;
};

int
hgd_get_playlist_cb(void *arg, int argc, char **data, char **names)
{
	struct hgd_playlist		*list;
	struct hgd_playlist_item	*item;

	/* shaddap gcc */
	argc = argc;
	names = names;

	list = (struct hgd_playlist *) arg;

	item = xmalloc(sizeof(struct hgd_playlist_item));

	item->id = atoi(data[0]);
	item->filename = strdup(data[1]);
	item->user = strdup(data[2]);
	item->playing = 0;	/* don't need in netd */
	item->finished = 0;	/* don't need in netd */

	/* remove unique string from filename, only playd uses that */
	item->filename[strlen(item->filename) - 9] = 0;

	list->items = xrealloc(list->items,
	    sizeof(struct hgd_playlist_item *) * list->n_items + 1);
	list->items[list->n_items] = item;

	list->n_items ++;

	return (SQLITE_OK);
}

/*
 * report back items in the playlist
 */
int
hgd_cmd_playlist(struct hgd_session *sess, char **args)
{
	int			sql_res;
	char			*sql_err, *resp;
	struct hgd_playlist	list;
	unsigned int		i;

	/* shhh */
	args = args;

	list.n_items = 0;
	list.items = NULL;

	DPRINTF(HGD_DEBUG_DEBUG, "%s: playlist request: %d\n", __func__, list.n_items);

	sql_res = sqlite3_exec(db,
	    "SELECT id, filename, user FROM playlist WHERE finished=0",
	    hgd_get_playlist_cb, &list, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't get playing track: %s\n",
		    __func__, sqlite3_errmsg(db));
		hgd_sock_send_line(sess->sock_fd, "err|sql");
		sqlite3_free(sql_err);
		return (-1);
	}

	DPRINTF(HGD_DEBUG_DEBUG, "%s: playlist request: %d items\n", __func__, list.n_items);

	/* and respond to client */
	xasprintf(&resp, "ok|%d", list.n_items);
	hgd_sock_send_line(sess->sock_fd, resp);
	free(resp);

	for (i = 0; i < list.n_items; i++) {
		xasprintf(&resp, "%d|%s|%s", list.items[i]->id,
		    list.items[i]->filename, list.items[i]->user);
		hgd_sock_send_line(sess->sock_fd, resp);
		free(resp);
	}

	/* free up */
	for (i = 0; i < list.n_items; i ++) {
		free(list.items[i]);
	}

	return (0);
}

int
hgd_get_num_votes_cb(void *arg, int argc, char **data, char **names)
{
	int			*num = (int *) arg;

	/* quiet */
	argc = argc;
	names = names;

	*num = atoi(data[0]);
	return (0);
}

int
hgd_get_num_votes()
{
	int			sql_res, num = -1;
	char			*sql, *sql_err;

	xasprintf(&sql, "SELECT COUNT (*) FROM votes;");
	sql_res = sqlite3_exec(db, sql, hgd_get_num_votes_cb, &num, &sql_err);
	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't get votes: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_free(sql_err);
		free(sql);
		return (-1);
	}
	free(sql);

	DPRINTF(HGD_DEBUG_DEBUG, "%s: %d votes so far\n", __func__, num);
	return num;
}

#define HGD_PID_STR_SZ		10
int
hgd_cmd_vote_off(struct hgd_session *sess, char **args)
{
	struct hgd_playlist_item	*playing = NULL;
	char				*pid_path, pid_str[HGD_PID_STR_SZ];
	char				*sql, *sql_err;
	pid_t				pid;
	FILE				*pid_file;
	size_t				read;
	int				sql_res, tid;

	DPRINTF(HGD_DEBUG_INFO, "%s: %s wants to kill track %d\n", __func__, sess->user, tid);

	if (sess->user == NULL) {
		hgd_sock_send_line(sess->sock_fd, "err|user_not_identified");
		return -1;
	}

	sess = sess; args = args;
	playing = hgd_get_playing_item();

	/* is *anything* playing? */
	if (playing == NULL) {
		fprintf(stderr,
		    "%s: no track is playing, can't vote off", __func__);
		hgd_sock_send_line(sess->sock_fd, "err|not_playing");
		hgd_free_playlist_item(playing);
		return (-1);
	}

	/* is the file they are voting off playing? */
	if (args != NULL) { /* null if call from hgd_cmd_vote_off_noargs */
		tid = atoi(args[0]);
		if (playing->id != tid) {
			fprintf(stderr,
			    "%s: track to vote off isn't playing\n", __func__);
			hgd_sock_send_line(sess->sock_fd, "err|wrong_track");
			hgd_free_playlist_item(playing);
			return (-1);
		}
	}
	hgd_free_playlist_item(playing);

	/* insert vote */
	asprintf(&sql, "INSERT INTO votes (user) VALUES ('%s');", sess->user);
	sql_res = sqlite3_exec(db, sql, NULL, NULL, &sql_err);
	free(sql);

	switch (sql_res) {
	case SQLITE_OK:
		break;
	case SQLITE_CONSTRAINT:
		DPRINTF(HGD_DEBUG_INFO, "%s: user '%s' already voted\n", __func__, sess->user);
		hgd_sock_send_line(sess->sock_fd, "err|duplicate_vote");
		sqlite3_free(sql_err);
		return (-1);
	default:
		hgd_sock_send_line(sess->sock_fd, "err|sql");
		fprintf(stderr, "%s: can't insert vote: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_free(sql_err);
		return (-1);
	}

	/* are we at the vote limit yet? */
	if (hgd_get_num_votes() < req_votes) {
		hgd_sock_send_line(sess->sock_fd, "ok");
		return 0;
	}

	DPRINTF(HGD_DEBUG_INFO, "%s: vote limit exceeded - kill track", __func__);

	/* kill mplayer then */
	xasprintf(&pid_path, "%s/%s", hgd_dir, HGD_MPLAYER_PID_NAME);
	pid_file = fopen(pid_path, "r");
	if (pid_file == NULL) {
		warn("%s: can't find mplayer pid file", __func__);
		free(pid_path);
		return -1;
	}

	free(pid_path);
	read = fread(pid_str, HGD_PID_STR_SZ, 1, pid_file);
	if (read == 0) {
		if (!feof(pid_file)) {
			warn("%s: can't find pid in pid file", __func__);
			fclose(pid_file);
			return -1;
		}
	}
	fclose(pid_file);

	pid = atoi(pid_str);
	DPRINTF(HGD_DEBUG_DEBUG, "%s: killing mplayer\n", __func__);
	if (kill(pid, SIGINT) < 0)
		warn("%s: can't kill mplayer", __func__);

	/* Note: player daemon will empty the votes table */
	hgd_sock_send_line(sess->sock_fd, "ok");

	return 0;
}

int
hgd_cmd_vote_off_noarg(struct hgd_session *sess, char **unused)
{
	unused = unused;
	return (hgd_cmd_vote_off(sess, NULL));
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
	for (p = line; *p != 0; p++) {
		if ((*p == '\r') || (*p == '\n'))
			*p = 0;
	}

	/* tokenise */
	do {
		tokens[n_toks] = strdup(strsep(&next, "|"));
		DPRINTF(HGD_DEBUG_DEBUG, "%s: tok %d: %s\n", __func__, n_toks, tokens[n_toks]);
	} while ((n_toks++ < HGD_MAX_PROTO_TOKS) && (next != NULL));

	DPRINTF(HGD_DEBUG_DEBUG, "%s: got %d tokens\n", __func__, n_toks);
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
		DPRINTF(HGD_DEBUG_DEBUG, "%s: despatching '%s' handler\n", __func__, tokens[0]);
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

	DPRINTF(HGD_DEBUG_DEBUG, "%s: client connection: '%s'\n", __func__, sess.cli_str);

	/* oh hai */
	hgd_sock_send_line(cli_fd, HGD_GREET);

	/* main command recieve loop */
	exit = 0;
	do {
		recv_line = hgd_sock_recv_line(sess.sock_fd);
		exit = hgd_parse_line(&sess, recv_line);
		free(recv_line);
	} while (!exit && !dying);

	/* laters */
	hgd_sock_send_line(cli_fd, HGD_BYE);

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
	waitpid(-1, NULL, NULL); /* clear up exit status from proc table */
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

	DPRINTF(HGD_DEBUG_DEBUG, "%s: setting up socket\n", __func__);

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

	DPRINTF(HGD_DEBUG_DEBUG, "%s: socket ready and listening on port %d\n", __func__, port);

	/* setup signal handler */
	signal(SIGCHLD, hgd_sigchld);

	while (1) {

		DPRINTF(HGD_DEBUG_DEBUG, "%s: waiting for client connection\n", __func__);

		/* spin until something is ready */
		pfd.fd = svr_fd;
		pfd.events = POLLIN;
		data_ready = 0;

		while (!dying && !data_ready) {
			data_ready = poll(&pfd, 1, INFTIM);
			if (data_ready == -1) {
				if (errno != EINTR) {
					warn("%s: poll error\n", __func__);
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
			warn("%s: server failed to accept", __func__);
			sleep(1);
			continue;
		}

		if (setsockopt(cli_fd, SOL_SOCKET, SO_REUSEADDR,
			    &sockopt, sizeof(sockopt)) < 0) {
			warn("%s: cannot set SO_REUSEADDR", __func__);
		}

		/* ok, let's deal with that request then */
		child_pid = fork();

		if (!child_pid) {

			db = hgd_open_db(db_path);
			if (db == NULL)
				hgd_exit_nicely();

			hgd_service_client(cli_fd, &cli_addr);
			DPRINTF(HGD_DEBUG_DEBUG, "%s: client service complete\n", __func__);

			/* XXX experimental - probably will be removed */
#if 0
			while (1) {
				pfd.fd = cli_fd;
				data_ready = poll(&pfd, 1, INFTIM);
				/* wait for a hangup */
				if (pfd.revents | POLLHUP) {
					hgd_exit_nicely();
				}
			}
#endif

			/* and we are done with this client */
			if (shutdown(cli_fd, SHUT_RDWR) == -1)
				fprintf(stderr,
				    "%s: can't shutdown socket\n", __func__);
			close(cli_fd);

			close(svr_fd);
			svr_fd = -1; /* prevent shutdown of svr_fd */
			exit_ok = 1;
			hgd_exit_nicely();
		} /* child block ends */

		close (cli_fd);
		DPRINTF(HGD_DEBUG_DEBUG, "%s: client servicer PID = '%d'\n",
		    __func__, child_pid);
		/* otherwise, back round for the next client */
	}
	/* NOREACH */
}

void
hgd_usage()
{
	printf("usage: hgd-netd <options>\n");
	printf("  -d		set hgd state directory\n");
	printf("  -h		show this message and exit\n");
	printf("  -n		set number of votes required to vote-off\n");
	printf("  -p		set network port number\n");
	printf("  -v		show version and exit\n");
	printf("  -x		set debug level (0-3)\n");
}

int
main(int argc, char **argv)
{
	char			ch;

	/* if killed, die nicely */
	hgd_register_sig_handlers();

	hgd_dir = strdup(HGD_DFL_DIR);

	DPRINTF(HGD_DEBUG_DEBUG, "%s: parsing options\n", __func__);
	while ((ch = getopt(argc, argv, "d:hn:p:vx:")) != -1) {
		switch (ch) {
		case 'd':
			free(hgd_dir);
			hgd_dir = strdup(optarg);
			DPRINTF(HGD_DEBUG_DEBUG,
			    "set hgd dir to '%s'\n", hgd_dir);
			break;
		case 'n':
			req_votes = atoi(optarg);
			DPRINTF(HGD_DEBUG_DEBUG,
			    "set required-votes to %d\n", req_votes);
			break;
		case 'p':
			port = atoi(optarg);
			DPRINTF(HGD_DEBUG_DEBUG,
			    "set port to %d\n", port);
			break;
		case 'v':
			printf("Hackathon Gunther Daemon v" HGD_VERSION "\n");
			printf("(C) Edd Barrett 2011\n");
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_DEBUG_DEBUG,
			    "set debug level to %d\n", hgd_debug);
			break;
		case 'h':
		default:
			hgd_usage();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		};

		argc -= optind;
		argv += optind;
	}

	/* set up paths */
	xasprintf(&db_path, "%s/%s", hgd_dir, HGD_DB_NAME);
	xasprintf(&filestore_path, "%s/%s", hgd_dir, HGD_FILESTORE_NAME);

	/* make state dir if not existing */
	if (mkdir(hgd_dir, 0700) != 0) {
		if (errno != EEXIST) {
			DPRINTF(HGD_DEBUG_ERROR,
			    "%s: %s", hgd_dir, serror());
			hgd_exit_nicely();
		}
	}

	/* make filestore if not existing */
	if (mkdir(filestore_path, 0700) != 0) {
		if (errno != EEXIST) {
			warn("%s: %s", __func__, filestore_path);
			hgd_exit_nicely();
		}
	}

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
