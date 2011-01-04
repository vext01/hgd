#define _GNU_SOURCE	/* linux */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sqlite3.h>

#include "hgd.h"

char				*db_path = HGD_DFL_DB_PATH, *sql_err;
char				*mplayer_pid_path = HGD_DFL_MPLAYER_PID_PATH;
struct hgd_playlist_item	*next_track;
sqlite3				*db = NULL;
uint8_t				db_open = 0, hgd_debug = 1;
int				sql_res;

void
hgd_exit_nicely(int status)
{
	if (db_open)
		sqlite3_close(db);

	exit (status);
}

/* Open, create and initialise database */
int
hgd_open_db()
{
	/* open the database */
	if (sqlite3_open(db_path, &db)) {
		fprintf(stderr, "%s: can't open db: %s\n",
		    __func__, sqlite3_errmsg(db));
		hgd_exit_nicely(EXIT_FAILURE);
	}

	db_open = 1;

	sql_res = sqlite3_exec(db,
	    "CREATE TABLE IF NOT EXISTS playlist ("
	    "id INTEGER PRIMARY KEY,"
	    "filename VARCHAR(50),"
	    "user VARCHAR(15),"
	    "playing INTEGER,"
	    "finished INTEGER)",
	    NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't initialise db: %s\n",
		    __func__, sqlite3_errmsg(db));
		hgd_exit_nicely(EXIT_FAILURE);
	}

	return SQLITE_OK;
}

void
hgd_play_track(struct hgd_playlist_item *t)
{
	int			status = 0;
	char			*q;

	DPRINTF("%s: playing '%s' for '%s'\n", __func__, t->filename, t->user);

	/* mark it as playing in the database */
	xasprintf(&q, "UPDATE playlist SET playing=1 WHERE id=%d", t->id);
	sql_res = sqlite3_exec(db, q, NULL, NULL, &sql_err);
	free(q);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't initialise db: %s\n",
		    __func__, sqlite3_errmsg(db));
		hgd_exit_nicely(EXIT_FAILURE);
	}


	if (!fork()) {
		/* child - your the d00d who will play this track */
		execlp("mplayer", "mplayer", "-quiet",
		    t->filename, (char *) NULL);

		/* if we get here, the shit hit the fan with execlp */
		warn("execlp() failed");
		hgd_exit_nicely(EXIT_FAILURE);
	} else {
		wait(&status);
	}

	DPRINTF("%s: finished playing (exit %d)\n", __func__, status);

	/* mark it as finished in the database */
	xasprintf(&q,
	    "UPDATE playlist SET playing=0, finished=1 WHERE id=%d", t->id);
	sql_res = sqlite3_exec(db, q, NULL, NULL, &sql_err);
	free(q);

	hgd_free_playlist_item(t);
}

int
hgd_get_next_track_cb(void *na, int argc, char **data, char **names)
{
	struct hgd_playlist_item	*t;

	/* silence compiler */
	na = na;
	argc = argc;
	names = names;

	/* populate a struct that we pick up later */
	t = xmalloc(sizeof(t));
	t->id = atoi(data[0]);
	t->filename = strdup(data[1]);
	t->user = strdup(data[2]);
	t->playing = 0;
	t->finished = 0;

	next_track = t;

	return SQLITE_OK;
}

void
hgd_play_loop()
{
	/* forever play songs */
	DPRINTF("%s: starting play loop\n", __func__);
	while (1) {
		/* get the next track (if there is one) */
		next_track = NULL;
		sql_res = sqlite3_exec(db,
		   "SELECT id, filename, user "
		   "FROM playlist WHERE finished=0 LIMIT 1",
		   hgd_get_next_track_cb, NULL, &sql_err);

		if (sql_res != SQLITE_OK) {
			fprintf(stderr, "%s: can't get next track: %s\n",
			    __func__, sqlite3_errmsg(db));
			hgd_exit_nicely(EXIT_FAILURE);
		}

		if (next_track) {
			DPRINTF("%s: next track is: '%s'\n",
			    __func__, next_track->filename);
			hgd_play_track(next_track);
		} else {
			DPRINTF("%s: no tracks to play\n", __func__);
			sleep(1);
		}
	}
}

int
main(int argc, char **argv)
{
	hgd_open_db();
	hgd_play_loop();

	argc = argc; argv = argv;

	hgd_exit_nicely(EXIT_SUCCESS);
	exit (EXIT_SUCCESS); /* NOREACH */
}
