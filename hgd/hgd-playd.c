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

int				db_open = 0;
sqlite3				*db = NULL;
struct hgd_playlist_item	*next_track;
char				*db_path = HGD_DFL_DB_PATH;

void
hgd_exit_nicely(int status)
{
	if (db_open)
		sqlite3_close(db);

	exit (status);
}


void
hgd_play_track(struct hgd_playlist_item *t)
{
	int			status = 0, sql_res;
	char			*q, *sql_err;

	DPRINTF("%s: playing '%s' for '%s'\n", __func__, t->filename, t->user);

	/* mark it as playing in the database */
	xasprintf(&q, "UPDATE playlist SET playing=1 WHERE id=%d", t->id);
	sql_res = sqlite3_exec(db, q, NULL, NULL, &sql_err);
	free(q);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't initialise db: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_free(sql_err);
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
	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't initialise db: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_free(sql_err);
	}

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
	int			sql_res;
	char			*sql_err;

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
			sqlite3_free(sql_err);
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
	db = hgd_open_db(db_path);
	hgd_play_loop();

	argc = argc; argv = argv;

	hgd_exit_nicely(EXIT_SUCCESS);
	exit (EXIT_SUCCESS); /* NOREACH */
}
