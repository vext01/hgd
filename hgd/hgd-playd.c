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

struct hgd_playlist_item	*next_track; /* not need pass as cb arg */

char				*hgd_dir = NULL;
char				*db_path = NULL;
char				*filestore_path;
sqlite3				*db = NULL;

uint8_t				exit_ok = 0;

/*
 * clean up, exit. if exit_ok = 0, an error (signal/error)
 */
void
hgd_exit_nicely()
{
	if (db)
		sqlite3_close(db);
	if (hgd_dir)
		free(hgd_dir);
	if (db_path)
		free (db_path);
	if (filestore_path)
		free(filestore_path);

	if (exit_ok)
		exit (EXIT_SUCCESS);
	else
		exit (EXIT_FAILURE);
}

void
hgd_play_track(struct hgd_playlist_item *t)
{
	int			status = 0, sql_res, pid;
	char			*q, *sql_err;
	char			*pid_path;
	FILE			*pid_file;

	DPRINTF("%s: playing '%s' for '%s'\n", __func__, t->filename, t->user);

	/* mark it as playing in the database */
	xasprintf(&q, "UPDATE playlist SET playing=1 WHERE id=%d", t->id);
	sql_res = sqlite3_exec(db, q, NULL, NULL, &sql_err);
	free(q);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: set track playing in sql: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_free(sql_err);
		hgd_exit_nicely();
	}


	pid = fork();
	if (!pid) {
		/* child - your the d00d who will play this track */
		execlp("mplayer", "mplayer", "-quiet",
		    t->filename, (char *) NULL);

		/* if we get here, the shit hit the fan with execlp */
		warn("execlp() failed");
		hgd_exit_nicely();
	} else {
		/* we will write away child pid */
		xasprintf(&pid_path, "%s/%s", hgd_dir, HGD_MPLAYER_PID_NAME);

		pid_file = fopen(pid_path, "w");
		if (pid_file == NULL) {
			warn("%s: can't open '%s'", __func__, pid_path);
			free(pid_path);
			hgd_exit_nicely();
		}


		fprintf(pid_file, "%d", pid);
		fclose(pid_file);
		wait(&status);
		if (unlink(pid_path) < 0) {
			warn("%s: can't unlink '%s'", __func__, pid_path);
			free(pid_path);
			hgd_exit_nicely();
		}
		free(pid_path);
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
	xasprintf(&t->filename, "%s/%s", filestore_path, data[1]);
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
			hgd_exit_nicely();
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
	/* i command you to stfu GCC */
	argc = argc;
	argv = argv;

	hgd_dir = strdup(HGD_DFL_DIR);
	xasprintf(&db_path, "%s/%s", hgd_dir, HGD_DB_NAME);
	xasprintf(&filestore_path, "%s/%s", hgd_dir, HGD_FILESTORE_NAME);

	db = hgd_open_db(db_path);
	if (db == NULL)
		hgd_exit_nicely();

	/* start */
	hgd_play_loop();


	exit_ok = 1;
	hgd_exit_nicely();
	exit (EXIT_SUCCESS); /* NOREACH */
}
