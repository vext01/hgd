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

char				*hgd_dir = NULL;
char				*db_path = NULL;
char				*filestore_path;
sqlite3				*db = NULL;

//uint8_t				exit_ok = 0;

/*
 * clean up, exit. if exit_ok = 0, an error (signal/error)
 */
void
hgd_exit_nicely()
{
	if (!exit_ok)
		fprintf(stderr,
		    "\n%s: hgd-playd was interrupted or crashed\n", __func__);

	if (db)
		sqlite3_close(db);
	if (hgd_dir)
		free(hgd_dir);
	if (db_path)
		free (db_path);
	if (filestore_path)
		free(filestore_path);

	exit (!exit_ok);
}

void
hgd_play_track(struct hgd_playlist_item *t)
{
	int			status = 0, sql_res, pid;
	char			*query, *sql_err;
	char			*query2, *sql_err2;
	char			*pid_path;
	FILE			*pid_file;

	DPRINTF(HGD_DEBUG_DEBUG, "%s: playing '%s' for '%s'\n", __func__, t->filename, t->user);

	/* mark it as playing in the database */
	xasprintf(&query, "UPDATE playlist SET playing=1 WHERE id=%d", t->id);
	sql_res = sqlite3_exec(db, query, NULL, NULL, &sql_err);
	free(query);

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

	DPRINTF(HGD_DEBUG_DEBUG, "%s: finished playing (exit %d)\n", __func__, status);

	/* mark it as finished in the database */
	xasprintf(&query2,
	    "UPDATE playlist SET playing=0, finished=1 WHERE id=%d", t->id);
	sql_res = sqlite3_exec(db, query2, NULL, NULL, &sql_err2);
	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't initialise db: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_free(sql_err2);
	}

	free(query2);
}

int
hgd_get_next_track_cb(void *item, int argc, char **data, char **names)
{
	struct hgd_playlist_item	*item_t;

	/* silence compiler */
	argc = argc;
	names = names;

	DPRINTF(HGD_DEBUG_DEBUG, "%s: track found\n", __func__);

	item_t = (struct hgd_playlist_item *) item;

	/* populate a struct that we pick up later */
	item_t->id = atoi(data[0]);
	xasprintf(&(item_t->filename), "%s/%s", filestore_path, data[1]);
	item_t->user = strdup(data[2]);
	item_t->playing = 0;
	item_t->finished = 0;

	return SQLITE_OK;
}

void
hgd_clear_votes()
{
	char			*query = "DELETE FROM votes;", *sql_err;
	int			sql_res;

	/* mark it as playing in the database */
	sql_res = sqlite3_exec(db, query, NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't clear vote list\n", __func__);
		sqlite3_free(sql_err);
		hgd_exit_nicely();
	}
}

void
hgd_play_loop()
{
	int				sql_res;
	char				*sql_err;
	struct hgd_playlist_item	*track;

	/* forever play songs */
	DPRINTF(HGD_DEBUG_DEBUG, "%s: starting play loop\n", __func__);
	while (!dying) {

		track = hgd_new_playlist_item();

		/* get the next track (if there is one) */
		sql_res = sqlite3_exec(db,
		   "SELECT id, filename, user "
		   "FROM playlist WHERE finished=0 LIMIT 1",
		   hgd_get_next_track_cb, track, &sql_err);

		if (sql_res != SQLITE_OK) {
			fprintf(stderr, "%s: can't get next track: %s\n",
			    __func__, sqlite3_errmsg(db));
			sqlite3_free(sql_err);
			hgd_exit_nicely();
		}

		if (track->filename != NULL) {
			DPRINTF(HGD_DEBUG_DEBUG, "%s: next track is: '%s'\n",
			    __func__, track->filename);
			hgd_clear_votes();
			hgd_play_track(track);
		} else {
			DPRINTF(HGD_DEBUG_DEBUG, "%s: no tracks to play\n", __func__);
			sleep(1);
		}
		hgd_free_playlist_item(track);
	}

	if (dying)
		hgd_exit_nicely();
}

void
hgd_usage()
{
	printf("usage: hgd-netd <options>\n");
	printf("  -d		set hgd state directory\n");
	printf("  -h		show this message and exit\n");
	printf("  -v		show version and exit\n");
	printf("  -x		set debug level (0-3)\n");
}

int
main(int argc, char **argv)
{
	int			sql_res;
	char			*sql_err, ch;

	hgd_register_sig_handlers();
	hgd_dir = strdup(HGD_DFL_DIR);

	DPRINTF(HGD_DEBUG_DEBUG, "%s: parsing options\n", __func__);
	while ((ch = getopt(argc, argv, "d:hvx:")) != -1) {
		switch (ch) {
		case 'd':
			free(hgd_dir);
			hgd_dir = strdup(optarg);
			DPRINTF(HGD_DEBUG_DEBUG,
			    "set hgd dir to '%s'\n", hgd_dir);
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

	xasprintf(&db_path, "%s/%s", hgd_dir, HGD_DB_NAME);
	xasprintf(&filestore_path, "%s/%s", hgd_dir, HGD_FILESTORE_NAME);

	db = hgd_open_db(db_path);
	if (db == NULL)
		hgd_exit_nicely();

	DPRINTF(HGD_DEBUG_DEBUG, "%s: clearing 'playing' flags\n", __func__);
	sql_res = sqlite3_exec(db, "UPDATE playlist SET playing=0;",
	    NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't initialise db: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	/* start */
	hgd_play_loop();

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
