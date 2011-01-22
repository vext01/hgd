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
#include <stdarg.h>
#include <string.h>
#include <err.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sqlite3.h>

#include "hgd.h"

sqlite3				*db = NULL;
char				*db_path = NULL;

/* Open, create and initialise database */
sqlite3 *
hgd_open_db(char *db_path)
{
	int			sql_res;
	char			*sql_err;
	sqlite3			*db;

	/* open the database */
	DPRINTF(HGD_D_DEBUG, "opening database");
	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't open db: %s", sqlite3_errmsg(db));
		return NULL;
	}

	DPRINTF(HGD_D_DEBUG, "Setting database timeout");
	sql_res = sqlite3_busy_timeout(db, 2000);


	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't set busy timout on db: %s",
		    sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	DPRINTF(HGD_D_DEBUG, "Making playlist table (if needed)");
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE IF NOT EXISTS playlist ("
	    "id INTEGER PRIMARY KEY,"
	    "filename VARCHAR(" HGD_DBS_FILENAME_LEN " ),"
	    "user VARCHAR(" HGD_DBS_USERNAME_LEN "),"
	    "playing INTEGER,"
	    "finished INTEGER)",
	    NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s",
		    sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	DPRINTF(HGD_D_DEBUG, "making votes table (if needed)");
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE IF NOT EXISTS votes ("
	    "user VARCHAR(" HGD_DBS_USERNAME_LEN ") PRIMARY KEY)",
	    NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s",
		    sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	return db;
}

int
hgd_get_playing_item_cb(void *arg, int argc, char **data, char **names)
{
	struct hgd_playlist_item	*t;

	DPRINTF(HGD_D_DEBUG, "A track is playing");

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
		DPRINTF(HGD_D_ERROR, "Can't get playing track: %s",
		    sqlite3_errmsg(db));
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
		DPRINTF(HGD_D_ERROR, "Can't get votes: %s",
		    sqlite3_errmsg(db));
		sqlite3_free(sql_err);
		free(sql);
		return (-1);
	}
	free(sql);

	DPRINTF(HGD_D_DEBUG, "%d votes so far", num);
	return num;
}


