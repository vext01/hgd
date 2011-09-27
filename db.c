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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>

#include <sqlite3.h>

#include "hgd.h"
#include "db.h"

sqlite3				*db = NULL;
char				*db_path = NULL;


int
hgd_get_db_vers_cb(void *arg, int argc, char **data, char **names)
{
	int		*vers;

	(void) argc;
	(void) names;

	vers = (int *) arg;
	*vers = atoi(data[0]);

	return (SQLITE_OK);
}

/* Optionally create, and open database */
sqlite3 *
hgd_open_db(char *db_path, uint8_t create)
{
	int			 sql_res;
	sqlite3			*db;
	int			 db_vers = -1;
	uint8_t			 db_schema_err = 0;
	struct stat		 st;

	DPRINTF(HGD_D_DEBUG, "opening database");

	if (!create) {
		if (stat(db_path, &st) < 0) {
			DPRINTF(HGD_D_ERROR, "Can't stat %s: %s", db_path, SERROR);
			DPRINTF(HGD_D_ERROR, "Did you run 'hgd-admin db-init'?");
			return (NULL);
		}
	}

	/* open the database */
	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't open %s: %s", db_path, DERROR);
		return (NULL);
	}

	/* make database secure */
	if (chmod(db_path, S_IRUSR | S_IWUSR) != 0) {
		DPRINTF(HGD_D_WARN, "Could not make %s file secure: %s",
		    db_path, SERROR);
	}

	DPRINTF(HGD_D_DEBUG, "Setting database timeout");
	sql_res = sqlite3_busy_timeout(db, 2000);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't set busy timout: %s", DERROR);
		sqlite3_close(db);
		return (NULL);
	}

	/* if we are not creating a db, it should be the right version */
	if (!create) {
		sql_res = sqlite3_exec(db,
		    "SELECT db_schema_version FROM system WHERE id=0",
		    hgd_get_db_vers_cb, &db_vers, NULL);

		if (sql_res != SQLITE_OK) {
			DPRINTF(HGD_D_ERROR,
			    "Can't get db schema version, "
			    "is your database too old?: %s", DERROR);
			db_schema_err = 1;
		} else if (db_vers != atoi(HGD_DB_SCHEMA_VERS)) {
			DPRINTF(HGD_D_ERROR, "Database schema version "
			    "mismatch: needed '%s', got '%d'",
			    HGD_DB_SCHEMA_VERS, db_vers);
			db_schema_err = 1;
		} else
			DPRINTF(HGD_D_INFO, "Database schema version "
			    "is good: needed '%s', got '%d'",
			    HGD_DB_SCHEMA_VERS, db_vers);

		if (db_schema_err) {
			DPRINTF(HGD_D_ERROR, "If you are happy to lose your "
				"database,you can make a new one with: "
				"'hgd-admin db-init'");
			sqlite3_close(db);
			return (NULL);
		}
	}
	return (db);
}

/*
 * remove old db and create new one
 */
int
hgd_make_new_db(char *db_path)
{
	int			sql_res;
	sqlite3			*db;

	DPRINTF(HGD_D_INFO, "Creating new database: %s", db_path);

	if ((unlink(db_path) < 0) && (errno != ENOENT)) {
		DPRINTF(HGD_D_ERROR, "Could not unlink existing db: %s", SERROR);
		return (HGD_FAIL);
	}

	db = hgd_open_db(db_path, 1); /* and create */
	if (!db)
		return (HGD_FAIL);

	/* no-one else should do this at the same time */
	sql_res = sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s", DERROR);
		sqlite3_close(db);
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "Making system table");
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE system ("
	    "id INTEGER PRIMARY KEY,"
	    "db_schema_version INTEGER)",
	    NULL, NULL, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s", DERROR);
		sqlite3_close(db);
		return (HGD_FAIL);
	}

	/* the system table should only have one row with id 0 */
	sql_res = sqlite3_exec(db,
	    "INSERT into system VALUES(0, '" HGD_DB_SCHEMA_VERS "');",
	    NULL, NULL, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s", DERROR);
		sqlite3_close(db);
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "Making playlist table");
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE playlist ("
	    "id INTEGER PRIMARY KEY,"
	    "filename TEXT,"
	    "user TEXT,"
	    "playing INTEGER,"
	    "finished INTEGER,"
	    "tag_artist TEXT,"
	    "tag_title TEXT,"
	    "tag_album TEXT,"
	    "tag_genre TEXT,"
	    "tag_year INTEGER,"
	    "tag_channels INTEGER,"
	    "tag_samplerate INTEGER,"
	    "tag_duration INTEGER,"
	    "tag_bitrate INTEGER)",
	    NULL, NULL, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s", DERROR);
		sqlite3_close(db);
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "making votes table");
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE votes ("
	    "user TEXT PRIMARY KEY)",
	    NULL, NULL, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s",
		    DERROR);
		sqlite3_close(db);
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "making user table");
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE users ("
	    "username TEXT PRIMARY KEY, "
	    "hash TEXT, "	/* sha1 */
	    "salt TEXT, "
	    "perms INTEGER"
	    ");",
	    NULL, NULL, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s",
		    DERROR);
		sqlite3_close(db);
		return (HGD_FAIL);
	}

	sql_res = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't initialise db: %s", DERROR);
		sqlite3_close(db);
		return (HGD_FAIL);
	}

	sqlite3_close(db);

	return (HGD_OK);
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
	t->filename = xstrdup(data[1]);
	t->tags.artist = xstrdup(data[2]);
	t->tags.title = xstrdup(data[3]);
	t->user = xstrdup(data[4]);
	t->tags.album = xstrdup(data[5]);
	t->tags.genre = xstrdup(data[6]);
	t->tags.duration = atoi(data[7]);
	t->tags.bitrate = atoi(data[8]);
	t->tags.samplerate = atoi(data[9]);
	t->tags.channels = atoi(data[10]);
	t->tags.year = atoi(data[11]);

	return (SQLITE_OK);
}

int
hgd_get_playing_item(struct hgd_playlist_item *playing)
{
	int				 sql_res;

	sql_res = sqlite3_exec(db,
	    "SELECT id, filename, tag_artist, tag_title, user, tag_album, "
	    "tag_genre, tag_duration, tag_bitrate, tag_samplerate, "
	    "tag_channels, tag_year FROM playlist WHERE playing=1 LIMIT 1",
	    hgd_get_playing_item_cb, playing, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't get playing track: %s", DERROR);
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

int
hgd_get_num_votes_cb(void *arg, int argc, char **data, char **names)
{
	int			*num = (int *) arg;

	/* quiet */
	argc = argc;
	names = names;

	*num = atoi(data[0]);
	return (SQLITE_OK);
}

/* XXX make it return HGD_OK or HGD_FAIL */
int
hgd_get_num_votes()
{
	int			sql_res, num = -1;
	char			*sql;

	xasprintf(&sql, "SELECT COUNT (*) FROM votes;");
	sql_res = sqlite3_exec(db, sql, hgd_get_num_votes_cb, &num, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't get votes: %s", DERROR);
		free(sql);
		return (HGD_FAIL);
	}
	free(sql);

	DPRINTF(HGD_D_DEBUG, "%d votes so far", num);
	return (num);
}

int
hgd_user_has_voted(char *user, int *v)
{
	int			 ret = HGD_FAIL;
	int			 sql_res;
	sqlite3_stmt		*stmt;
	char			*sql = "SELECT user FROM votes WHERE user=?";

	/* we start assuming they have not voted */
	*v = 0;

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s",
		    DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_TRANSIENT);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res == SQLITE_ROW) { /* if a row, they voted */
		*v = 1;
	} else if ((sql_res != SQLITE_ROW) && (sql_res != SQLITE_DONE)) {
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	ret = HGD_OK; /* everything went ok */
clean:
	sqlite3_finalize(stmt);
	return (ret);
}

int
hgd_insert_track(char *filename, struct hgd_media_tag *t, char *user)
{
	int			 ret = HGD_FAIL;
	int			 sql_res;
	sqlite3_stmt		*stmt;
	char			*sql = "INSERT INTO playlist "
	    "(filename, tag_artist, tag_title, tag_album, tag_duration, "
	    "tag_samplerate, tag_bitrate, tag_channels, tag_genre, tag_year, "
	    "user, playing, finished) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
	    "?, ?, 0, 0)";

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s",
		    DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_TRANSIENT);
	sql_res &= sqlite3_bind_text(stmt, 2, t->artist, -1, SQLITE_TRANSIENT);
	sql_res &= sqlite3_bind_text(stmt, 3, t->title, -1, SQLITE_TRANSIENT);
	sql_res &= sqlite3_bind_text(stmt, 4, t->album, -1, SQLITE_TRANSIENT);
	sql_res &= sqlite3_bind_int(stmt, 5, t->duration);
	sql_res &= sqlite3_bind_int(stmt, 6, t->samplerate);
	sql_res &= sqlite3_bind_int(stmt, 7, t->bitrate);
	sql_res &= sqlite3_bind_int(stmt, 8, t->channels);
	sql_res &= sqlite3_bind_text(stmt, 9, t->genre, -1, SQLITE_TRANSIENT);
	sql_res &= sqlite3_bind_int(stmt, 10, t->year);
	sql_res &= sqlite3_bind_text(stmt, 11, user, -1, SQLITE_TRANSIENT);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res != SQLITE_DONE) {
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	ret = HGD_OK; /* everything went ok */
clean:
	sqlite3_finalize(stmt);
	return (ret);
}

int
hgd_insert_vote(char *user)
{
	int			 ret = HGD_FAIL;
	int			 sql_res;
	sqlite3_stmt		*stmt;
	char			*sql = "INSERT INTO votes (user) VALUES (?)";

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s",
		    DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_TRANSIENT);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res == SQLITE_CONSTRAINT) {
		ret = 1; /* indicates duplicat vote */
		goto clean;
	} else if (sql_res != SQLITE_DONE) {
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	ret = HGD_OK; /* everything went ok */
clean:
	sqlite3_finalize(stmt);
	return (ret);
}

int
hgd_get_playlist_cb(void *arg, int argc, char **data, char **names)
{
	struct hgd_playlist		*list;
	struct hgd_playlist_item	*item;

	/* shaddap gcc */
	(void) argc;
	(void) names;

	list = (struct hgd_playlist *) arg;

	item = xmalloc(sizeof(struct hgd_playlist_item));

	item->id = atoi(data[0]);
	item->filename = xstrdup(data[1]);
	item->tags.artist = xstrdup(data[2]);
	item->tags.title = xstrdup(data[3]);
	item->user = xstrdup(data[4]);
	item->tags.album = xstrdup(data[5]);
	item->tags.genre = xstrdup(data[6]);
	item->tags.duration = atoi(data[7]);
	item->tags.bitrate = atoi(data[8]);
	item->tags.samplerate = atoi(data[9]);
	item->tags.channels = atoi(data[10]);
	item->tags.year = atoi(data[11]);
	item->playing = 0;	/* don't need */
	item->finished = 0;	/* don't need */

	list->items = xrealloc(list->items,
	    sizeof(struct hgd_playlist_item *) * (list->n_items + 1));
	list->items[list->n_items] = item;

	list->n_items++;

	return (SQLITE_OK);
}

/*
 * report back items in the playlist
 */
int
hgd_get_playlist(struct hgd_playlist *list)
{
	int			sql_res;

	list->n_items = 0;
	list->items = NULL;

	DPRINTF(HGD_D_DEBUG, "Playlist request");

	sql_res = sqlite3_exec(db,
	    "SELECT id, filename, tag_artist, tag_title, user, tag_album, "
	    "tag_genre, tag_duration, tag_bitrate, tag_samplerate, "
	    "tag_channels, tag_year FROM playlist",
	    hgd_get_playlist_cb, list, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't get playing track: %s", DERROR);
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

int
hgd_get_next_track_cb(void *item, int argc, char **data, char **names)
{
	struct hgd_playlist_item	*item_t;

	/* silence compiler */
	argc = argc;
	names = names;

	DPRINTF(HGD_D_DEBUG, "track found");

	item_t = (struct hgd_playlist_item *) item;

	/* populate a struct that we pick up later */
	item_t->id = atoi(data[0]);
	xasprintf(&(item_t->filename), "%s/%s", filestore_path, data[1]);
	item_t->user = xstrdup(data[2]);
	item_t->playing = 0;
	item_t->finished = 0;

	return (SQLITE_OK);
}

/* get the next track (if there is one) */
int
hgd_get_next_track(struct hgd_playlist_item *track)
{
	int			 sql_res;

	sql_res = sqlite3_exec(db,
	    "SELECT id, filename, user "
	    "FROM playlist WHERE finished=0 LIMIT 1",
	    hgd_get_next_track_cb, track, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't get next track: %s", DERROR);
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

/* mark it as playing in the database */
int
hgd_mark_playing(int id)
{
	int			 sql_res, ret = HGD_FAIL;
	sqlite3_stmt		*stmt;
	char			*sql = "UPDATE playlist SET playing=1 "
				    "WHERE id=?";

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s", DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_int(stmt, 1, id);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res != SQLITE_DONE) {
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	ret = HGD_OK;
clean:
	sqlite3_finalize(stmt);
	return (ret);
}

int
hgd_mark_finished(int id, uint8_t purge)
{
	int			 sql_res;
	char			*q_purge = "DELETE FROM playlist WHERE "
				    "id=? OR finished=1";
	char			*q_mark = "UPDATE playlist SET playing=0,"
				    " finished=1 WHERE id=?";
	char			*sql = NULL;
	sqlite3_stmt		*stmt;
	int			 ret = HGD_FAIL;

	/* mark it as finished or delete in the database */
	if (purge) {
		sql = q_purge;
		DPRINTF(HGD_D_DEBUG, "Purging/cleaning up db");
	} else {
		sql = q_mark;
		DPRINTF(HGD_D_DEBUG, "Marking finished up db");
	}

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s", DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_int(stmt, 1, id);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res != SQLITE_DONE) {
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	ret = HGD_OK;
clean:
	sqlite3_finalize(stmt);
	return (ret);
}

int
hgd_clear_votes()
{
	char			*query = "DELETE FROM votes;";
	int			sql_res;

	/* mark it as playing in the database */
	sql_res = sqlite3_exec(db, query, NULL, NULL, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't clear vote list");
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

int
hgd_init_playstate()
{
	int			 sql_res;

	DPRINTF(HGD_D_DEBUG, "Clearing 'playing' flags");
	sql_res = sqlite3_exec(db, "UPDATE playlist SET playing=0;",
	    NULL, NULL, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't clear db flags: %s", DERROR);
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

int
hgd_clear_playlist()
{
	char			*query = "DELETE FROM playlist;";
	int			sql_res;

	/* mark it as playing in the database */
	sql_res = sqlite3_exec(db, query, NULL, NULL, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't clear playlist");
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

/*
 * add a user to the database
 */
int
hgd_add_user(char *user, char *salt, char *hash)
{
	int			 sql_res, ret = HGD_FAIL;
	sqlite3_stmt		*stmt;
	char			*sql = "INSERT INTO users "
				   "(username, salt, hash, perms) "
				   " VALUES (?, ?, ?, 0)";

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s", DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_TRANSIENT);
	sql_res |= sqlite3_bind_text(stmt, 2, salt, -1, SQLITE_TRANSIENT);
	sql_res |= sqlite3_bind_text(stmt, 3, hash, -1, SQLITE_TRANSIENT);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res == SQLITE_CONSTRAINT) {
		DPRINTF(HGD_D_ERROR, "User '%s' already exists", user);
		goto clean;
	} else if (sql_res != SQLITE_DONE) {
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	ret = HGD_OK;
clean:
	sqlite3_finalize(stmt);
	return (ret);
}

int
hgd_update_user(struct hgd_user *user)
{
	int			sql_res;
	sqlite3_stmt		*stmt;
	char			*sql = "UPDATE users SET perms=? WHERE username=?";
	int			ret = HGD_OK;

	DPRINTF(HGD_D_DEBUG, "Updating user info for %s", user->name);

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s", DERROR);
		ret = HGD_FAIL;
		goto clean;
	}

	sql_res = sqlite3_bind_int(stmt, 1, user->perms);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		ret = HGD_FAIL;
		goto clean;
	}

	sql_res = sqlite3_bind_text(stmt, 2, user->name, -1, SQLITE_TRANSIENT);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		ret = HGD_FAIL;
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res != SQLITE_DONE) {
		DPRINTF(HGD_D_ERROR, "Failed to update user: %s", DERROR);
		ret = HGD_FAIL;
		goto clean;
	}

clean:
	sqlite3_finalize(stmt);
	return (ret);
}

struct hgd_user *
hgd_authenticate_user(char *user, char *pass)
{
	int			 sql_res;
	sqlite3_stmt		*stmt;
	char			*sql = "SELECT username, salt, hash, perms "
				    "FROM users WHERE username=?";
	struct hgd_user		*user_info = NULL;
	char			*stored_hash, *salt;
	char			*hash = NULL;

	DPRINTF(HGD_D_DEBUG, "Get user info for '%s'", user);

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s", DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_TRANSIENT);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res == SQLITE_DONE) {
		DPRINTF(HGD_D_WARN, "User '%s', does not exist", user);
		goto clean;
	} else if (sql_res != SQLITE_ROW) { /* we expect exactly one row */
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	/* these will be thrown away soon */
	salt = (char *) sqlite3_column_text(stmt, 1);
	stored_hash = (char *) sqlite3_column_text(stmt, 2);

	hash = hgd_sha1(pass, salt);
	if (strcmp(hash, stored_hash) != 0) {
		DPRINTF(HGD_D_WARN, "User '%s': authentication failed", user);
		goto clean;
	}

	user_info = xmalloc(sizeof(struct hgd_user));
	user_info->name = xstrdup((const char *) sqlite3_column_text(stmt, 0));
	user_info->perms = sqlite3_column_int(stmt, 3);

clean:
	if (hash)
		free(hash);

	sqlite3_finalize(stmt);
	return (user_info);
}

/*
 * remove user from db forever
 */
int
hgd_delete_user(char *user)
{
	int			 sql_res, ret = HGD_FAIL;
	sqlite3_stmt		*stmt;
	char			*sql = "DELETE FROM users WHERE username=?";

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s", DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_TRANSIENT);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res != SQLITE_DONE) {
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	ret = HGD_OK;
clean:
	sqlite3_finalize(stmt);
	return (ret);
}

int
hgd_get_all_users_cb(void *arg, int argc, char **data, char **names)
{
	struct hgd_user		*user;
	struct hgd_user_list	*list = (struct hgd_user_list *) arg;

	/* ssh */
	names = names;

	if (argc != 2)
		DPRINTF(HGD_D_WARN, "incorrect param count");

	user = xmalloc(sizeof(struct hgd_user));
	user->name = strdup(data[0]);
	user->perms = atoi(data[1]);

	list->users = xrealloc(list->users,
	    ++(list->n_users) * sizeof(struct hgd_user));
	list->users[list->n_users - 1] = user;

	return (SQLITE_OK);
}

int
hgd_num_tracks_user(char *username)
{
	int			 sql_res, ret = HGD_FAIL;
	sqlite3_stmt		*stmt;
	char			*sql = "SELECT COUNT(*) FROM playlist WHERE user=? AND finished=0";

	sql_res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't prepare sql: %s", DERROR);
		goto clean;
	}

	/* bind params */
	sql_res = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_WARN, "Can't bind sql: %s", DERROR);
		goto clean;
	}

	sql_res = sqlite3_step(stmt);
	if (sql_res != SQLITE_ROW) {
		DPRINTF(HGD_D_WARN, "Can't step sql: %s", DERROR);
		goto clean;
	}

	ret = sqlite3_column_int(stmt, 0);
clean:
	sqlite3_finalize(stmt);
	return (ret);
}

/* get all users from the db, caler must free */
struct hgd_user_list *
hgd_get_all_users()
{
	int			 sql_res;
	struct hgd_user_list	*list = xcalloc(1, sizeof(struct hgd_user_list));

	sql_res = sqlite3_exec(db,
	    "SELECT username, perms FROM users",
	    hgd_get_all_users_cb, list, NULL);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_D_ERROR, "Can't get users: %s", DERROR);
		return (NULL);
	}

	return (list);
}
