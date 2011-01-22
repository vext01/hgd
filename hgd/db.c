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

/* Open, create and initialise database */
sqlite3 *
hgd_open_db(char *db_path)
{
	int			sql_res;
	char			*sql_err;
	sqlite3			*db;

	/* open the database */
	DPRINTF(HGD_DEBUG_DEBUG, "%s: opening database\n", __func__);
	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		DPRINTF(HGD_DEBUG_ERROR, "Can't open db: %s\n",
		    sqlite3_errmsg(db));
		return NULL;
	}

	DPRINTF(HGD_DEBUG_DEBUG, "%s: setting database timeout\n", __func__);
	sql_res = sqlite3_busy_timeout(db, 2000);


	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_DEBUG_ERROR, "Can't set busy timout on db: %s\n",
		    sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	DPRINTF(HGD_DEBUG_DEBUG, "Making playlist table (if needed)\n");
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE IF NOT EXISTS playlist ("
	    "id INTEGER PRIMARY KEY,"
	    "filename VARCHAR(" HGD_DBS_FILENAME_LEN " ),"
	    "user VARCHAR(" HGD_DBS_USERNAME_LEN "),"
	    "playing INTEGER,"
	    "finished INTEGER)",
	    NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_DEBUG_ERROR, "Can't initialise db: %s\n",
		    sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	DPRINTF(HGD_DEBUG_DEBUG, "making votes table (if needed)\n");
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE IF NOT EXISTS votes ("
	    "user VARCHAR(" HGD_DBS_USERNAME_LEN ") PRIMARY KEY)",
	    NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		DPRINTF(HGD_DEBUG_ERROR, "Can't initialise db: %s\n",
		    sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	return db;
}

