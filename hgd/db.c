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
	DPRINTF("%s: opening database\n", __func__);
	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		fprintf(stderr, "%s: can't open db: %s\n",
		    __func__, sqlite3_errmsg(db));
		return NULL;
	}

	DPRINTF("%s: setting database timeout\n", __func__);
	sql_res = sqlite3_busy_timeout(db, 2000);
	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't set busy timout on db: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	DPRINTF("%s: making playlist table (if needed)\n", __func__);
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE IF NOT EXISTS playlist ("
	    "id INTEGER PRIMARY KEY,"
	    "filename VARCHAR(" HGD_DBS_FILENAME_LEN " ),"
	    "user VARCHAR(" HGD_DBS_USERNAME_LEN "),"
	    "playing INTEGER,"
	    "finished INTEGER)",
	    NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't initialise db: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	DPRINTF("%s: making votes table (if needed)\n", __func__);
	sql_res = sqlite3_exec(db,
	    "CREATE TABLE IF NOT EXISTS votes ("
	    "user VARCHAR(" HGD_DBS_USERNAME_LEN ") PRIMARY KEY)",
	    NULL, NULL, &sql_err);

	if (sql_res != SQLITE_OK) {
		fprintf(stderr, "%s: can't initialise db: %s\n",
		    __func__, sqlite3_errmsg(db));
		sqlite3_close(db);
		sqlite3_free(sql_err);
		return NULL;
	}

	return db;
}

