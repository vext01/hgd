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
	if (sqlite3_open(db_path, &db)) {
		fprintf(stderr, "%s: can't open db: %s\n",
		    __func__, sqlite3_errmsg(db));
		return NULL;
	}

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
		sqlite3_close(db);
		return NULL;
	}
	DPRINTF("%s: database open\n", __func__);
	return db;
}

