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

#ifndef __DB_H
#define __DB_H

/* database schema */
#define HGD_DBS_FILENAME_LEN	"50"
#define HGD_DBS_USERNAME_LEN	"15"

#include <sqlite3.h>

extern sqlite3			*db;
extern char			*db_path;

sqlite3				*hgd_open_db(char *);
int				 hgd_get_playing_item_cb(void *arg,
				     int argc, char **data, char **names);
int				 hgd_get_playing_item(
				     struct hgd_playlist_item *playing);
int				 hgd_get_num_votes_cb(void *arg,
				     int argc, char **data, char **names);
int				 hgd_get_num_votes();
int				 hgd_insert_track(char *filename, char *user);
int				 hgd_insert_vote(char *user);
int				 hgd_get_playlist(struct hgd_playlist *list);
int				 hgd_get_next_track(
				     struct hgd_playlist_item *track);
#endif
