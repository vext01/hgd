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

#include <sys/types.h>

#include <stdio.h>
#include <curses.h>
#include <dirent.h>
#include <stdlib.h>
#include <menu.h>
#include <err.h>

#include "hgd.h"
#include "config.h"
#include "cfg.h"
#include "client.h"
#include "nchgdc.h"

#define	HGD_CPAIR_BARS				1
#define HGD_CPAIR_SELECTED			2
#define HGD_CPAIR_DIALOG			3
#define	HGD_CPAIR_PBAR_BG			4

#define HGD_LOG_BACKBUFFER			4096

/* status bar positioning */
#define HGD_POS_STATUS_X			0
#define HGD_POS_STATUS_Y			LINES - 1
#define HGD_POS_STATUS_W			COLS
#define HGD_POS_STATUS_H			1

/* title bar positioning */
#define HGD_POS_TITLE_X				0
#define HGD_POS_TITLE_Y				0
#define HGD_POS_TITLE_W				COLS
#define HGD_POS_TITLE_H				1

/* content windows positioning */
#define HGD_POS_CONT_X				0
#define HGD_POS_CONT_Y				1
#define HGD_POS_CONT_W				COLS
#define HGD_POS_CONT_H				LINES - 2

const char					*hgd_component = "nchgdc";

const char *window_names[] = {
	"Playlist",
	"File Browser",
	"Debug Console"
};

struct hgd_ui_log			logs;

void
hgd_exit_nicely()
{
	DPRINTF(HGD_D_INFO, "EXIT!");

	if (endwin() == ERR)
		DPRINTF(HGD_D_ERROR, "Failed to exit curses");

	if (!exit_ok) {
		DPRINTF(HGD_D_ERROR, "nchgdc crashed or was interrupted");
		/* XXX why not printed??? */
		printf("ERROR: nchgdc crashed or was interrupted!"
		    " Please examine the log file\n");
	}

	_exit(!exit_ok);
}

/* XXX this sucks, use memset, strncpy */
int
hgd_prepare_item_string(char **ret_p, char *str)
{
	int			sz = 0, written = 0, i;
	char			*p = str, *c, *ret;

	/* We will be padding this up to UI width */
	*ret_p = xmalloc(COLS + 1);
	ret = *ret_p;

	memset(ret, ' ', COLS);
	ret[COLS] = 0;

	/* count how large the string should be */
	p = str;
	c = ret;
	while (written <= COLS) {

		if (*p == '\0')
			break; /* done */

		if (*p == '\t')
			sz = 4;
		else
			sz = 1;

		if (written + sz > COLS)
			break; /* that is all we would be able to cram in */

		if (sz == 1) { /* thus a non-tab */
			if ((*p == '\n') || (*p == '\r'))
				*p = '^';
			*c++ = *p;
			written++;
		} else { /* thus a tab, which expands to 4 spaces */
			for (i = 0; i < 4; i++) {
				*c = ' ';
				c++;
				written++;
			}
		}
		p++;
	}

	return (HGD_OK);
}

void
hgd_update_statusbar(struct ui *u)
{
	char			*fmt;
	int			 i;

	/* do not use wclear(), causes flickery screen */
	wmove(u->status, 0, 0);	
	for (i = 0; i < COLS; i++)
		wprintw(u->status, " ");

	xasprintf(&fmt, "%%-%ds", COLS);

	wattron(u->status, COLOR_PAIR(HGD_CPAIR_BARS));
	wmove(u->status, 0, 0);	
	wprintw(u->status, fmt, u->status_str);

	free (fmt);
}

void
hgd_refresh_statusbar(struct ui *u)
{
	hgd_update_statusbar(u);
	wrefresh(u->status);
}

void
hgd_refresh_ui(struct ui *u)
{
	redrawwin(u->content_wins[u->active_content_win]);
	wnoutrefresh(u->content_wins[u->active_content_win]);

	hgd_update_titlebar(u);
	wnoutrefresh(u->title);

	hgd_update_statusbar(u);
	wnoutrefresh(u->status);

	doupdate();
}

int
init_log()
{
	char *logfile = NULL;

	xasprintf(&logfile, "%s/%s/nchgdc.log",
	    getenv("HOME"), HGD_USR_CFG_DIR);

	DPRINTF(HGD_D_INFO, "UI logging to '%s'", logfile);
	if ((logs.wr = fopen(logfile, "w")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not open write log: %s", SERROR);
		return (HGD_FAIL);
	}

	if ((logs.rd = fopen(logfile, "r")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not open read log: %s", SERROR);
		return (HGD_FAIL);
	}

	free(logfile);

	/* Redirect stderr here, so that DPRINTF can still work */
	close(fileno(stderr));
	if (dup(fileno(logs.wr)) < 0) {
		DPRINTF(HGD_D_ERROR, "dup() failed: %s", SERROR);
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

void
hgd_update_titlebar(struct ui *u)
{
	char			*fmt = NULL, *title_str = NULL;

	DPRINTF(HGD_D_INFO, "Update titlebar window");

	wattron(u->title, COLOR_PAIR(HGD_CPAIR_BARS));

	xasprintf(&fmt, "%%-%ds", COLS);

	/* browser win shows path next to title */
	if (u->active_content_win == HGD_WIN_FILES) {
		xasprintf(&title_str, "nchgdc-%s :: %s :: %s", HGD_VERSION,
		    window_names[u->active_content_win], u->cwd);
	} else {
		xasprintf(&title_str, "nchgdc-%s :: %s", HGD_VERSION,
		    window_names[u->active_content_win]);
	}

	mvwprintw(u->title, 0, 0, fmt, title_str);

	free(title_str);
	free(fmt);
}

int
hgd_update_playlist_win(struct ui *u)
{
	ITEM			**items = NULL;
	int			  i, ret = HGD_FAIL;
	char			 *item_str;
	struct hgd_playlist	 *playlist = NULL;
	char			 *track_str;

	DPRINTF(HGD_D_INFO, "Update playlist window");

	hgd_set_statusbar_text(u, "Connected >>> Fetching playlist");

	if (sock_fd == -1) {
		ret = HGD_OK;
		goto clean;
	}

	wclear(u->content_wins[HGD_WIN_PLAYLIST]);
	hgd_unpost_and_free_content_menu(u, HGD_WIN_PLAYLIST);

	/* and now populate the menu */
	if (hgd_cli_get_playlist(&playlist) != HGD_OK) {
		goto clean;
	}

	if (playlist->n_items == 0) {
		ret = HGD_OK;
		mvwprintw(u->content_wins[HGD_WIN_PLAYLIST], 0, 0, "Playlist Empty - Saddest of times!");
		goto clean;
	}

	items = xcalloc(playlist->n_items + 1, sizeof(ITEM *));
	for (i = 0; i < playlist->n_items; i++) {

		DPRINTF(HGD_D_DEBUG, "Adding item \"%s\"",
		    playlist->items[i]->tags.title);

		if ((strcmp(playlist->items[i]->tags.artist, "")) ||
		    (strcmp(playlist->items[i]->tags.title, ""))) {

			xasprintf(&track_str, "#%03d from %-8s: '%s' by '%s'",
			    playlist->items[i]->id,
			    playlist->items[i]->user,
			    playlist->items[i]->tags.title,
			    playlist->items[i]->tags.artist);
		} else  {
			xasprintf(&track_str, "#%03d from %-8s: '%s'",
			    playlist->items[i]->id,
			    playlist->items[i]->user,
			    playlist->items[i]->filename);
		}

		hgd_prepare_item_string(&item_str, track_str);
		free(track_str);

		items[i] = new_item(item_str, NULL);
		if (items[i] == NULL)
			DPRINTF(HGD_D_WARN, "Could not make new item: %s", SERROR);
	}

	u->content_menus[HGD_WIN_PLAYLIST] = new_menu(items);
	if (u->content_menus[HGD_WIN_PLAYLIST] == NULL) {
			DPRINTF(HGD_D_ERROR, "Could not make menu");
			goto clean;
	}

	set_menu_win(u->content_menus[HGD_WIN_PLAYLIST],
	    u->content_wins[HGD_WIN_PLAYLIST]);
	set_menu_mark(u->content_menus[HGD_WIN_PLAYLIST], "");
	set_menu_format(u->content_menus[HGD_WIN_PLAYLIST], LINES - 2, 1);
	set_menu_fore(u->content_menus[HGD_WIN_PLAYLIST],
	    COLOR_PAIR(HGD_CPAIR_SELECTED));

	if ((post_menu(u->content_menus[HGD_WIN_PLAYLIST])) != E_OK) {
		DPRINTF(HGD_D_ERROR, "Could not post menu");
		goto clean;
	}

	hgd_set_standard_statusbar_text(u);

	ret = HGD_OK;
clean:
	if (playlist)
		hgd_free_playlist(playlist);
#if 0
	if (items)
		free(items);
#endif
	if (playlist)
		free(playlist);

	return (ret);
}

int
hgd_unpost_and_free_content_menu(struct ui *u, int which)
{
	ITEM			**items;
	int			  n_items, i;

	if (u->content_menus[which] == NULL)
		return (HGD_OK);

	DPRINTF(HGD_D_INFO, "free menu: %s", window_names[which]);

	if ((n_items = item_count(u->content_menus[which])) == ERR) {
		DPRINTF(HGD_D_ERROR, "Couldn't get item count");
		return (HGD_FAIL);
	}

	if ((items = menu_items(u->content_menus[which])) == NULL) {
		DPRINTF(HGD_D_ERROR, "Got NULL items array");
		return (HGD_FAIL);
	}

	if (unpost_menu(u->content_menus[which]) != E_OK)
		DPRINTF(HGD_D_ERROR, "could not unpost menu %d", errno);

	/* must come before freeing items */
	if (free_menu(u->content_menus[which]) != E_OK)
		DPRINTF(HGD_D_ERROR, "could not free menu");

	for (i = 0; i < n_items; i++) {
		free((char *) item_name(items[i]));
		free((char *) item_description(items[i]));
		free(item_userptr(items[i]));
		if (free_item(items[i]) != OK)
			DPRINTF(HGD_D_ERROR, "can't free item");
	}

	free(items);
	u->content_menus[which] = NULL;

	return (HGD_OK);
}

/* filters for scandir() */
#if !defined(__linux__)
int
hgd_filter_dirs(struct dirent *d)
#else
int
hgd_filter_dirs(const struct dirent *d)
#endif
{
	if (strcmp(".", d->d_name) == 0)
		return (0);

	return (d->d_type == DT_DIR);
}

#if !defined(__linux__)
int
hgd_filter_files(struct dirent *d)
#else
int
hgd_filter_files(const struct dirent *d)
#endif
{
	return (d->d_type != DT_DIR);
}

int
hgd_update_files_win(struct ui *u)
{
	ITEM			**items = NULL;
	char			 *slash_append, *prep_item_str;
	struct dirent		**dirents_dirs = 0, **dirents_files = 0, *d, *d_copy;
	int			  n_dirs = 0, n_files = 0;
	int			  i, cur_item = 0, ret = HGD_FAIL;

	DPRINTF(HGD_D_INFO, "Update files window");

	wclear(u->content_wins[HGD_WIN_FILES]);
	hgd_unpost_and_free_content_menu(u, HGD_WIN_FILES);

	if ((n_dirs = scandir(
	    u->cwd, &dirents_dirs, hgd_filter_dirs, alphasort)) < 0) {
		 DPRINTF(HGD_D_WARN, "Failed to scan directory: '%s'", u->cwd);
		 goto clean;
	}

	if ((n_files = scandir(
	    u->cwd, &dirents_files, hgd_filter_files, alphasort)) < 0) {
		 DPRINTF(HGD_D_WARN, "Failed to scan directory: '%s'", u->cwd);
		 goto clean;
	}

	/* make our menu items */
	DPRINTF(HGD_D_INFO, "allocating %d menu items", n_files + n_dirs);
	items = xcalloc(n_files + n_dirs + 1, sizeof(ITEM *));

	/* add dirs */
	for (i = 0; i < n_dirs; i++) {
		d = dirents_dirs[i];

		xasprintf(&slash_append, "%s/", d->d_name);
		hgd_prepare_item_string(&prep_item_str, slash_append);
		free(slash_append);

		items[cur_item] = new_item(prep_item_str, NULL);

		if (items[cur_item] == NULL) {
			DPRINTF(HGD_D_WARN,
			    "Could not make new menu item: %s", SERROR);
			free(prep_item_str);
			continue;
		}

		/*
		 * jam away the dirent for later use
		 * Note! scandir does notallocate a full struct dirent
		 */
#if !defined(__linux__)
		d_copy = xcalloc(1, sizeof(struct dirent));
		d_copy->d_fileno = d->d_fileno;2
		d_copy->d_reclen = d->d_reclen;
		d_copy->d_type = d->d_type;
		d_copy->d_namlen = d->d_namlen;
		strlcpy(d_copy->d_name, d->d_name, d->d_namlen + 1);
#else
		d_copy = xcalloc(1, d->d_reclen);
		memcpy(d_copy, d, d->d_reclen);
#endif

		set_item_userptr(items[cur_item], d_copy);

		cur_item++;
	}

	/* add files */
	for (i = 0; i < n_files; i++) {
		d = dirents_files[i];

		hgd_prepare_item_string(&prep_item_str, d->d_name);

		items[cur_item] = new_item(prep_item_str, NULL);

		if (items[cur_item] == NULL) {
			DPRINTF(HGD_D_WARN,
			    "Could not make new menu item: %s", SERROR);
			free(prep_item_str);
			continue;
		}

		/*
		 * copy manually, do not use memcpy, as scandir does not
		 * allocate a full struct dirent
		 */
#if !defined(__linux__)
		d_copy = xcalloc(1, sizeof(struct dirent));
		d_copy->d_fileno = d->d_fileno;2
		d_copy->d_reclen = d->d_reclen;
		d_copy->d_type = d->d_type;
		d_copy->d_namlen = d->d_namlen;
		strlcpy(d_copy->d_name, d->d_name, d->d_namlen + 1);
#else
		d_copy = xcalloc(1, d->d_reclen);
		memcpy(d_copy, d, d->d_reclen);
#endif

		set_item_userptr(items[cur_item], d_copy);

		cur_item++;
	}

	DPRINTF(HGD_D_INFO, "Actually allocated %d menu items", cur_item);
	items[cur_item] = NULL;

	u->content_menus[HGD_WIN_FILES] = new_menu(items);

	keypad(u->content_wins[HGD_WIN_FILES], TRUE);
	set_menu_win(u->content_menus[HGD_WIN_FILES],
	    u->content_wins[HGD_WIN_FILES]);
	set_menu_mark(u->content_menus[HGD_WIN_FILES], "");
	set_menu_format(u->content_menus[HGD_WIN_FILES],
	    LINES - 2, 1);
	set_menu_fore(u->content_menus[HGD_WIN_FILES],
	    COLOR_PAIR(HGD_CPAIR_SELECTED));

	if ((post_menu(u->content_menus[HGD_WIN_FILES])) != E_OK)
		DPRINTF(HGD_D_WARN, "Could not post menu");

	ret = HGD_OK;

clean:
	if (dirents_files) {
		for (i = 0; i < n_files; i ++)
			free(dirents_files[i]);
		free(dirents_files);
	}

	if (dirents_dirs) {
		for (i = 0; i < n_dirs; i ++)
			free(dirents_dirs[i]);
		free(dirents_dirs);
	}

#if 0
	if (items)
		free(items);
#endif

	return (ret);

}

int
hgd_update_console_win(struct ui *u)
{
	char		  buf[HGD_LOG_BACKBUFFER + 1], *start = buf, *end, *copy;
	long		  pos, endpos, read;
	long		  toread = HGD_LOG_BACKBUFFER;
	ITEM		**items = NULL;
	int		  cur_index = 0;

	DPRINTF(HGD_D_INFO, "Update console window");

	wclear(u->content_wins[HGD_WIN_CONSOLE]);
	hgd_unpost_and_free_content_menu(u, HGD_WIN_CONSOLE);

	memset(buf, 0, HGD_LOG_BACKBUFFER + 1);

	/* find how long the log is */
	if ((fseek(logs.rd, 0, SEEK_END)) != 0)
		DPRINTF(HGD_D_WARN, "fseek: %s", SERROR);

	endpos = ftell(logs.rd);
	if (endpos < HGD_LOG_BACKBUFFER)
		toread = endpos;

	/* rewind at most HGD_LOG_BACKBUFFER and read into buffer */
	if ((fseek(logs.rd, -toread, SEEK_END)) != 0)
		DPRINTF(HGD_D_WARN, "fseek: %s", SERROR);

	pos = ftell(logs.rd);
	if ((read = fread(buf, toread, 1, logs.rd)) == 0) {
		if (ferror(logs.rd)) {
		    DPRINTF(HGD_D_WARN,
			"Failed to read console log: %s", SERROR);
		}
	}

	/* ensure we dont start printing the middle of a line */
	if (pos < 0)
		DPRINTF(HGD_D_WARN, "ftell failed: %s", SERROR);
	else if (pos != 0) {
		/* if not at the start of file, find a \n */
		while ((*start != '\n') && (*start != '\0'))
			start++;
	}

	/* this SHOULD happen, but not guaraunteed */
	if (*start == '\n')
		start++;

	items = xcalloc(sizeof(ITEM *), 1);

	/* scan for lines and add them as menu items */
	end = start;
	while (*start != 0) {
		while ((*end != 0) && (*end != '\n'))
			end++;

		if (*end == 0) {
			DPRINTF(HGD_D_WARN, "Unexpected end of log");
			break;
		}
		*end = 0;

		/* could be more efficient */
		items = xrealloc(items, sizeof(ITEM *) * (cur_index + 2));
		items[cur_index + 1] = NULL;

		hgd_prepare_item_string(&copy, start);
		items[cur_index] = new_item(copy, NULL);

		if (items[cur_index] == NULL) {
			DPRINTF(HGD_D_WARN,
			    "Could not make new menu item '%s'", start);
			free(copy);
		}

		end++;
		start = end;

		if (items[cur_index] == NULL)
			continue;

		cur_index++;
	}

	/* now we have our items, make the menu */
	if (u->content_menus[HGD_WIN_CONSOLE] != NULL) {
		/* XXX clean up old menu */
	}

	u->content_menus[HGD_WIN_CONSOLE] = new_menu(items);

	keypad(u->content_wins[HGD_WIN_CONSOLE], TRUE);
	set_menu_win(u->content_menus[HGD_WIN_CONSOLE],
	    u->content_wins[HGD_WIN_CONSOLE]);
	set_menu_mark(u->content_menus[HGD_WIN_CONSOLE], "");
	set_menu_format(u->content_menus[HGD_WIN_CONSOLE],
	    LINES - 2, 1);
	set_menu_fore(u->content_menus[HGD_WIN_CONSOLE],
	    COLOR_PAIR(HGD_CPAIR_SELECTED));

	if ((post_menu(u->content_menus[HGD_WIN_CONSOLE])) != E_OK)
		DPRINTF(HGD_D_WARN, "Could not post menu");

	menu_driver(u->content_menus[HGD_WIN_CONSOLE], REQ_LAST_ITEM);

	return (HGD_OK);
}

/*
 * switches the content window and marks it for refresh
 */
int
hgd_switch_content(struct ui *u, int w)
{
	int			ret = HGD_FAIL;

	DPRINTF(HGD_D_INFO, "Switch to window: %s", window_names[w]);

	if (u->content_refresh_handler[w] == NULL) {
		DPRINTF(HGD_D_WARN, "No content refresh handler defined");
		goto clean;
	}

	if (u->content_refresh_handler[w](u) != HGD_OK)
		goto clean;

	u->active_content_win = w;
	hgd_refresh_ui(u);

	ret = HGD_OK;
clean:
	return (ret);
}

int
hgd_init_titlebar(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise titlebar");

	if ((u->title = newwin(1, COLS, 0, 0)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise titlebar");
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

int
hgd_init_statusbar(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise statusbar");

	if ((u->status = newwin(HGD_POS_STATUS_H, HGD_POS_STATUS_W,
	    HGD_POS_STATUS_Y, HGD_POS_STATUS_X)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise statusbar");
		return (HGD_FAIL);
	}

	u->status_str = xstrdup("***");

	return (HGD_OK);
}

int
hgd_init_playlist_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise playlist window");

	/* make window */
	if ((u->content_wins[HGD_WIN_PLAYLIST] = newwin(HGD_POS_CONT_H, HGD_POS_CONT_W,
	    HGD_POS_CONT_Y, HGD_POS_CONT_X)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to playlist content window");
		return (HGD_FAIL);
	}

	u->content_menus[HGD_WIN_PLAYLIST] = NULL;
	keypad(u->content_wins[HGD_WIN_PLAYLIST], TRUE);

	/* refresh handler */
	u->content_refresh_handler[HGD_WIN_PLAYLIST] = hgd_update_playlist_win;

	return (HGD_OK);
}

/* initialise the file browser content pane */
int
hgd_init_files_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise file browser window");

	if ((u->content_wins[HGD_WIN_FILES] = newwin(HGD_POS_CONT_H, HGD_POS_CONT_W,
	    HGD_POS_CONT_Y, HGD_POS_CONT_X)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise file browser content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_FILES], TRUE);

	u->content_menus[HGD_WIN_FILES] = NULL;
	u->content_refresh_handler[HGD_WIN_FILES] = hgd_update_files_win;

	u->cwd = xstrdup(getenv("PWD"));

	return (HGD_OK);
}

int
hgd_init_console_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise console window");

	if ((u->content_wins[HGD_WIN_CONSOLE] = newwin(HGD_POS_CONT_H, HGD_POS_CONT_W,
	    HGD_POS_CONT_Y, HGD_POS_CONT_X)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise file browser content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_CONSOLE], TRUE);
	mvwprintw(u->content_wins[HGD_WIN_CONSOLE], 0, 0, "Insert console here");

	u->content_menus[HGD_WIN_CONSOLE] = NULL;
	u->content_refresh_handler[HGD_WIN_CONSOLE] = hgd_update_console_win;

	return (HGD_OK);
}

int
hgd_resize_app(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Resize application: %dx%d", COLS, LINES);
	
	/* update geometry of titlebar - no need to move, always (0,0)  */
	if (wresize(u->title, HGD_POS_TITLE_H, HGD_POS_TITLE_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of statusbar */
	if (mvwin(u->status, HGD_POS_STATUS_Y, HGD_POS_STATUS_X) == ERR)
		DPRINTF(HGD_D_WARN, "Could not move window: %s", SERROR);
	if (wresize(u->status, HGD_POS_STATUS_H, HGD_POS_STATUS_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of playlist window - no need to move, always (1,0) */
	if (wresize(u->content_wins[HGD_WIN_PLAYLIST], HGD_POS_CONT_H, HGD_POS_CONT_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of files window - no need to move, always (1,0) */
	if (wresize(u->content_wins[HGD_WIN_FILES], HGD_POS_CONT_H, HGD_POS_CONT_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of console window - no need to move, always (1,0) */
	if (wresize(u->content_wins[HGD_WIN_CONSOLE], HGD_POS_CONT_H, HGD_POS_CONT_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	return (hgd_switch_content(u, u->active_content_win));
}

/*
 * calculate dimensions of a centred, usefully sized dialog win
 */
#define				HGD_DIALOG_WIN_HRATIO		0.2
#define				HGD_DIALOG_WIN_WRATIO		0.7
int
hgd_calc_dialog_win_dims(int *y, int *x, int *h, int *w)
{
	*h = LINES * HGD_DIALOG_WIN_HRATIO;
	*w = COLS * HGD_DIALOG_WIN_WRATIO;
	*y = (LINES - *h) / 2;
	*x = (COLS - *w) / 2;

	return (HGD_OK);
}

int
hgd_centre_dialog_text(char **dest, const char *src_const)
{
	char			*next = xstrdup(src_const);
	char			*centre_line, *tok, *trunc = NULL;
	int			 centre_start;
	int			 dwidth = COLS * HGD_DIALOG_WIN_WRATIO;

	*dest = NULL;

	centre_line = malloc(dwidth + 1);

	while ((tok = strsep(&next, "\n")) != NULL) {

		/* blank out and terminate */
		memset(centre_line, ' ', dwidth);
		centre_line[dwidth] = '\0';

		/* calculate start point and copy in */
		trunc = hgd_truncate_string(tok, dwidth);
		centre_start = dwidth / 2 - (strlen(trunc) / 2);
		strncpy(centre_line + centre_start, trunc, strlen(trunc));

		if (*dest == NULL)
			*dest = xstrdup(centre_line);
		else
			xasprintf(dest, "%s\n%s", *dest, centre_line);
	}

	free(trunc);
	free(centre_line);

	return (HGD_OK);
}

int
hgd_show_dialog(struct ui *u, const char *title, const char *msg, int secs)
{
	WINDOW			*bwin, *win;
	int			 x, y, h, w;
	char			*msg_centre;
	int			 ch = 0, again = 0;

	/* we will need to redisplay the dialog if we get a resize */
	do {
		again = 0;

		hgd_calc_dialog_win_dims(&y, &x, &h, &w);
		hgd_centre_dialog_text(&msg_centre, msg);

		DPRINTF(HGD_D_INFO, "Show dialog: '%s'", title);

		if ((bwin = newwin(h + 2, w + 2, y - 1, x - 1)) == NULL) {
			DPRINTF(HGD_D_ERROR, "Could not initialise progress window");
			return (HGD_FAIL);
		}

		if ((win = newwin(h, w, y, x)) == NULL) {
			DPRINTF(HGD_D_ERROR, "Could not initialise progress window");
			return (HGD_FAIL);
		}

		wattron(win, COLOR_PAIR(HGD_CPAIR_DIALOG));
		wattron(bwin, COLOR_PAIR(HGD_CPAIR_DIALOG));

		wclear(win);
		wclear(bwin);

		wbkgd(win, COLOR_PAIR(HGD_CPAIR_DIALOG));
		box(bwin, '|', '-');

		mvwprintw(bwin, 0, w / 2 - (strlen(title) / 2), title);
		mvwprintw(win, 1, 0, msg_centre);

		redrawwin(bwin);
		redrawwin(win);
		wrefresh(bwin);
		wrefresh(win);

		if (secs)
			sleep(secs);
		else
			ch = wgetch(win);

		if (ch == KEY_RESIZE) {
			DPRINTF(HGD_D_INFO, "redraw dialog");
			hgd_resize_app(u);
			again = 1;
		}

		delwin(win);
		delwin(bwin);

		free(msg_centre);

	} while(again);

	hgd_refresh_ui(u);

	return (HGD_OK);
}

int
hgd_set_statusbar_text(struct ui *u, char *fmt, ...)
{
	va_list			 ap;
	char			*buf;

	va_start(ap, fmt);
	if (vasprintf(&buf, fmt, ap) < 0) {
		DPRINTF(HGD_D_ERROR, "Can't allocate");
		return (HGD_FAIL);
	}

	free(u->status_str);
	u->status_str = buf;
	hgd_refresh_statusbar(u);

	return (HGD_OK);
}

/*
 * The "standard" statusbar that the user sees 99% of the time
 */
int
hgd_set_standard_statusbar_text(struct ui *u)
{
	return (hgd_set_statusbar_text(u,
	    "Connected >>> %s@%s:%d   Vote: %d", user, host, port, -1));
}


int hgd_ui_q_callback(void *arg, float progress)
{
	char				 bar[COLS+1];
	struct ui 			*u = (struct ui *) arg;
	int				 i, fill = COLS * progress;

	memset(bar, ' ', COLS);
	bar[COLS] = '\0';

	for (i = 0; i < fill; i++)
		bar[i] = '#';

	hgd_set_statusbar_text(u, "%s", bar);

	return (HGD_OK);
}

int
hgd_ui_queue_track(struct ui *u, char *filename)
{
	char			*full_path = NULL;
	char			*title = "[ File Upload ]";
	int			 ret = HGD_FAIL;
	WINDOW			*bwin = NULL, *win = NULL, *bar = NULL;
	int			 x, y, h, w;
	char			*msg_centre;

	DPRINTF(HGD_D_INFO, "Upload track: %s", filename);

	xasprintf(&full_path, "%s/%s", u->cwd, filename);

	hgd_calc_dialog_win_dims(&y, &x, &h, &w);
	hgd_centre_dialog_text(&msg_centre, filename);

	if ((bwin = newwin(h + 2, w + 2, y - 1, x - 1)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise progress window");
		goto clean;
	}

	if ((win = newwin(h, w, y, x)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise progress window");
		goto clean;
	}

	wattron(win, COLOR_PAIR(HGD_CPAIR_DIALOG));
	wattron(bwin, COLOR_PAIR(HGD_CPAIR_DIALOG));

	wclear(win);
	wclear(bwin);

	wbkgd(win, COLOR_PAIR(HGD_CPAIR_DIALOG));
	wbkgd(bar, COLOR_PAIR(HGD_CPAIR_PBAR_BG));
	box(bwin, '|', '-');

	mvwprintw(bwin, 0, w / 2 - (strlen(title) / 2), title);
	mvwprintw(win, 1, 0, msg_centre);

	redrawwin(bwin);
	redrawwin(win);
	wrefresh(bwin);
	wrefresh(win);

	ret = hgd_cli_queue_track(full_path, u, hgd_ui_q_callback);

	/* XXX */
	//hgd_resize_app(u);
clean:
	if (full_path)
		free(full_path);

	if (ret == HGD_OK) 
		hgd_set_statusbar_text(u, "Upload of '%s' succesful", filename);
	else
		hgd_set_statusbar_text(u, "Upload of '%s' failed", filename);

	delwin(win);
	delwin(bwin);

	free(msg_centre);

	hgd_refresh_ui(u);

	return (ret);
}

/* uh oh, someone hit enter on the files menu! */
int
hgd_enter_on_files_menu(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Selected item on files menu");

	char			*new_cwd = NULL;
	ITEM			*item;
	struct dirent		*dirent;

	if ((item = current_item(u->content_menus[HGD_WIN_FILES])) == NULL) {
	    DPRINTF(HGD_D_WARN, "Could not get current item");
	    return (HGD_FAIL);
	}

	dirent = (struct dirent *) item_userptr(item);

	switch (dirent->d_type) {
	case DT_DIR:
		DPRINTF(HGD_D_INFO, "switch cwd: dirent->d_name");

		if (strcmp(dirent->d_name, "..") == 0)
			new_cwd = xstrdup(dirname(u->cwd));
		else
			xasprintf(&new_cwd, "%s/%s", u->cwd, dirent->d_name);

		free(u->cwd);
		u->cwd = new_cwd;

		break;
	default:
		hgd_ui_queue_track(u, dirent->d_name);
		break;
	};

	return (HGD_OK);
}

int
hgd_event_loop(struct ui *u)
{
	int			c;


	while ((!dying) && (!restarting)) {

		c = wgetch(u->content_wins[u->active_content_win]);

		if ((dying) || (restarting))
		    continue;

		switch(c) {
		case KEY_DOWN:
			menu_driver(u->content_menus[u->active_content_win],
			    REQ_DOWN_ITEM);
			break;
		case KEY_UP:
			menu_driver(u->content_menus[u->active_content_win],
			    REQ_UP_ITEM);
			break;
		case KEY_NPAGE:
			menu_driver(u->content_menus[u->active_content_win],
			    REQ_SCR_DPAGE);
			break;
		case KEY_PPAGE:
			menu_driver(u->content_menus[u->active_content_win],
			    REQ_SCR_UPAGE);
			break;
		case '1':
			menu_driver(u->content_menus[u->active_content_win],
			    REQ_FIRST_ITEM);
			break;
		case 'G':
			menu_driver(u->content_menus[u->active_content_win],
			    REQ_LAST_ITEM);
			break;
		case '\t':
			/* tab toggles toggle between files and playlist */
			if (u->active_content_win != HGD_WIN_PLAYLIST)
				hgd_switch_content(u, HGD_WIN_PLAYLIST);
			else
				hgd_switch_content(u, HGD_WIN_FILES);
			break;
		case '`':
			hgd_switch_content(u, HGD_WIN_CONSOLE);
			break;
		case KEY_RESIZE:
			/* fires magically when terminal is resized */
			hgd_resize_app(u);
			break;
		case '\n':
			if (u->active_content_win == HGD_WIN_FILES) {
				hgd_enter_on_files_menu(u);
				hgd_switch_content(u, HGD_WIN_FILES);
			}
		}

	}

	return (HGD_OK);
}

int
hgd_read_config(char **config_locations)
{
#ifdef HAVE_LIBCONFIG
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 * see hgd-playd.c for how to remove need for stat.
	 */
	config_t		 cfg, *cf;
	int			 ret = HGD_OK;

	cf = &cfg;

	if (hgd_load_config(cf, config_locations) == HGD_FAIL)
		return (HGD_OK);

	/* hgd_cfg_c_colours(cf, &colours_on); */
	hgd_cfg_crypto(cf, "hgdc", &crypto_pref);
	hgd_cfg_c_hostname(cf, &host);
	hgd_cfg_c_port(cf, &port);
	hgd_cfg_c_password(cf, &password, *config_locations);
	/* hgd_cfg_c_refreshrate(cf, &hud_refresh_speed); */
	hgd_cfg_c_username(cf, &user);
	hgd_cfg_c_debug(cf, &hgd_debug);

	config_destroy(cf);
	return (ret);
#else
	return (HGD_OK);
#endif
}

int
hgd_show_about(struct ui *u)
{
	char			*msg;

	xasprintf(&msg, "Welcome to nchgdc version %s!\n\n"
	    "http://hgd.theunixzoo.co.uk", HGD_VERSION);

	hgd_show_dialog(u, "[ Welcome to the Land of Forbidden Fruit! ]", msg, 0);
	free(msg);

	return (HGD_OK);
}

int
hgd_ui_connect(struct ui *u)
{
	hgd_set_statusbar_text(u, "Connecting >>> %s@%s:%d", user, host, port);

	if (hgd_setup_socket() != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Cannot setup socket");
		hgd_show_dialog(u, "[ Error ]", "Failed to connect", 0);
		return (HGD_FAIL);
	}

	hgd_set_statusbar_text(u,
	    "Connected, checking server version >>> %s@%s:%d",
	    user, host, port);

	/* check protocol matches the server before we continue */
	if (hgd_check_svr_proto() != HGD_OK) {
		hgd_show_dialog(u, "[ Error ]", "Protocol mismatch", 0);
		return (HGD_FAIL);
	}

	hgd_set_statusbar_text(u, "Connected, authenticating >>> %s@%s:%d",
	    user, host, port);

	if (hgd_client_login(sock_fd, ssl, user) != HGD_OK) {
		hgd_show_dialog(u, "[ Error ]", "Authentication Failed", 0);
		return (HGD_FAIL);
	}

	hgd_set_standard_statusbar_text(u);
	hgd_update_playlist_win(u);
	hgd_refresh_ui(u);

	return (HGD_OK);
}

int
hgd_free_content_win(struct ui *u, int which)
{
	DPRINTF(HGD_D_INFO, "free window: %s", window_names[which]);

	if (u->content_wins[which] == NULL)
		return (HGD_OK);

	hgd_unpost_and_free_content_menu(u, which);
	delwin(u->content_wins[which]);

	u->content_wins[which] = NULL;

	return (HGD_OK);
}

int
main(int argc, char **argv)
{
	struct ui		 u;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2;

	memset(&u, 0, sizeof(u));

	hgd_debug = 3; /* XXX config file or getopt */

	host = xstrdup(HGD_DFL_HOST);
#ifdef HAVE_LIBCONFIG
	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_CLI_CFG );
	config_path[2] = hgd_get_XDG_userprefs_location(hgdc);
#endif

	hgd_read_config(config_path + num_config);

	while(num_config > 0) {
		if (config_path[num_config] != NULL) {
			free (config_path[num_config]);
			config_path[num_config] = NULL;
		}
		num_config--;
	}

	if (init_log() != HGD_OK)
		hgd_exit_nicely();

	/* XXX proper dialog box needed */
	if (password == NULL) {
		password = xmalloc(HGD_MAX_PASS_SZ);
		if (readpassphrase("Password: ", password, HGD_MAX_PASS_SZ,
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
			DPRINTF(HGD_D_ERROR, "Can't read password");
			hgd_exit_nicely();
		}
	}

	hgd_register_sig_handlers();

	initscr();

	cbreak();
	keypad(stdscr, TRUE);
	noecho();

	if (has_colors()) {
		if (start_color() == ERR)
			DPRINTF(HGD_D_WARN, "Could not initialise colour terminal");
	}

	/* XXX fall back implementations for B+W terms? */
	init_pair(HGD_CPAIR_BARS, COLOR_YELLOW, COLOR_BLUE);
	init_pair(HGD_CPAIR_SELECTED, COLOR_BLACK, COLOR_WHITE);
	init_pair(HGD_CPAIR_DIALOG, COLOR_BLACK, COLOR_CYAN);
	init_pair(HGD_CPAIR_PBAR_BG, COLOR_YELLOW, COLOR_BLACK);

	/* initialise top and bottom bars */
	if (hgd_init_titlebar(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_statusbar(&u) != HGD_OK)
		hgd_exit_nicely();

	/* and all content windows */
	if (hgd_init_files_win(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_console_win(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_playlist_win(&u) != HGD_OK)
		hgd_exit_nicely();

	/* start on the playlist */
	hgd_switch_content(&u, HGD_WIN_PLAYLIST);

	if (user == NULL) user = getenv("USER"); /* XXX duplicated */
	if (hgd_ui_connect(&u) != HGD_OK)
		hgd_exit_nicely();

	/* main event loop */
	DPRINTF(HGD_D_INFO, "nchgdc event loop starting");
	hgd_event_loop(&u);

	DPRINTF(HGD_D_INFO, "Closing down");
	hgd_free_content_win(&u, HGD_WIN_PLAYLIST);
	hgd_free_content_win(&u, HGD_WIN_FILES);
	hgd_free_content_win(&u, HGD_WIN_CONSOLE);
	delwin(u.status);
	delwin(u.title);

	exit_ok = 1;
	hgd_exit_nicely();

	return 0;
}

