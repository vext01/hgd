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
#include <curses.h>
#include <stdlib.h>
#include <menu.h>
#include <err.h>

#include "hgd.h"
#include "config.h"
#include "cfg.h"
#include "client.h"
#include "nchgdc.h"

#define HGD_CPAIR_BARS		1
#define HGD_CPAIR_SELECTED	2

const char		*hgd_component = "nchgdc";

const char *window_names[] = {
	"Playlist",
	"File Browser",
	"Console"
};

const char *test_playlist[] = {
	"Gunther.ogg",
	"Crabs.mp3",
	"Some longer file name with spaces.ogg",
	"Some track4",
	"Some track5",
	"Some track6",
	"Some track7",
	"Some track8",
	"Some track10",
	"Some track11",
	"Some track11",
	"Some track12",
	"Some track15",
	"Some track13",
	"Some track12",
	NULL
};

struct hgd_ui_log			logs;

void
hgd_exit_nicely()
{
	endwin();

	if (!exit_ok) {
		DPRINTF(HGD_D_ERROR, "nchgdc crashed or was interrupted");
		printf("ERROR: nchgdc crashed or was interrupted! Please examine the log file\n");
	}

	_exit(!exit_ok);
}

void
hgd_refresh_ui(struct ui *u)
{
	refresh();

	if (u->content_menus[u->active_content_win] != NULL) {
		if ((post_menu(u->content_menus[u->active_content_win])) != E_OK)
			DPRINTF(HGD_D_ERROR, "Could not post menu");
	}

	if (u->refresh_content) {
		redrawwin(u->content_wins[u->active_content_win]);
		wrefresh(u->content_wins[u->active_content_win]);
		u->refresh_content = 0;
	}

	hgd_update_titlebar(u);
	wrefresh(u->title);

	wrefresh(u->status);
}

void
init_log()
{
	char *logfile = NULL;

	xasprintf(&logfile, "%s/%s/nchgdc.log",
	    getenv("HOME"), HGD_USR_CFG_DIR);

	DPRINTF(HGD_D_INFO, "UI logging to '%s'", logfile);
	if ((logs.wr = fopen(logfile, "w")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not open write log: %s", SERROR);
		exit (1); /* XXX */
	}

	if ((logs.rd = fopen(logfile, "r")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not open read log: %s", SERROR);
		exit (1); /* XXX */
	}

	free(logfile);

	/* Redirect stderr here, so that DPRINTF can still work */
	close(fileno(stderr));
	dup(fileno(logs.wr));
}

void
hgd_update_titlebar(struct ui *u)
{
	char			*fmt = NULL, *title_str = NULL;

	DPRINTF(HGD_D_INFO, "Update titlebar window");

	wattron(u->title, COLOR_PAIR(HGD_CPAIR_BARS));

	xasprintf(&fmt, "%%-%ds", COLS);
	xasprintf(&title_str, "nchgdc-%s :: %s", HGD_VERSION,
	    window_names[u->active_content_win]);

	mvwprintw(u->title, 0, 0, fmt, title_str);

	free(title_str);
	free(fmt);
}

#define HGD_LOG_BACKBUFFER			1024
void
hgd_update_console_win(struct ui *u)
{
	char		buf[HGD_LOG_BACKBUFFER + 1], *p = buf;
	long		pos, endpos, read;
	long		toread = HGD_LOG_BACKBUFFER;

	DPRINTF(HGD_D_INFO, "Update console window");

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
		if (ferror(logs.rd))
		    DPRINTF(HGD_D_WARN, "Failed to read console log: %s", SERROR);
	}

	/* ensure we dont start printing the middle of a line */
	if (pos < 0)
		DPRINTF(HGD_D_WARN, "ftell failed: %s", SERROR);
	else if (pos != 0) {
		/* if not at the start of file, find a \n */
		while (*p != '\n')
			p++;
	}

	wclear(u->content_wins[HGD_WIN_CONSOLE]);
	mvwprintw(u->content_wins[HGD_WIN_CONSOLE], 0, 0, "%s", p);
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
	char			*fmt = NULL;

	DPRINTF(HGD_D_INFO, "Initialise statusbar");

	if ((u->status = newwin(1, COLS, LINES - 1, 0)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise statusbar");
		return (HGD_FAIL);
	}

	wattron(u->status, COLOR_PAIR(HGD_CPAIR_BARS));
	xasprintf(&fmt, "%%-%ds", COLS);
	wprintw(u->status, fmt,  "User: edd\tHasVote: Yes");
	free (fmt);

	return (HGD_OK);
}

int
hgd_init_playlist_win(struct ui *u)
{
	ITEM			**items;
	int			  num, i;

	DPRINTF(HGD_D_INFO, "Initialise playlist window");

	num = ARRAY_SIZE(test_playlist);

	items = calloc(num, sizeof(ITEM *));
	for (i = 0; i < num; i++)
		items[i] = new_item(test_playlist[i], NULL);

	u->content_menus[HGD_WIN_PLAYLIST] = new_menu(items);
	if ((u->content_wins[HGD_WIN_PLAYLIST] = newwin(LINES - 2, COLS, 1, 0)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to playlist content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_PLAYLIST], TRUE);
	set_menu_win(u->content_menus[HGD_WIN_PLAYLIST], u->content_wins[HGD_WIN_PLAYLIST]);
	set_menu_mark(u->content_menus[HGD_WIN_PLAYLIST], "");
	set_menu_format(u->content_menus[HGD_WIN_PLAYLIST], LINES - 2, 1);
	set_menu_fore(u->content_menus[HGD_WIN_PLAYLIST], COLOR_PAIR(HGD_CPAIR_SELECTED));

	return (HGD_OK);
}

/* initialise the file browser content pane */
int
hgd_init_files_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise file browser window");

	if ((u->content_wins[HGD_WIN_FILES] = newwin(LINES - 2, COLS, 1, 0)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise file browser content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_FILES], TRUE);
	mvwprintw(u->content_wins[HGD_WIN_FILES], 0, 0, "Insert file browser here");
	mvwprintw(u->content_wins[HGD_WIN_FILES], 10, 0, "Ooooh - you touch my tralala");

	u->content_menus[HGD_WIN_FILES] = NULL; /* no menu */

	return (HGD_OK);
}

int
hgd_init_console_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise console window");

	if ((u->content_wins[HGD_WIN_CONSOLE] = newwin(LINES - 2, COLS, 1, 0)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise file browser content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_CONSOLE], TRUE);
	mvwprintw(u->content_wins[HGD_WIN_CONSOLE], 0, 0, "Insert console here");

	u->content_menus[HGD_WIN_CONSOLE] = NULL; /* no menu */

	return (HGD_OK);
}

int
main(int argc, char **argv)
{
	struct ui	u;
	int		c;

	hgd_debug = 3; /* XXX config file or getopt */

	init_log();

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

	u.refresh_content = 1;
	u.active_content_win = HGD_WIN_PLAYLIST;

	/* initialise top and bottom bars */
	if (hgd_init_titlebar(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_statusbar(&u) != HGD_OK)
		hgd_exit_nicely();

	/* and all content windows */
	if (hgd_init_playlist_win(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_files_win(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_console_win(&u) != HGD_OK)
		hgd_exit_nicely();

	DPRINTF(HGD_D_INFO, "nchgdc event loop starting");

	/* main event loop */
	/* XXX catch C^c */
	while (1) {
		hgd_refresh_ui(&u);

		c = wgetch(u.content_wins[u.active_content_win]);
		switch(c) {
		case KEY_DOWN:
			menu_driver(u.content_menus[u.active_content_win], REQ_DOWN_ITEM);
			break;
		case KEY_UP:
			menu_driver(u.content_menus[u.active_content_win], REQ_UP_ITEM);
			break;
		case '\t':
			/* tab toggles toggle between files and playlist */
			if (u.active_content_win != HGD_WIN_PLAYLIST)
				u.active_content_win = HGD_WIN_PLAYLIST;
			else
				u.active_content_win = HGD_WIN_FILES;
			u.refresh_content = 1;
			break;
		case '`':
			u.active_content_win = HGD_WIN_CONSOLE;
			u.refresh_content = 1;
			break;
		}

		if (u.active_content_win == HGD_WIN_CONSOLE)
			hgd_update_console_win(&u);
	}

	exit_ok = 1;
	hgd_exit_nicely();

	return 0;
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


