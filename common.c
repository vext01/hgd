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
#include <errno.h>
#include <signal.h>
#ifdef __linux__
#include <bsd/readpassphrase.h>
#else
#include <readpassphrase.h>
#endif


#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdarg.h>

#include "config.h"
#include "hgd.h"

int8_t				  hgd_debug = HGD_D_WARN;
uint8_t				  dying = 0;
char				**cmd_line_args;
uint8_t				  restarting = 0;
uint8_t				  exit_ok = 0;
pid_t				  pid = 0;

char				 *debug_names[] = {
				    "error", "warn", "info", "debug"};
int				 syslog_error_map[] = {
				    LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG
				 };

/* these are unused in client */
char				 *state_path = NULL;
char				 *filestore_path = NULL;

/*
 * frees members of a playlist item, but not the item
 * itself, therefore allowing stack allocation if wished
 */
void
hgd_free_playlist_item(struct hgd_playlist_item *i)
{
	if (i->filename != NULL)
		free(i->filename);
	if (i->user != NULL)
		free(i->user);
	if (i->tag_artist != NULL)
		free(i->tag_artist);
	if (i->tag_title != NULL)
		free(i->tag_title);
}

/*
 * free a playlist's members but not the list itself
 */
void
hgd_free_playlist(struct hgd_playlist *list)
{
	unsigned int		i;

	for (i = 0; i < list->n_items; i ++) {
		hgd_free_playlist_item(list->items[i]);
		free(list->items[i]);
	}

	free(list->items);
}

void *
xmalloc(size_t sz)
{
	void			*ptr;

	ptr = malloc(sz);
	if (!ptr) {
		DPRINTF(HGD_D_ERROR, "Could not allocate");
		hgd_exit_nicely();
	}

	return (ptr);

}

void *
xcalloc(size_t sz, size_t size)
{
	void			*ptr;

	ptr = calloc(sz, size);
	if (!ptr) {
		DPRINTF(HGD_D_ERROR, "Could not allocate");
		hgd_exit_nicely();
	}

	return (ptr);
}

void *
xrealloc(void *old_p, size_t sz)
{
	void			*ptr;

	ptr = realloc(old_p, sz);
	if (!ptr) {
		DPRINTF(HGD_D_ERROR, "Could not reallocate");
		hgd_exit_nicely();
	}

	return (ptr);
}

char *
xstrdup(const char *s)
{
	char *dup = strdup(s);

	if (dup == NULL)
		DPRINTF(HGD_D_ERROR, "Could not duplicate string");

	return (dup);
}

int
xasprintf(char **buf, char *fmt, ...)
{
	va_list			ap;
	int			ret;

	va_start(ap, fmt);
	ret = vasprintf(buf, fmt, ap);

	if (ret == -1) {
		DPRINTF(HGD_D_ERROR, "Can't allocate");
		hgd_exit_nicely();
	}

	return (ret);
}

void
hgd_kill_sighandler(int sig)
{
	if (sig == SIGHUP)
		restarting = 1;
	else
		dying = 1;
}

void
hgd_register_sig_handlers()
{
	struct sigaction	sa;
	/* NB: update loop bounds if adding more */
	int			sigs[] =
				    {SIGTERM, SIGABRT, SIGINT, SIGHUP};
	int			i;

	DPRINTF(HGD_D_INFO, "Registering signal handlers");

	sa.sa_handler = hgd_kill_sighandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	for (i = 0; i < 4; i++) {
		if (sigaction (sigs[i], &sa, NULL) != 0)
			DPRINTF(HGD_D_WARN,
			    "registering sighandler failed: %s", SERROR);
	}
}

/* make state dir if not existing */
void
hgd_mk_state_dir()
{
	if (mkdir(state_path, S_IRWXU) != 0) {
		if (errno != EEXIST) {
			DPRINTF(HGD_D_ERROR, "%s: %s", state_path, SERROR);
			hgd_exit_nicely();
		}
	}

	/* make filestore if not existing */
	if (mkdir(filestore_path, S_IRWXU) != 0) {
		if (errno != EEXIST) {
			DPRINTF(HGD_D_ERROR, "%s:%s", filestore_path, SERROR);
			hgd_exit_nicely();
		}
	}

	/* correct any insecure perms (user may think he knows better) */
	if (chmod(filestore_path, S_IRWXU) != 0)
		DPRINTF(HGD_D_WARN, "Could not make filestore secure");

	if (chmod(state_path, S_IRWXU) != 0)
		DPRINTF(HGD_D_WARN, "Could not make state dir secure");
}

void
hgd_print_version()
{
	printf("Hackathon Gunther Daemon v" HGD_VERSION "\n");
	printf("(C) Edd Barrett, Martin Ellis 2011\n");
}

/*
 * Turn bytes into hex for storage.
 * Caller must free.
 */
char *
hgd_bytes_to_hex(unsigned char *bytes, int len)
{
	char			*hex;
	int			 i, hex_len;

	hex_len = len * 2 + 1;
	hex = xmalloc(hex_len);	/* two hex chars for each byte */
	memset(hex, 0, hex_len);

	for (i = 0; i < len; i++)
		snprintf(hex, hex_len, "%s%02x", hex, bytes[i]);

	return (hex);
}

/*
 * Non allocating version of the above.
 * out should be twice as big as in + 1.
 */
void
hgd_bytes_to_hex_buf(char *in, char *out, int length)
{
	int			i;

	for (i = 0; i < length; ++i)
		snprintf(out+(i*2), 3, "%X", (unsigned int) *in+i);
}

/* free a user struct's members */
void
hgd_free_user(struct hgd_user *u)
{
	/* looks silly now, but I am sure we will add more stuff later */
	free(u->name);
}

/* free a user list struct's members */
void
hgd_free_user_list(struct hgd_user_list *ul)
{
	int			i;

	for (i = 0; i < ul->n_users; i++) {
		hgd_free_user(ul->users[i]);
		free(ul->users[i]);
	}
	free(ul->users);
}

/*
 * read a password twice and return if the same
 */
int
hgd_readpassphrase_confirmed(char buf[HGD_MAX_PASS_SZ])
{
	char			p1[HGD_MAX_PASS_SZ], p2[HGD_MAX_PASS_SZ];
	uint8_t			again = 1;

	while (again) {
		if (readpassphrase("Password: ", p1, HGD_MAX_PASS_SZ,
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
			DPRINTF(HGD_D_ERROR, "Can't read password");
			return (HGD_FAIL);
		}

		if (readpassphrase("Again: ", p2, HGD_MAX_PASS_SZ,
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
			DPRINTF(HGD_D_ERROR, "Can't read password");
			return (HGD_FAIL);
		}

		if (strcmp(p1, p2) == 0)
			again = 0;
		else
			DPRINTF(HGD_D_ERROR, "Passwords did not match!");
	}

	strncpy(buf, p1, HGD_MAX_PASS_SZ);

	return (HGD_OK);
}

int
hgd_daemonise()
{
	pid_t			pid;
	pid = fork();
	if (pid) {
		/* parent */
		DPRINTF(HGD_D_INFO, "Daemonising. PID=%d", pid);
		exit_ok = 1;
		hgd_exit_nicely();
	}

	/* child */
	if (setsid() != getpid()) {
		DPRINTF(HGD_D_ERROR, "failed to setsid: %s", SERROR);
		return (HGD_FAIL);
	}

	fclose(stdout);
	fclose(stderr);

	return (HGD_OK);
}

void
hgd_restart_myself()
{
	DPRINTF(HGD_D_WARN, "Caught SIGHUP, restarting");

	if (execv(cmd_line_args[0], cmd_line_args) < 0) {
		DPRINTF(HGD_D_ERROR, "Failed to restart"
		    ", is %s in your path?: %s", hgd_component, SERROR);
	}

	/*
	 * If we get here, something screwed up.
	 * We can't call hgd_exit_nicely again, as
	 * everything is already freed. So we just exit.
	 */
	DPRINTF(HGD_D_ERROR, "%s was interrupted or crashed", hgd_component);
}

int
hgd_cache_exec_context(char **argv)
{
	if (*(argv[0]) != '/') {
		DPRINTF(HGD_D_ERROR,
		    "HGD daemons must be started with an absolute path. "
		    "You passed '%s'", argv[0]);
		return (HGD_FAIL);
	}

	//self_abs_path = argv[0];
	cmd_line_args = argv;

	DPRINTF(HGD_D_INFO, "daemon='%s'", argv[0]);

	return (HGD_OK);
}
