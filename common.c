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
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#ifdef __linux__
#include <bsd/readpassphrase.h>
#else
#include <readpassphrase.h>
#endif

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

/* permission descriptions */
struct hgd_user_perm hgd_user_perms[] = {
	{ HGD_AUTH_ADMIN,	"ADMIN" },
	{ -1,			0 },
};

/* these are unused in client */
char				 *state_path = NULL;
char				 *filestore_path = NULL;

void
hgd_free_media_tags(struct hgd_media_tag *t)
{
	if (t->artist)
		free(t->artist);

	if (t->title)
		free(t->title);

	if (t->album)
		free(t->album);

	if (t->genre)
		free(t->genre);
}

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

	hgd_free_media_tags(&i->tags);
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

/**
 * read a password twice and return if the same
 * @param buf input buffer should be of size HGD_MAX_PASS_SZ
 */
int
hgd_readpassphrase_confirmed(char *buf, char *prompt)
{
	char			p1[HGD_MAX_PASS_SZ], p2[HGD_MAX_PASS_SZ];
	uint8_t			again = 1;

	if (prompt == NULL)
		prompt = "Password: ";

	while (again) {
		if (readpassphrase(prompt, p1, HGD_MAX_PASS_SZ,
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
	DPRINTF(HGD_D_INFO, "Daemonising...");
	if (daemon(0, 0) < 0) {
		DPRINTF(HGD_D_WARN, "Failed to daemonise: %s", SERROR);
		return (HGD_FAIL);
	}

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

/* in place '...' truncation of long strings if needed */
char *
hgd_truncate_string(char *in, size_t sz)
{
	int			i;

	if (sz < 3) {
		DPRINTF(HGD_D_WARN, "cannot truncate string < 3");
		return (in);
	} else if (strlen(in) <= sz)
		return (in); /* fits */

	in[sz] = 0;
	for (i = 1; i <= 3; i++)
		in[sz - i] = '.';

	return (in);
}

/*
 * generate a user readable permissions description from a bitfield
 *
 * not in user.c as that pulls in sqlite
 */
int
hgd_gen_perms_str(int pfld, char **ret)
{
	struct hgd_user_perm	*perm;
	size_t			 prev_len;

	xasprintf(ret, "<perms:");
	prev_len = strlen(*ret);

	for (perm = hgd_user_perms; perm->bitval != -1; perm++) {
		if (perm->bitval & pfld) {
			xasprintf(ret, "%s %s", *ret, perm->descr);
		}
	}

	if (strlen(*ret) == prev_len)
		xasprintf(ret, "%s NONE>", *ret);
	else
		xasprintf(ret, "%s>", *ret);

	return (HGD_OK);
}

/* type is F_WRLCK (exclusive write), or F_RDLCK (read) */
int
hgd_file_lock(FILE *file, int type)
{
	int			ret = HGD_FAIL;
	struct flock		fl;

	fl.l_type = type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;		/* to EOF */
	fl.l_pid = getpid();

	if (type == F_WRLCK)
		DPRINTF(HGD_D_INFO, "WRLCK");
	else
		DPRINTF(HGD_D_INFO, "RDLCK");

	if (fcntl(fileno(file), F_SETLKW, &fl) == -1) {
		DPRINTF(HGD_D_ERROR,
		    "failed lock: fd=%d: %s", fileno(file), SERROR);
		goto clean;
	}

	ret = HGD_OK;
clean:
	return (ret);
}

int
hgd_file_unlock(FILE *file)
{
	int			ret = HGD_FAIL;
	struct flock		fl;

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;		/* to EOF */
	fl.l_pid = getpid();

	if (fcntl(fileno(file), F_SETLK, &fl) == -1) {
		DPRINTF(HGD_D_ERROR,
		    "fcntl failed: fd=%d: %s", fileno(file), SERROR);
		goto clean;
	}

	ret = HGD_OK;
clean:
	return (ret);
}

/* type is F_WRLOCK (exclusive write), or F_RDLCK (read) */
int
hgd_file_open_and_lock(char *fname, int type, FILE **file)
{
	int			ret = HGD_FAIL;

	if (type == F_WRLCK)
		DPRINTF(HGD_D_INFO, "open and WRLCK: %s", fname);
	else
		DPRINTF(HGD_D_INFO, "open and RDLCK: %s", fname);

	if (type == F_WRLCK)
		*file = fopen(fname, "w");
	else
		*file = fopen(fname, "r");

	if (*file == NULL) {
		DPRINTF(HGD_D_ERROR, "Can't open '%s': %s", fname, SERROR);
		if (errno == ENOENT)
			ret = HGD_FAIL_ENOENT;
		goto clean;
	}

	if (hgd_file_lock(*file, type) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "couldn't lock: %s", fname);
		fclose(*file);
		goto clean;
	}

	ret = HGD_OK;
clean:
	return (ret);
}

int
hgd_file_unlock_and_close(FILE *file)
{
	int			ret = HGD_FAIL;

	DPRINTF(HGD_D_INFO, "unlock and close: fd=%d", fileno(file));

	if (hgd_file_unlock(file) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "falied to unlock: fd=%d", fileno(file));
		goto clean;
	}

	ret = HGD_OK;
clean:
	fclose(file);

	return (ret);
}

void
hgd_set_line_colour(char *ansi_code)
{
	printf("%s", ansi_code);
	fflush(stdout);
}

int
hgd_open_pid_file(FILE **pidfile)
{
	char			*path;
	int			 ret = HGD_FAIL, sr;
	struct stat		 st;

	DPRINTF(HGD_D_INFO, "Opening pid file for %s", hgd_component);

	xasprintf(&path, "%s/%s.pid", state_path, hgd_component);

	/* if the pid file exists, something is wrong */
	sr = stat(path, &st);
	if ((sr != -1) || (errno != ENOENT)) {
		DPRINTF(HGD_D_ERROR,
		    "Stale pid file (%s) or another instance of %s is running.",
		    path, hgd_component);
		goto clean;
	}

	if (hgd_file_open_and_lock(path, F_WRLCK, pidfile)) {
		DPRINTF(HGD_D_ERROR, "Cannot lock pid file");
		goto clean;
	}

	ret = HGD_OK;
clean:
	free(path);

	return (ret);
}
int
hgd_write_pid_file(FILE **pidfile)
{
	int			 ret = HGD_FAIL;

	DPRINTF(HGD_D_INFO, "Write away pid file for %s", hgd_component);

	if (fprintf(*pidfile, "%d", getpid()) < 0) {
		DPRINTF(HGD_D_ERROR, "Can't write out pid: %s", SERROR);
		goto clean;
	}

	if (hgd_file_unlock_and_close(*pidfile) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Can't close/unlock pid file");
		goto clean;
	}

	ret = HGD_OK;
clean:
	return (ret);
}

int
hgd_unlink_pid_file()
{
	char			*path;
	int			 ret = HGD_FAIL;
	FILE			*pidfile;

	DPRINTF(HGD_D_INFO, "Unlink pid file for %s", hgd_component);

	xasprintf(&path, "%s/%s.pid", state_path, hgd_component);

	if (hgd_file_open_and_lock(path, F_WRLCK, &pidfile)) {
		DPRINTF(HGD_D_ERROR, "Cannot lock pid file");
		goto clean;
	}

	if (unlink(path) < 0) {
		DPRINTF(HGD_D_ERROR, "Can't unlink pidfile: %s", SERROR);
		goto clean;
	}

	if (hgd_file_unlock_and_close(pidfile) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Can't close/unlock pid file");
		goto clean;
	}

	ret = HGD_OK;
clean:
	free(path);

	return (ret);
}

/*
 * checks to see if a component is running.
 *
 * if success is returned, then you trust *running, else
 * you can not be sure.
 */
int
hgd_check_component_status(char *component, int *running)
{
	char			*path = NULL, pid_str[HGD_PID_STR_SZ];
	int			 ret = HGD_FAIL;
	FILE			*pidfile = NULL;
	pid_t			 cpid;

	*running = 0;

	xasprintf(&path, "%s/%s.pid", state_path, component);

	if ((pidfile = fopen(path, "r")) == NULL) {
		/* thats fine, means the component isnt running */
		DPRINTF(HGD_D_INFO, "pidfile %s missing, not running",
		    path);
		ret = HGD_OK;
		goto clean;
	}

	if (fgets(pid_str, HGD_PID_STR_SZ, pidfile) == 0) {
		DPRINTF(HGD_D_ERROR, "Can't read pid: %s", SERROR);
		goto clean;
	}

	cpid = atoi(pid_str);
	if (cpid == 0) {
		DPRINTF(HGD_D_ERROR, "pid not found in pid file");
		goto clean;
	}

	/* funky hack to decide if a process is running */
	switch (kill(cpid, 0)) {
	case 0:
		*running = 1;
		break;
	case ESRCH:
		/* stale pid file */
		DPRINTF(HGD_D_ERROR, "stale PID file");
		goto clean;
		break;
	default:
		DPRINTF(HGD_D_ERROR, "Can't determine if %s is running: %s",
		    hgd_component, SERROR);
		goto clean;
		break;
	};

	ret = HGD_OK;
clean:
	free(path);

	if (pidfile != NULL)
		fclose(pidfile);

	return (ret);
}
