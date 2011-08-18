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

#include "config.h"
#ifdef HAVE_PYTHON
#include <Python.h> /* defines _GNU_SOURCE */
#else
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "config.h"
#include "hgd.h"
#include "mplayer.h"
#include "py.h"
#include "db.h"

char			*mplayer_fifo_path = 0;

int
hgd_init_mplayer_globals()
{
	xasprintf(&mplayer_fifo_path, "%s/%s",
	    state_path, HGD_MPLAYER_PIPE_NAME);

	return (HGD_OK);
}

int
hgd_free_mplayer_globals()
{
	if (mplayer_fifo_path)
		free(mplayer_fifo_path);
	mplayer_fifo_path = 0;

	return (HGD_OK);
}

int
hgd_mplayer_pipe_send(char *what)
{
	FILE			*pipe = NULL;
	int			 ret = HGD_FAIL;

	if ((pipe = fopen(mplayer_fifo_path, "w")) == NULL) {
		DPRINTF(HGD_D_ERROR,
		    "Can't open mplayer pipe, is a track playing?\n");
		goto clean;
	}

	if (fwrite(what, strlen(what), 1, pipe) == 0) {
		if (ferror(pipe))
			DPRINTF(HGD_D_ERROR,
			    "Failed to write to pipe: %s", SERROR);
		goto clean;
	}

	ret = HGD_OK;
clean:
	if (pipe)
		fclose(pipe);

	return (ret);
}

/*
 * make a fifo that mplayer can take commands from
 */
int
hgd_make_mplayer_input_fifo()
{
	if (mkfifo(mplayer_fifo_path, 0600) < 0) {
		/* pipe should not exist, but no harm if it does */
		if (errno != EEXIST) {
			DPRINTF(HGD_D_WARN,
			    "Failed to create mplayer input fifo: %s", SERROR);
			return (HGD_FAIL);
		}
	}

	return (HGD_OK);
}

int
hgd_play_track(struct hgd_playlist_item *t, uint8_t purge_fs, uint8_t purge_db)
{
	int			status = 0, pid, ret = HGD_FAIL;
	char			*pid_path = 0, *pipe_arg = 0;
	FILE			*pid_file;
	struct flock		fl;

	fl.l_type   = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
	fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
	fl.l_start  = 0;        /* Offset from l_whence         */
	fl.l_len    = 0;        /* length, 0 = to EOF           */
	fl.l_pid    = getpid(); /* our PID                      */

	DPRINTF(HGD_D_INFO, "Playing '%s' for '%s'", t->filename, t->user);
	if (hgd_mark_playing(t->id) == HGD_FAIL)
		goto clean;

	/* we will write away child pid */
	xasprintf(&pid_path, "%s/%s", state_path, HGD_MPLAYER_PID_NAME);

	pid_file = fopen(pid_path, "w");
	if (pid_file == NULL) {
		DPRINTF(HGD_D_ERROR, "Can't open '%s'", pid_path);
		goto clean;
	}

	if (fcntl(fileno(pid_file), F_SETLKW, &fl) == -1) {
		DPRINTF(HGD_D_ERROR, "failed to get lock on pid file");
		goto clean;
	}

	if (chmod(pid_path, S_IRUSR | S_IWUSR) != 0)
		DPRINTF(HGD_D_WARN, "Can't secure mplayer pid file");

#ifdef HAVE_PYTHON
	hgd_execute_py_hook("pre_play");
#endif

	if (hgd_make_mplayer_input_fifo() != HGD_OK)
		goto clean;

	xasprintf(&pipe_arg, "file=%s", mplayer_fifo_path);

	pid = fork();
	if (!pid) {

		/* close stdin, or mplayer catches keyboard shortcuts */
		fclose(stdin);

		/* child - your the d00d who will play this track */
		execlp("mplayer", "mplayer", "-really-quiet", "-slave",
		    "-input", pipe_arg, t->filename,
		    (char *) NULL);

		/* if we get here, the shit hit the fan with execlp */
		DPRINTF(HGD_D_ERROR, "execlp() failed");
		hgd_exit_nicely(); /* child should always exit */
	} else {
		DPRINTF(HGD_D_INFO, "Mplayer spawned: pid=%d", pid);
		fprintf(pid_file, "%d\n%d", pid, t->id);

		fl.l_type = F_UNLCK;  /* set to unlock same region */

		if (fcntl(fileno(pid_file), F_SETLK, &fl) == -1) {
			DPRINTF(HGD_D_ERROR, "failed to get lock on pid file");
			goto clean;
		}

		fclose(pid_file);
		DPRINTF(HGD_D_INFO, "Waiting for mplayer to finish: pid=%d", pid);
		if (waitpid(pid, &status, 0) < 0) {
			/* it is ok for this to fail if we are restarting */
			if (restarting || dying) {
				kill(pid, SIGINT);
			}
			DPRINTF(HGD_D_WARN, "Could not wait(): %s", SERROR);
		}

		/* unlink mplayer pid path */
		DPRINTF(HGD_D_DEBUG, "Deleting mplayer pid file");
		if (unlink(pid_path) < 0) {
			DPRINTF(HGD_D_WARN, "Can't unlink '%s'", pid_path);
		}

		/* unlink input pipe */
		if (unlink(mplayer_fifo_path) < 0) {
			DPRINTF(HGD_D_WARN,
			    "Could not unlink mplayer input fifo: %s", SERROR);
		}

		/* unlink media (but not if restarting, we replay the track) */
		if ((!restarting) && (!dying)
		    && (purge_fs) && (unlink(t->filename) < 0)) {
			DPRINTF(HGD_D_DEBUG,
			    "Deleting finished: %s", t->filename);
			DPRINTF(HGD_D_WARN, "Can't unlink '%s'", pid_path);
		}
	}
#ifdef HAVE_PYTHON
	hgd_execute_py_hook("post_play");
#endif

	DPRINTF(HGD_D_DEBUG, "Finished playing (exit %d)", status);

	/* if we are restarting, we replay the track on restart */
	if ((!restarting) && (!dying) &&
	    (hgd_mark_finished(t->id, purge_db) == HGD_FAIL))
		DPRINTF(HGD_D_WARN,
		    "Could not purge/mark finished -- trying to continue");

	ret = HGD_OK;

clean:
	if (pipe_arg)
		free(pipe_arg);
	if (pid_path)
		free(pid_path);

	return (ret);
}
