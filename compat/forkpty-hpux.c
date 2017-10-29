/*
 * Copyright (c) 2008 Nicholas Marriott <nicholas.marriott@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdlib.h>
#include <stropts.h>
#include <unistd.h>

#include "tmux.h"

pid_t
forkpty(int *master, char *name, struct termios *tio, struct winsize *ws)
{
	int	replica = -1;
	char   *path;
	pid_t	pid;

	if ((*master = open("/dev/ptmx", O_RDWR|O_NOCTTY)) == -1)
		return (-1);
	if (grantpt(*master) != 0)
		goto out;
	if (unlockpt(*master) != 0)
		goto out;

	if ((path = ptsname(*master)) == NULL)
		goto out;
	if (name != NULL)
		strlcpy(name, path, TTY_NAME_MAX);
	if ((replica = open(path, O_RDWR|O_NOCTTY)) == -1)
		goto out;

	switch (pid = fork()) {
	case -1:
		goto out;
	case 0:
		close(*master);

		setsid();
#ifdef TIOCSCTTY
		if (ioctl(replica, TIOCSCTTY, NULL) == -1)
			fatal("ioctl failed");
#endif

		if (ioctl(replica, I_PUSH, "ptem") == -1)
			fatal("ioctl failed");
		if (ioctl(replica, I_PUSH, "ldterm") == -1)
			fatal("ioctl failed");

		if (tio != NULL && tcsetattr(replica, TCSAFLUSH, tio) == -1)
			fatal("tcsetattr failed");
		if (ioctl(replica, TIOCSWINSZ, ws) == -1)
			fatal("ioctl failed");

		dup2(replica, 0);
		dup2(replica, 1);
		dup2(replica, 2);
		if (replica > 2)
			close(replica);
		return (0);
	}

	close(replica);
	return (pid);

out:
	if (*master != -1)
		close(*master);
	if (replica != -1)
		close(replica);
	return (-1);
}
