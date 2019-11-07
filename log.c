/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicholas.marriott@gmail.com>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "tmux.h"
#include "tmate.h"

FILE *log_file;

static void	log_event_cb(int, const char *);
static void	log_vwrite(const char *, va_list);

static int log_level;
char *log_prefix;

static void
log_event_cb(__unused int severity, const char *msg)
{
	log_debug("%s", msg);
}

/* Increment log level. */
void
log_add_level(void)
{
	log_level++;
}

/* Get log level. */
int
log_get_level(void)
{
	return log_level;
}

void init_logging(int _log_level)
{
	log_level = _log_level;
	log_prefix = xstrdup("");

	log_file = fdopen(dup(STDERR_FILENO), "a");
	if (!log_file)
		exit(1);

	event_set_log_callback(log_event_cb);
}

void set_log_prefix(char *_log_prefix)
{
	free(log_prefix);
	log_prefix = xstrdup(_log_prefix);
}

/* Write a log message. */
__attribute__((__format__(__printf__, 1, 0)))
static void
log_vwrite(const char *msg, va_list ap)
{
	char		*fmt, *out;
	struct timeval	 tv;

	if (log_file == NULL)
		return;

	if (vasprintf(&fmt, msg, ap) == -1)
		exit(1);
	if (stravis(&out, fmt, VIS_OCTAL|VIS_CSTYLE|VIS_TAB|VIS_NL) == -1)
		exit(1);

	if (fprintf(log_file, "%s%s\n", log_prefix, out) == -1)
		exit(1);

	fflush(log_file);

	free(out);
	free(fmt);
}

void
log_emit(int level, const char *msg, ...)
{
	va_list	ap;

	if (log_level < level)
		return;

	va_start(ap, msg);
	log_vwrite(msg, ap);
	va_end(ap);
}

/* Log a critical error with error string and die. */
__attribute__((__format__(__printf__, 1, 0)))
__dead void
fatal(const char *msg, ...)
{
	char	*fmt;
	va_list	 ap;

	va_start(ap, msg);
	if (asprintf(&fmt, "fatal: %s: %s", msg, strerror(errno)) == -1)
		exit(1);
	msg = fmt;
	log_vwrite(msg, ap);
	exit(1);
}

/* Log a critical error and die. */
__attribute__((__format__(__printf__, 1, 0)))
__dead void
fatalx(const char *msg, ...)
{
	char	*fmt;
	va_list	 ap;

	va_start(ap, msg);
	if (asprintf(&fmt, "fatal: %s", msg) == -1)
		exit(1);
	msg = fmt;
	log_vwrite(msg, ap);
	exit(1);
}
