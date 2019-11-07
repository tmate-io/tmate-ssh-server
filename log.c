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
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "tmux.h"
#include "tmate.h"

FILE *log_file;

struct logging_settings {
	const char *program_name;
	bool use_syslog;
	int log_level;
};

static struct logging_settings log_settings;

static void	log_event_cb(int, const char *);
static void	log_vwrite(int, const char *, va_list);

static void
log_event_cb(__unused int severity, const char *msg)
{
	log_debug("%s", msg);
}

/* Increment log level. */
void
log_add_level(void)
{
	log_settings.log_level++;
}

/* Get log level. */
int
log_get_level(void)
{
	return (log_settings.log_level);
}

void init_logging(const char *program_name, bool use_syslog, int log_level)
{
	log_settings.log_level = log_level;
	log_settings.use_syslog = use_syslog;
	log_settings.program_name = xstrdup(program_name);

	if (use_syslog) {
		openlog(program_name, LOG_CONS | LOG_PID, LOG_USER);
		setlogmask(LOG_UPTO(log_level));
	} else {
		log_file = fdopen(dup(STDERR_FILENO), "a");
		if (!log_file)
			exit(1);
	}

	event_set_log_callback(log_event_cb);
}

/* Write a log message. */
__attribute__((__format__(__printf__, 2, 0)))
static void
log_vwrite(int level, const char *msg, va_list ap)
{
	char	*fmt = NULL;

	const char *token = tmate_session->obfuscated_session_token;

	if (log_settings.log_level < level)
		return;

	if (token) {
		if (asprintf(&fmt, "[%s] %s", token, msg) < 0)
			exit(1);
		msg = fmt;
	}

	if (log_settings.use_syslog) {
		vsyslog(level, msg, ap);
	} else {
		fprintf(log_file, "<%d> ", level);
		vfprintf(log_file, msg, ap);
		fprintf(log_file, "\n");
		fflush(log_file);
	}

	free(fmt);
}

/* Log a debug message. */
void
log_debug(const char *msg, ...)
{
	va_list	ap;

	va_start(ap, msg);
	log_vwrite(LOG_DEBUG, msg, ap);
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
	log_vwrite(LOG_CRIT, msg, ap);
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
	log_vwrite(LOG_CRIT, msg, ap);
	exit(1);
}

__attribute__((__format__(__printf__, 2, 0)))
void tmate_log(int level, const char *msg, ...)
{
	char *fmt;
	va_list	ap;

	if (log_settings.log_level < level)
		return;

	va_start(ap, msg);

	if (asprintf(&fmt, "(tmate) %s", msg) < 0)
		exit(1);
	msg = fmt;
	log_vwrite(level, msg, ap);
	va_end(ap);

	free(fmt);
}
