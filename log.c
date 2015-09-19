/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm@users.sourceforge.net>
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

void		 log_event_cb(int, const char *);
void		 log_vwrite(int, const char *, va_list);
__dead void	 log_vfatal(const char *, va_list);

void
log_event_cb(unused int severity, const char *msg)
{
	log_warnx("%s", msg);
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
void
log_vwrite(int level, const char *msg, va_list ap)
{
	char	*fmt = NULL;

	const char *token = tmate_session->session_token;

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

/* Log a warning with error string. */
void printflike1
log_warn(const char *msg, ...)
{
	va_list	 ap;
	char	*fmt;

	va_start(ap, msg);
	if (asprintf(&fmt, "%s: %s", msg, strerror(errno)) == -1)
		exit(1);
	log_vwrite(LOG_WARNING, fmt, ap);
	free(fmt);
	va_end(ap);
}

/* Log a warning. */
void printflike1
log_warnx(const char *msg, ...)
{
	va_list	ap;

	va_start(ap, msg);
	log_vwrite(LOG_WARNING, msg, ap);
	va_end(ap);
}

/* Log an informational message. */
void printflike1
log_info(const char *msg, ...)
{
	va_list	ap;

	va_start(ap, msg);
	log_vwrite(LOG_NOTICE, msg, ap);
	va_end(ap);
}

/* Log a debug message. */
void printflike1
log_debug(const char *msg, ...)
{
	va_list	ap;

	va_start(ap, msg);
	log_vwrite(LOG_INFO, msg, ap);
	va_end(ap);
}

/* Log a debug message at level 2. */
void printflike1
log_debug2(const char *msg, ...)
{
	va_list	ap;

	/* Not going with crazy logging on tmux */
#ifndef TMATE_SLAVE
	va_start(ap, msg);
	log_vwrite(LOG_DEBUG, msg, ap);
	va_end(ap);
#endif
}

/* Log a critical error, with error string if necessary, and die. */
__dead void
log_vfatal(const char *msg, va_list ap)
{
	char	*fmt;

	if (errno != 0) {
		if (asprintf(&fmt, "fatal: %s: %s", msg, strerror(errno)) == -1)
			exit(1);
		log_vwrite(LOG_CRIT, fmt, ap);
	} else {
		if (asprintf(&fmt, "fatal: %s", msg) == -1)
			exit(1);
		log_vwrite(LOG_CRIT, fmt, ap);
	}
	free(fmt);

	exit(1);
}

/* Log a critical error, with error string, and die. */
__dead void printflike1
log_fatal(const char *msg, ...)
{
	va_list	ap;

	va_start(ap, msg);
	log_vfatal(msg, ap);
}

/* Log a critical error and die. */
__dead void printflike1
log_fatalx(const char *msg, ...)
{
	va_list	ap;

	errno = 0;
	va_start(ap, msg);
	log_vfatal(msg, ap);
}

void printflike2 tmate_log(int level, const char *msg, ...)
{
	char *fmt;
	va_list	ap;

	if (log_settings.log_level < level)
		return;

	va_start(ap, msg);

	if (asprintf(&fmt, "(tmate) %s", msg) < 0)
		exit(1);
	log_vwrite(level, fmt, ap);
	va_end(ap);

	free(fmt);
}
