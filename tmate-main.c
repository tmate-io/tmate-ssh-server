#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#ifdef HAVE_CURSES_H
#include <curses.h>
#else
#include <ncurses.h>
#endif
#include <term.h>
#include <time.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include "tmate.h"

static char *cmdline;
static char *cmdline_end;

struct tmate_settings _tmate_settings = {
	.keys_dir        	= TMATE_SSH_DEFAULT_KEYS_DIR,
	.ssh_port        	= TMATE_SSH_DEFAULT_PORT,
	.ssh_port_advertized    = -1,
	.websocket_hostname  	= NULL,
	.bind_addr	 	= NULL,
	.websocket_port      	= TMATE_DEFAULT_WEBSOCKET_PORT,
	.tmate_host      	= NULL,
	.log_level      	= LOG_INFO,
	.use_proxy_protocol	= false,
};

struct tmate_settings *tmate_settings = &_tmate_settings;

extern int server_fd;
extern void server_send_exit(void);
void request_server_termination(void)
{
	if (server_fd) {
		server_send_exit();
	} else
		exit(1);
}

static void usage(void)
{
	fprintf(stderr, "usage: tmate-ssh-server [-b ip] [-h hostname] [-k keys_dir] [-p listen_port] [-q ssh_port_advertized] [-w websocket_hostname] [-z websocket_port] [-x] [-v]\n");
}

static char* get_full_hostname(void)
{
	struct addrinfo hints, *info;
	char hostname[1024];
	int gai_result;
	char *ret;

	if (gethostname(hostname, sizeof(hostname)) < 0)
		tmate_fatal("cannot get hostname");
	hostname[1023] = '\0';

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if ((gai_result = getaddrinfo(hostname, NULL, &hints, &info)) != 0) {
		tmate_info("cannot lookup hostname: %s", gai_strerror(gai_result));
		return xstrdup(hostname);
	}

	ret = xstrdup(info->ai_canonname);

	freeaddrinfo(info);
	return ret;
}
#include <langinfo.h>
#include <locale.h>

static void setup_locale(void)
{
	const char *s;

	if (setlocale(LC_CTYPE, "en_US.UTF-8") == NULL) {
		if (setlocale(LC_CTYPE, "") == NULL)
			tmate_fatal("invalid LC_ALL, LC_CTYPE or LANG");
		s = nl_langinfo(CODESET);
		if (strcasecmp(s, "UTF-8") != 0 &&
		    strcasecmp(s, "UTF8") != 0)
			tmate_fatal("need UTF-8 locale (LC_CTYPE) but have %s", s);
	}

	setlocale(LC_TIME, "");
	tzset();
}

int main(int argc, char **argv, char **envp)
{
	int opt;

	while ((opt = getopt(argc, argv, "b:h:k:p:q:w:z:xv")) != -1) {
		switch (opt) {
		case 'b':
			tmate_settings->bind_addr = xstrdup(optarg);
			break;
		case 'h':
			tmate_settings->tmate_host = xstrdup(optarg);
			break;
		case 'k':
			tmate_settings->keys_dir = xstrdup(optarg);
			break;
		case 'p':
			tmate_settings->ssh_port = atoi(optarg);
			break;
		case 'q':
			tmate_settings->ssh_port_advertized = atoi(optarg);
			break;
		case 'w':
			tmate_settings->websocket_hostname = xstrdup(optarg);
			break;
		case 'z':
			tmate_settings->websocket_port = atoi(optarg);
			break;
		case 'x':
			tmate_settings->use_proxy_protocol = true;
			break;
		case 'v':
			tmate_settings->log_level++;
			break;
		default:
			usage();
			return 1;
		}
	}

	init_logging(tmate_settings->log_level);

	setup_locale();

	if (!tmate_settings->tmate_host)
		tmate_settings->tmate_host = get_full_hostname();

	cmdline = *argv;
	cmdline_end = *envp;

	tmate_preload_trace_lib();
	tmate_catch_sigsegv();
	tmate_init_rand();

	if ((mkdir(TMATE_WORKDIR, 0701)             < 0 && errno != EEXIST) ||
	    (mkdir(TMATE_WORKDIR "/sessions", 0703) < 0 && errno != EEXIST) ||
	    (mkdir(TMATE_WORKDIR "/jail", 0700)     < 0 && errno != EEXIST))
		tmate_fatal("Cannot prepare session in " TMATE_WORKDIR);

	/* The websocket server needs to access the /session dir to rename sockets */
	if ((chmod(TMATE_WORKDIR, 0701)             < 0) ||
	    (chmod(TMATE_WORKDIR "/sessions", 0703) < 0) ||
	    (chmod(TMATE_WORKDIR "/jail", 0700)     < 0))
		tmate_fatal("Cannot prepare session in " TMATE_WORKDIR);

	tmate_ssh_server_main(tmate_session,
			      tmate_settings->keys_dir, tmate_settings->bind_addr, tmate_settings->ssh_port);
	return 0;
}

char *get_socket_path(const char *_token)
{
	char *path;
	char *token = xstrdup(_token);

	for (char *c = token; *c; c++) {
		if (*c == '/' || *c == '.')
			*c = '=';
	}

	xasprintf(&path, TMATE_WORKDIR "/sessions/%s", token);
	free(token);
	return path;
}

void set_session_token(struct tmate_session *session, const char *token)
{
	session->session_token = xstrdup(token);
	socket_path = get_socket_path(token);

	xasprintf((char **)&session->obfuscated_session_token, "%.4s...",
		  session->session_token);

	size_t size = cmdline_end - cmdline;
	memset(cmdline, 0, size);
	snprintf(cmdline, size-1, "tmate-ssh-server [%s] %s %s",
		tmate_session->obfuscated_session_token,
		session->ssh_client.role == TMATE_ROLE_DAEMON ? "(daemon)" : "(pty client)",
		session->ssh_client.ip_address);

	char *log_prefix;
	xasprintf(&log_prefix, "[%s] ", session->obfuscated_session_token);
	set_log_prefix(log_prefix);
	free(log_prefix);
}

void close_fds_except(int *fd_to_preserve, int num_fds)
{
	int fd, i, preserve;

	for (fd = 0; fd < 1024; fd++) {
		preserve = 0;
		for (i = 0; i < num_fds; i++)
			if (fd_to_preserve[i] == fd)
				preserve = 1;

		if (!preserve)
			close(fd);
	}
}

void get_in_jail(void)
{
	struct passwd *pw;
	uid_t uid;
	gid_t gid;

	pw = getpwnam(TMATE_JAIL_USER);
	if (!pw) {
		tmate_fatal("Cannot get the /etc/passwd entry for %s",
			    TMATE_JAIL_USER);
	}
	uid = pw->pw_uid;
	gid = pw->pw_gid;

	if (getuid() != 0)
		tmate_fatal("Need root privileges to create the jail");

	if (chroot(TMATE_WORKDIR "/jail") < 0)
		tmate_fatal("Cannot chroot()");

	if (chdir("/") < 0)
		tmate_fatal("Cannot chdir()");

#ifdef IS_LINUX
	if (unshare(CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET) < 0)
		tmate_fatal("Cannot create new namespace");
#endif

	if (setgroups(1, (gid_t[]){gid}) < 0)
		tmate_fatal("Cannot setgroups()");

#if defined(HAVE_SETRESGID)
	if (setresgid(gid, gid, gid) < 0)
		tmate_fatal("Cannot setresgid() %d", gid);
#elif defined(HAVE_SETREGID)
	if (setregid(gid, gid) < 0)
		tmate_fatal("Cannot setregid()");
#else
	if (setgid(gid) < 0)
		tmate_fatal("Cannot setgid()");
#endif

#if defined(HAVE_SETRESUID)
	if (setresuid(uid, uid, uid) < 0)
		tmate_fatal("Cannot setresuid()");
#elif defined(HAVE_SETREUID)
	if (setreuid(uid, uid) < 0)
		tmate_fatal("Cannot setreuid()");
#else
	if (setuid(uid) < 0)
		tmate_fatal("Cannot setuid()");
#endif

	nice(1);

	tmate_debug("Dropped priviledges to %s (%d,%d), jailed in %s",
		    TMATE_JAIL_USER, uid, gid, TMATE_WORKDIR "/jail");
}

void setup_ncurse(int fd, const char *name)
{
	int error;
	if (setupterm((char *)name, fd, &error) != OK)
		tmate_fatal("Cannot setup terminal");
}

