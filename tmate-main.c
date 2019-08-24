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
#include <sys/syslog.h>
#include <sched.h>
#include <signal.h>
#include "tmate.h"

struct tmate_session _tmate_session, *tmate_session = &_tmate_session;

extern FILE *log_file;

static char *cmdline;
static char *cmdline_end;
static int dev_urandom_fd;

extern int server_create_socket(void);
extern int client_connect(struct event_base *base, const char *path, int start_server);

struct tmate_settings _tmate_settings = {
	.keys_dir        	= TMATE_SSH_DEFAULT_KEYS_DIR,
	.authorized_keys_path 	= NULL,
	.ssh_port        	= TMATE_SSH_DEFAULT_PORT,
	.websocket_hostname  	= NULL,
	.bind_addr	 	= NULL,
	.websocket_port      	= TMATE_DEFAULT_WEBSOCKET_PORT,
	.tmate_host      	= NULL,
	.log_level      	= LOG_NOTICE,
	.use_proxy_protocol	= false,
	.use_syslog      	= false,
};

struct tmate_settings *tmate_settings = &_tmate_settings;

void tmate_get_random_bytes(void *buffer, ssize_t len)
{
	if (read(dev_urandom_fd, buffer, len) != len)
		tmate_fatal("Cannot read from /dev/urandom");
}

long tmate_get_random_long(void)
{
	long val;
	tmate_get_random_bytes(&val, sizeof(val));
	return val;
}

#define RS_BUF_SIZE 256

struct random_stream {
	char bytes[RS_BUF_SIZE];
	off_t pos;
};

static void random_stream_init(struct random_stream *rs)
{
	rs->pos = RS_BUF_SIZE;
}

static char *random_stream_get(struct random_stream *rs, size_t count)
{
	char *ret;

	if (count > RS_BUF_SIZE) {
		tmate_fatal("buffer too small");
	}

	if (rs->pos + count > RS_BUF_SIZE) {
		tmate_get_random_bytes(rs->bytes, RS_BUF_SIZE);
		rs->pos = 0;
	}


	ret = &rs->bytes[rs->pos];
	rs->pos += count;
	return ret;
}


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
	fprintf(stderr, "usage: tmate-ssh-server [-b ip] [-h hostname] [-k keys_dir] [-a authorized_keys_path] [-p port] [-w websocket_hostname] [-q websocket_port] [-x] [-s] [-v]\n");
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
		tmate_warn("cannot lookup hostname: %s", gai_strerror(gai_result));
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

	while ((opt = getopt(argc, argv, "b:h:k:a:p:w:q:xsv")) != -1) {
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
		case 'a':
			tmate_settings->authorized_keys_path = xstrdup(optarg);
			break;
		case 'p':
			tmate_settings->ssh_port = atoi(optarg);
			break;
		case 'w':
			tmate_settings->websocket_hostname = xstrdup(optarg);
			break;
		case 'q':
			tmate_settings->websocket_port = atoi(optarg);
			break;
		case 'x':
			tmate_settings->use_proxy_protocol = true;
			break;
		case 's':
			tmate_settings->use_syslog = true;
			break;
		case 'v':
			tmate_settings->log_level++;
			break;
		default:
			usage();
			return 1;
		}
	}

	init_logging("tmate-remote-tmux",
		     tmate_settings->use_syslog, tmate_settings->log_level);

	setup_locale();

	if (!tmate_settings->tmate_host)
		tmate_settings->tmate_host = get_full_hostname();

	cmdline = *argv;
	cmdline_end = *envp;

	tmate_preload_trace_lib();

	if ((dev_urandom_fd = open("/dev/urandom", O_RDONLY)) < 0)
		tmate_fatal("Cannot open /dev/urandom");

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

static char tmate_token_digits[] = "abcdefghijklmnopqrstuvwxyz"
				   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				   "0123456789";
#define NUM_DIGITS (sizeof(tmate_token_digits) - 1)

static char *get_random_token(void)
{
	struct random_stream rs;
	char *token = xmalloc(TMATE_TOKEN_LEN + 1);
	int i;
	unsigned char c;

	random_stream_init(&rs);

	for (i = 0; i < TMATE_TOKEN_LEN; i++) {
		do {
			c = *random_stream_get(&rs, 1);
		} while (c >= NUM_DIGITS);

		token[i] = tmate_token_digits[c];
	}

	token[i] = 0;

	return token;
}

void set_session_token(struct tmate_session *session,
		       const char *token)
{
	char *path;
	session->session_token = xstrdup(token);
	xasprintf(&path, TMATE_WORKDIR "/sessions/%s", token);
	socket_path = path;

	memset(cmdline, 0, cmdline_end - cmdline);
	sprintf(cmdline, "tmate-ssh-server [%s] %s %s",
		session->session_token,
		session->ssh_client.role == TMATE_ROLE_DAEMON ? "(daemon)" : "(pty client)",
		session->ssh_client.ip_address);
}

static void create_session_ro_symlink(struct tmate_session *session)
{
	char *tmp, *token, *session_ro_path;

#ifdef DEVENV
	tmp = xstrdup("READONLYTOKENFORDEVENV000");
#else
	tmp = get_random_token();
#endif
	xasprintf(&token, "ro-%s", tmp);
	free(tmp);

	session->session_token_ro = token;

	xasprintf(&session_ro_path, TMATE_WORKDIR "/sessions/%s",
		  session->session_token_ro);

	unlink(session_ro_path);
	if (symlink(session->session_token, session_ro_path) < 0)
		tmate_fatal("Cannot create read-only symlink");
	free(session_ro_path);
}

static int validate_token(const char *token)
{
	int len;
	int i;

	if (!memcmp("ro-", token, 3))
		token += 3;

	len = strlen(token);

	if (len != TMATE_TOKEN_LEN)
		return -1;

	for (i = 0; i < len; i++) {
		if (!strchr(tmate_token_digits, token[i]))
			return -1;
	}

	return 0;
}

static void random_sleep(void)
{
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 50000000 + (tmate_get_random_long() % 150000000);
	nanosleep(&ts, NULL);
}

static void ssh_echo(struct tmate_ssh_client *ssh_client,
		     const char *str)
{
	ssh_channel_write(ssh_client->channel, str, strlen(str));
}

#define BAD_TOKEN_ERROR_STR						\
"Invalid session token"						 "\r\n"

#define EXPIRED_TOKEN_ERROR_STR						\
"Invalid or expired session token"				 "\r\n"

static void close_fds_except(int *fd_to_preserve, int num_fds)
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

static void jail(void)
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
		tmate_fatal("Need root privileges");

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

	tmate_info("Dropped priviledges to %s (%d,%d), jailed in %s",
		   TMATE_JAIL_USER, uid, gid, TMATE_WORKDIR "/jail");
}

static void setup_ncurse(int fd, const char *name)
{
	int error;
	if (setupterm((char *)name, fd, &error) != OK)
		tmate_fatal("Cannot setup terminal");
}

static void handle_sigterm(__unused int sig)
{
	request_server_termination();
}

static void tmate_spawn_daemon(struct tmate_session *session)
{
	struct tmate_ssh_client *client = &session->ssh_client;
	char *token;

#ifdef DEVENV
	token = xstrdup("SUPERSECURETOKENFORDEVENV");
#else
	token = get_random_token();
#endif

	set_session_token(session, token);
	free(token);

	tmate_notice("Spawning daemon for %s at %s (%s)",
		     client->username, client->ip_address, client->pubkey);

	session->tmux_socket_fd = server_create_socket();
	if (session->tmux_socket_fd < 0)
		tmate_fatal("Cannot create to the tmux socket");

	create_session_ro_symlink(session);

	/*
	 * Needed to initialize the database used in tty-term.c.
	 * We won't have access to it once in the jail.
	 */
	setup_ncurse(STDOUT_FILENO, "screen-256color");

	tmate_daemon_init(session);

	close_fds_except((int[]){session->tmux_socket_fd,
				 ssh_get_fd(session->ssh_client.session),
				 log_file ? fileno(log_file) : -1,
				 session->websocket_fd}, 4);

	jail();
	event_reinit(session->ev_base);

	tmux_server_init();
	signal(SIGTERM, handle_sigterm);
	server_start(session->ev_base, -1, NULL);
	/* never reached */
}

static void tmate_spawn_pty_client(struct tmate_session *session)
{
	struct tmate_ssh_client *client = &session->ssh_client;
	char *argv_rw[] = {(char *)"attach", NULL};
	char *argv_ro[] = {(char *)"attach", (char *)"-r", NULL};
	char **argv = argv_rw;
	int argc = 1;
	char *token = client->username;
	struct stat fstat;
	int slave_pty;
	int ret;

	if (validate_token(token) < 0) {
		ssh_echo(client, BAD_TOKEN_ERROR_STR);
		tmate_fatal("Invalid token");
	}

	set_session_token(session, token);

	tmate_notice("Spawning pty client for %s (%s)",
		     client->ip_address, client->pubkey);

	session->tmux_socket_fd = client_connect(session->ev_base, socket_path, 0);
	if (session->tmux_socket_fd < 0) {
		random_sleep(); /* for making timing attacks harder */
		ssh_echo(client, EXPIRED_TOKEN_ERROR_STR);
		tmate_fatal("Expired token");
	}

	/*
	 * If we are connecting through a symlink, it means that we are a
	 * readonly client.
	 * 1) We mark the client as CLIENT_READONLY on the server
	 * 2) We prevent any input (aside from the window size) to go through
	 *    to the server.
	 */
	session->readonly = false;
	if (lstat(socket_path, &fstat) < 0)
		tmate_fatal("Cannot fstat()");
	if (S_ISLNK(fstat.st_mode)) {
		session->readonly = true;
		argv = argv_ro;
		argc = 2;
	}

	if (openpty(&session->pty, &slave_pty, NULL, NULL, NULL) < 0)
		tmate_fatal("Cannot allocate pty");

	dup2(slave_pty, STDIN_FILENO);
	dup2(slave_pty, STDOUT_FILENO);
	dup2(slave_pty, STDERR_FILENO);

	setup_ncurse(slave_pty, "screen-256color");

	tmate_client_pty_init(session);

	/* the unused session->websocket_fd will get closed automatically */

	close_fds_except((int[]){STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
				 session->tmux_socket_fd,
				 ssh_get_fd(session->ssh_client.session),
				 session->pty, log_file ? fileno(log_file) : -1}, 7);
	jail();
	event_reinit(session->ev_base);

	ret = client_main(session->ev_base, argc, argv,
			  CLIENT_UTF8 | CLIENT_256COLOURS, NULL);
	tmate_flush_pty(session);
	exit(ret);
}

static void tmate_spawn_exec(struct tmate_session *session)
{
	close_fds_except((int[]){ssh_get_fd(session->ssh_client.session),
				 log_file ? fileno(log_file) : -1,
				 session->websocket_fd}, 3);
	jail();
	event_reinit(session->ev_base);

	tmate_client_exec_init(session);

	if (event_base_dispatch(session->ev_base) < 0)
		tmate_fatal("Cannot run event loop");
	exit(0);
}

void tmate_spawn(struct tmate_session *session)
{
	switch (session->ssh_client.role) {
	case TMATE_ROLE_DAEMON:		tmate_spawn_daemon(session);		break;
	case TMATE_ROLE_PTY_CLIENT:	tmate_spawn_pty_client(session);	break;
	case TMATE_ROLE_EXEC:		tmate_spawn_exec(session);		break;
	}
}
