#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <sys/stat.h>
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
#include "tmate.h"

struct tmate_decoder *tmate_decoder;
struct tmate_encoder *tmate_encoder;
int tmux_socket_fd;
const char *tmate_session_token;
const char *tmate_session_token_ro;

extern FILE *log_file;

static char *cmdline;
static char *cmdline_end;
static int dev_urandom_fd;

extern int server_create_socket(void);
extern int client_connect(char *path, int start_server);

struct tmate_settings tmate_settings = {
	.keys_dir        = TMATE_SSH_DEFAULT_KEYS_DIR,
	.ssh_port        = TMATE_SSH_DEFAULT_PORT,
	.master_hostname = TMATE_DEFAULT_MASTER_HOST,
	.master_port     = TMATE_DEFAULT_MASTER_PORT,
	.tmate_host      = NULL,
	.log_level       = LOG_NOTICE,
	.use_syslog      = false,
};

static void usage(void)
{
	fprintf(stderr, "usage: tmate-slave [-k keys_dir] [-p port] [-m master_hostname] [-q master_port] [-s] [-v]\n");
}

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

int main(int argc, char **argv, char **envp)
{
	int opt;

	while ((opt = getopt(argc, argv, "k:p:lvm:q:")) != -1) {
		switch (opt) {
		case 'p':
			tmate_settings.ssh_port = atoi(optarg);
			break;
		case 'k':
			tmate_settings.keys_dir = xstrdup(optarg);
			break;
		case 's':
			tmate_settings.use_syslog = true;
			break;
		case 'v':
			tmate_settings.log_level++;
			break;
		case 'm':
			tmate_settings.master_hostname = xstrdup(optarg);
			break;
		case 'q':
			tmate_settings.master_port = atoi(optarg);
			break;
		case 'h':
			tmate_settings.tmate_host = xstrdup(optarg);
			break;
		default:
			usage();
			return 1;
		}
	}

	if (!tmate_settings.tmate_host) {
		char hostname[255];
		if (gethostname(hostname, sizeof(hostname)) < 0)
			tmate_fatal("cannot get hostname");
		tmate_settings.tmate_host = xstrdup(hostname);
	}

	cmdline = *argv;
	cmdline_end = *envp;

	init_logging("tmate-ssh",
		     tmate_settings.use_syslog, tmate_settings.log_level);

	tmate_preload_trace_lib();

	if ((dev_urandom_fd = open("/dev/urandom", O_RDONLY)) < 0)
		tmate_fatal("Cannot open /dev/urandom");

	if ((mkdir(TMATE_WORKDIR, 0700)             < 0 && errno != EEXIST) ||
	    (mkdir(TMATE_WORKDIR "/sessions", 0700) < 0 && errno != EEXIST) ||
	    (mkdir(TMATE_WORKDIR "/jail", 0700)     < 0 && errno != EEXIST))
		tmate_fatal("Cannot prepare session in " TMATE_WORKDIR);

	tmate_ssh_server_main(tmate_settings.keys_dir, tmate_settings.ssh_port);
	return 0;
}

static char tmate_token_digits[] = "abcdefghijklmnopqrstuvwxyz"
				   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				   "0123456789";
#define NUM_DIGITS (sizeof(tmate_token_digits) - 1)

static char *get_random_token(void)
{
	int i;
	char *token = xmalloc(TMATE_TOKEN_LEN + 1);

	tmate_get_random_bytes(token, TMATE_TOKEN_LEN);
	for (i = 0; i < TMATE_TOKEN_LEN; i++)
		token[i] = tmate_token_digits[token[i] % NUM_DIGITS];
	token[i] = 0;

	return token;
}

static void set_session_token(struct tmate_ssh_client *client,
			      const char *token)
{
	tmate_session_token = xstrdup(token);
	strcpy(socket_path, TMATE_WORKDIR "/sessions/");
	strcat(socket_path, token);

	memset(cmdline, 0, cmdline_end - cmdline);
	sprintf(cmdline, "tmate-slave [%s] %s %s",
		tmate_session_token,
		client->role == TMATE_ROLE_SERVER ? "(server)" : "(client)",
		client->ip_address);
}
static void create_session_ro_symlink(void)
{
	char session_ro_path[MAXPATHLEN];

	tmate_session_token_ro = get_random_token();
#ifdef DEVENV
	strcpy((char *)tmate_session_token_ro, "READONLYTOKENFORDEVENV000");
#endif

	strcpy(session_ro_path, TMATE_WORKDIR "/sessions/");
	strcat(session_ro_path, tmate_session_token_ro);

	unlink(session_ro_path);
	if (symlink(tmate_session_token, session_ro_path) < 0)
		tmate_fatal("Cannot create read-only symlink");
}

static int validate_token(const char *token)
{
	int len = strlen(token);
	int i;

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
"  "								 "\r\n" \
"  Dear guest,"							 "\r\n" \
"  "								 "\r\n" \
"  There isn't much I can do without a valid session token."	 "\r\n" \
"  Feel free to reach out if you are having issues."		 "\r\n" \
"  "								 "\r\n" \
"  Thanks,"							 "\r\n" \
"  Nico"							 "\r\n" \
"  "								 "\r\n"

#define EXPIRED_TOKEN_ERROR_STR						\
"  "								 "\r\n" \
"  Dear guest,"							 "\r\n" \
"  "								 "\r\n" \
"  The provided session token is invalid, or has expired."	 "\r\n" \
"  Feel free to reach out if you are having issues."		 "\r\n" \
"  "								 "\r\n" \
"  Thanks,"							 "\r\n" \
"  Nico"							 "\r\n" \
"  "								 "\r\n"

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

	/*
	 * We are already in a new PID namespace (from the server fork).
	 */

	if (chroot(TMATE_WORKDIR "/jail") < 0)
		tmate_fatal("Cannot chroot()");

	if (chdir("/") < 0)
		tmate_fatal("Cannot chdir()");

	if (setgroups(1, (gid_t[]){gid}) < 0)
		tmate_fatal("Cannot setgroups()");

	if (setresuid(uid, uid, uid) < 0)
		tmate_fatal("Cannot setresuid()");

	if (setresuid(gid, gid, gid) < 0)
		tmate_fatal("Cannot setresgid()");

	if (nice(1) < 0)
		tmate_fatal("Cannot nice()");

	tmate_debug("Dropped priviledges to %s (%d,%d)",
		    TMATE_JAIL_USER, uid, gid);
}

static void setup_ncurse(int fd, const char *name)
{
	int error;
	if (setupterm((char *)name, fd, &error) != OK)
		tmate_fatal("Cannot setup terminal");
}

static void tmate_spawn_slave_server(struct tmate_ssh_client *client)
{
	char *token;
	struct tmate_encoder encoder;
	struct tmate_decoder decoder;

	token = get_random_token();
#ifdef DEVENV
	strcpy(token, "SUPERSECURETOKENFORDEVENV");
#endif

	set_session_token(client, token);
	free(token);

	tmate_debug("Spawning slave server for %s at %s (%s)",
		    client->username, client->ip_address, client->pubkey);

	tmux_socket_fd = server_create_socket();
	if (tmux_socket_fd < 0)
		tmate_fatal("Cannot create to the tmux socket");

	create_session_ro_symlink();

	/*
	 * Needed to initialize the database used in tty-term.c.
	 * We won't have access to it once in the jail.
	 */
	setup_ncurse(STDOUT_FILENO, "screen-256color");

	close_fds_except((int[]){tmux_socket_fd,
				 ssh_get_fd(client->session),
				 log_file ? fileno(log_file) : -1}, 3);

	jail();

	ev_base = osdep_event_init();

	tmate_encoder_init(&encoder);
	tmate_decoder_init(&decoder);
	tmate_encoder = &encoder;
	tmate_decoder = &decoder;

	tmate_ssh_client_init(client, &encoder, &decoder);

	tmux_server_init(IDENTIFY_UTF8 | IDENTIFY_256COLOURS);
	/* never reached */
}

static void tmate_spawn_slave_client(struct tmate_ssh_client *client)
{
	char *argv_rw[] = {(char *)"attach", NULL};
	char *argv_ro[] = {(char *)"attach", (char *)"-r", NULL};
	char **argv = argv_rw;
	int argc = 1;
	char *token = client->username;
	struct stat fstat;
	int slave_pty;
	int ret;

	/* the "ro-" part is just sugar, we don't care about it */
	if (!memcmp("ro-", token, 3))
		token += 3;

	if (validate_token(token) < 0) {
		ssh_echo(client, BAD_TOKEN_ERROR_STR);
		tmate_fatal("Invalid token");
	}

	set_session_token(client, token);

	tmate_debug("Spawning slave client for %s (%s)",
		    client->ip_address, client->pubkey);

	tmux_socket_fd = client_connect(socket_path, 0);
	if (tmux_socket_fd < 0) {
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
	client->readonly = 0;
	if (lstat(socket_path, &fstat) < 0)
		tmate_fatal("Cannot fstat()");
	if (S_ISLNK(fstat.st_mode)) {
		client->readonly = 1;
		argv = argv_ro;
		argc = 2;
	}

	if (openpty(&client->pty, &slave_pty, NULL, NULL, NULL) < 0)
		tmate_fatal("Cannot allocate pty");

	dup2(slave_pty, STDIN_FILENO);
	dup2(slave_pty, STDOUT_FILENO);
	dup2(slave_pty, STDERR_FILENO);

	setup_ncurse(slave_pty, "screen-256color");
	close_fds_except((int[]){STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
				 tmux_socket_fd, ssh_get_fd(client->session),
				 client->pty, log_file ? fileno(log_file) : -1}, 7);
	jail();

	ev_base = osdep_event_init();

	tmate_ssh_client_pty_init(client);

	ret = client_main(argc, argv, IDENTIFY_UTF8 | IDENTIFY_256COLOURS);
	tmate_flush_pty(client);
	exit(ret);
}

void tmate_spawn_slave(struct tmate_ssh_client *client)
{
	if (client->role == TMATE_ROLE_SERVER)
		tmate_spawn_slave_server(client);
	else
		tmate_spawn_slave_client(client);
}
