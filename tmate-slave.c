#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <sys/stat.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#ifdef HAVE_CURSES_H
#include <curses.h>
#else
#include <ncurses.h>
#endif
#include <term.h>
#include "tmate.h"

struct tmate_encoder *tmate_encoder;
int tmux_socket_fd;
const char *tmate_session_token = "main";

static char *cmdline;

extern FILE *log_file;
extern int server_create_socket(void);
extern int client_connect(char *path, int start_server);

static void usage(void)
{
	fprintf(stderr, "usage: tmate-slave [-l logfile] [-p PORT] [-v]\n");
}

int main(int argc, char **argv)
{
	int opt;
	int port = TMATE_DEFAULT_PORT;
	char *log_path = NULL; /* stderr */

	while ((opt = getopt(argc, argv, "p:l:v")) != -1) {
		switch (opt) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'l':
			log_path = optarg;
			break;
		case 'v':
			debug_level++;
			break;
		default:
			usage();
			return 1;
		}
	}

	cmdline = *argv;

	log_open(debug_level, log_path);

	if ((mkdir(TMATE_WORKDIR, 0700)             < 0 && errno != EEXIST) ||
	    (mkdir(TMATE_WORKDIR "/sessions", 0700) < 0 && errno != EEXIST) ||
	    (mkdir(TMATE_WORKDIR "/jail", 0700)     < 0 && errno != EEXIST))
		tmate_fatal("Cannot prepare session in " TMATE_WORKDIR);

	tmate_ssh_server_main(port);
	return 0;
}
static void set_session_token(struct tmate_ssh_client *client,
			      const char *token)
{
	tmate_session_token = xstrdup(token);
	strcpy(socket_path, TMATE_WORKDIR "/sessions/");
	strcat(socket_path, token);

	sprintf(cmdline, "tmate-slave [%s] %s %s",
		tmate_session_token,
		client->ip_address,
		client->role == TMATE_ROLE_SERVER ? "(server)" : "");
}

static char tmate_token_digits[] = "abcdefghijklmnopqrstuvwxyz"
				   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				   "0123456789";
#define NUM_DIGITS (sizeof(tmate_token_digits) - 1)

static char *get_random_token(void)
{
	int i;
	char *token = xmalloc(TMATE_TOKEN_LEN + 1);

	ssh_get_random(token, TMATE_TOKEN_LEN, 0);
	for (i = 0; i < TMATE_TOKEN_LEN; i++)
		token[i] = tmate_token_digits[token[i] % NUM_DIGITS];
	token[i] = 0;

#ifdef DEVENV
	strcpy(token, "SUPERSECURETOKENFORDEVENV");
#endif

	return token;
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
	usleep(50000 + (rand() % 50000));
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
	if (setupterm(name, fd, &error) != OK)
		tmate_fatal("Cannot setup terminal");
}

static void tmate_spawn_slave_server(struct tmate_ssh_client *client)
{
	char *token;
	struct tmate_encoder encoder;
	struct tmate_decoder decoder;

	token = get_random_token();
	set_session_token(client, token);
	free(token);

	tmate_debug("Spawning tmux slave server");

	tmux_socket_fd = server_create_socket();
	if (tmux_socket_fd < 0)
		tmate_fatal("Cannot create to the tmux socket");

	/*
	 * Needed to initialize the database used in tty-term.c.
	 * We won't have access to it once in the jail.
	 */
	setup_ncurse(STDOUT_FILENO, "screen-256color");
	close_fds_except((int[]){tmux_socket_fd, ssh_get_fd(client->session),
				 fileno(log_file)}, 7);
	jail();

	ev_base = osdep_event_init();

	tmate_encoder_init(&encoder);
	tmate_decoder_init(&decoder);
	tmate_encoder = &encoder;

	tmate_ssh_client_init(client, &encoder, &decoder);

	tmux_server_init(IDENTIFY_UTF8 | IDENTIFY_256COLOURS);
	/* never reached */
}

static void tmate_spawn_slave_client(struct tmate_ssh_client *client)
{
	char *argv[] = {(char *)"attach", NULL};
	char *token = client->username;
	int slave_pty;
	int ret;

	if (validate_token(token) < 0) {
		ssh_echo(client, BAD_TOKEN_ERROR_STR);
		tmate_fatal("Bad token");
	}

	set_session_token(client, token);

	tmate_debug("Spawn tmux slave client");

	tmux_socket_fd = client_connect(socket_path, 0);
	if (tmux_socket_fd < 0) {
		random_sleep(); /* for timing attacks */
		ssh_echo(client, EXPIRED_TOKEN_ERROR_STR);
		tmate_fatal("Expired token");
	}

	if (openpty(&client->pty, &slave_pty, NULL, NULL, NULL) < 0)
		tmate_fatal("Cannot allocate pty");

	dup2(slave_pty, STDIN_FILENO);
	dup2(slave_pty, STDOUT_FILENO);
	dup2(slave_pty, STDERR_FILENO);

	setup_ncurse(slave_pty, "screen-256color");
	close_fds_except((int[]){STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
				 tmux_socket_fd, ssh_get_fd(client->session),
				 client->pty, fileno(log_file)}, 7);
	jail();

	ev_base = osdep_event_init();

	tmate_ssh_client_pty_init(client);

	ret = client_main(1, argv, IDENTIFY_UTF8 | IDENTIFY_256COLOURS);
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
