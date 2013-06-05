#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "tmate.h"

struct event_base *ev_base;

struct options	 global_options;	/* server options */
struct options	 global_s_options;	/* session options */
struct options	 global_w_options;	/* window options */
struct environ	 global_environ;

struct event_base *ev_base;

char		*cfg_file;
char		*shell_cmd;
int		 debug_level;
time_t		 start_time;
char	 	 socket_path[MAXPATHLEN];
int		 login_shell;
char		*environ_path;
pid_t		 environ_pid = -1;
int		 environ_session_id = -1;

void
setblocking(int fd, int state)
{
	int mode;

	if ((mode = fcntl(fd, F_GETFL)) != -1) {
		if (!state)
			mode |= O_NONBLOCK;
		else
			mode &= ~O_NONBLOCK;
		fcntl(fd, F_SETFL, mode);
	}
}

const char*
get_full_path(const char *wd, const char *path)
{
	static char	newpath[MAXPATHLEN];
	char		oldpath[MAXPATHLEN];

	if (getcwd(oldpath, sizeof oldpath) == NULL)
		return (NULL);
	if (chdir(wd) != 0)
		return (NULL);
	if (realpath(path, newpath) != 0)
		return (NULL);
	chdir(oldpath);
	return (newpath);
}

static void usage(void)
{
	fprintf(stderr, "usage: tmate-server [-p PORT]\n");
}

int main(int argc, char **argv)
{
	int opt;
	int port = 22;
	char *log_path = NULL; /* stderr */

	strcpy(socket_path, "/tmp/tmate-slave");

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

	log_open(debug_level, log_path);
	tmate_ssh_server_main(port);
	return 0;
}

struct tmate_encoder *tmate_encoder;

void tmate_spawn_slave_server(struct tmate_ssh_client *client)
{
	int quiet = 0;
	int flags = IDENTIFY_UTF8 | IDENTIFY_256COLOURS;
	struct tmate_encoder encoder;
	struct tmate_decoder decoder;

	tmate_debug("Spawn tmux slave server");

	ev_base = osdep_event_init();

	tmate_encoder_init(&encoder);
	tmate_decoder_init(&decoder);
	tmate_encoder = &encoder;

	tmate_ssh_client_init(client, &encoder, &decoder);

	environ_init(&global_environ);

	options_init(&global_options, NULL);
	options_table_populate_tree(server_options_table, &global_options);
	options_set_number(&global_options, "quiet", quiet);

	options_init(&global_s_options, NULL);
	options_table_populate_tree(session_options_table, &global_s_options);

	options_init(&global_w_options, NULL);
	options_table_populate_tree(window_options_table, &global_w_options);

	if (flags & IDENTIFY_UTF8) {
		options_set_number(&global_s_options, "status-utf8", 1);
		options_set_number(&global_s_options, "mouse-utf8", 1);
		options_set_number(&global_w_options, "utf8", 1);
	}

	server_start(0, NULL);
	/* never reached */
}

void tmate_spawn_slave_client(struct tmate_ssh_client *ssh_client)
{
	struct tmate_ssh_client_pty _client;
	struct tmate_ssh_client_pty *client = &_client;
	int slave_pty;
	int ret;
	char *argv[] = {(char *)"attach", NULL};

	client->session = ssh_client->session;
	client->channel = ssh_client->channel;
	client->winsize_pty = ssh_client->winsize_pty;

	tmate_debug("Spawn tmux slave client");

	ev_base = osdep_event_init();

	if (openpty(&client->pty, &slave_pty, NULL, NULL, NULL) < 0)
		tmate_fatal("Cannot allocate pty");

	/* setsid(); */
	/* ioctl(slave_pty, TIOCSCTTY, NULL); */

	dup2(slave_pty, STDIN_FILENO);
	dup2(slave_pty, STDOUT_FILENO);
	stderr = stdout;
	close(slave_pty);

	tmate_ssh_client_pty_init(client);

	ret = client_main(1, argv, IDENTIFY_UTF8 | IDENTIFY_256COLOURS);
	tmate_flush_pty(client);
	exit(ret);
}
