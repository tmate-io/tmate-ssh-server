#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include "tmate.h"

struct tmate_encoder *tmate_encoder;
int tmux_socket_fd;
const char *tmate_session_token;

extern int server_create_socket(void);
extern int client_connect(char *path, int start_server);

static void usage(void)
{
	fprintf(stderr, "usage: tmate-slave [-p PORT]\n");
}

int main(int argc, char **argv)
{
	int opt;
	int port = 22;
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

	log_open(debug_level, log_path);
	tmate_ssh_server_main(port);
	return 0;
}

static void set_session_token(const char *token)
{
	tmate_session_token = xstrdup(token);
	strcpy(socket_path, "/tmp/tmate-slave-");
	strcat(socket_path, token);
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

static void tmate_spawn_slave_server(struct tmate_ssh_client *client)
{
	char *token;
	struct tmate_encoder encoder;
	struct tmate_decoder decoder;

	token = get_random_token();
	set_session_token(token);
	free(token);

	tmate_debug("Spawning tmux slave server %s", tmate_session_token);

	tmux_socket_fd = server_create_socket();
	if (tmux_socket_fd < 0)
		tmate_fatal("Cannot create to the tmux socket");

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

	set_session_token(token);

	tmate_debug("Spawn tmux slave client %s", tmate_session_token);

	ev_base = osdep_event_init();

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
	stderr = stdout;
	close(slave_pty);

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
