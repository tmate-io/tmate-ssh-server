#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "tmate.h"

static void usage(void)
{
	fprintf(stderr, "usage: tmate-slave [-p PORT]\n");
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
	struct tmate_encoder encoder;
	struct tmate_decoder decoder;

	tmate_debug("Spawn tmux slave server");

	ev_base = osdep_event_init();

	tmate_encoder_init(&encoder);
	tmate_decoder_init(&decoder);
	tmate_encoder = &encoder;

	tmate_ssh_client_init(client, &encoder, &decoder);

	tmux_server_init(IDENTIFY_UTF8 | IDENTIFY_256COLOURS);
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

	dup2(slave_pty, STDIN_FILENO);
	dup2(slave_pty, STDOUT_FILENO);
	stderr = stdout;
	close(slave_pty);

	tmate_ssh_client_pty_init(client);

	ret = client_main(1, argv, IDENTIFY_UTF8 | IDENTIFY_256COLOURS);
	tmate_flush_pty(client);
	exit(ret);
}
