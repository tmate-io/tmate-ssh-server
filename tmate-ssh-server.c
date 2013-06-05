#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <event.h>
#include <sys/wait.h>

#include "tmate.h"

#define SSH_GRACE_PERIOD 60

static void client_bootstrap(struct tmate_ssh_client *client)
{
	int auth = 0;
	ssh_session session = client->session;
	ssh_channel channel = NULL;
	ssh_message msg;

	int flag = 1;
	setsockopt(ssh_get_fd(session), IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	alarm(SSH_GRACE_PERIOD);

	tmate_debug("Exchanging DH keys");

	if (ssh_handle_key_exchange(session) < 0)
		tmate_fatal("Error doing the key exchange");

	tmate_debug("Authenticating with public key");

	while (!auth) {
		msg = ssh_message_get(session);
		if (!msg)
			tmate_fatal("Authentification error");

		switch (ssh_message_type(msg)) {
		case SSH_REQUEST_AUTH:
			switch (ssh_message_subtype(msg)) {
			case SSH_AUTH_METHOD_PUBLICKEY:
				if (ssh_message_auth_publickey_state(msg) == SSH_PUBLICKEY_STATE_NONE)
					ssh_message_auth_reply_pk_ok_simple(msg);

				else if (ssh_message_auth_publickey_state(msg) == SSH_PUBLICKEY_STATE_VALID) {
					ssh_message_auth_reply_success(msg, 0);
					auth = 1;
				}
				break;
			case SSH_AUTH_METHOD_NONE:
			default:
				ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PUBLICKEY);
				ssh_message_reply_default(msg);
				break;
			}
			break;
		default:
			ssh_message_reply_default(msg);
		}

		ssh_message_free(msg);
	}

	tmate_debug("Opening channel");

	while (!channel) {
		msg = ssh_message_get(session);
		if (!msg)
			tmate_fatal("Error getting channel");

		if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL_OPEN &&
		    ssh_message_subtype(msg) == SSH_CHANNEL_SESSION) {
			client->channel = channel = ssh_message_channel_request_open_reply_accept(msg);
			if (!channel)
				tmate_fatal("Error getting channel");
		} else {
			ssh_message_reply_default(msg);
		}
		
		ssh_message_free(msg);
	}

	tmate_debug("Getting client type");

	while (1) {
		msg = ssh_message_get(session);
		if (!msg)
			tmate_fatal("Error getting subsystem");

		/* subsystem request */
		if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
		    ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_SUBSYSTEM &&
		    !strcmp(ssh_message_channel_request_subsystem(msg), "tmate")) {
			alarm(0);
			ssh_message_channel_request_reply_success(msg);
			tmate_spawn_slave_server(client);
		}

		/* PTY request */
		else if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
			 ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_PTY) {

			client->winsize_pty.ws_col = ssh_message_channel_request_pty_width(msg);
			client->winsize_pty.ws_row = ssh_message_channel_request_pty_height(msg);
			ssh_message_channel_request_reply_success(msg);
		}

		/* SHELL request */
		else if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
			 ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_SHELL) {
			alarm(0);
			ssh_message_channel_request_reply_success(msg);
			tmate_spawn_slave_client(client);
		}

		/* Default */
		else {
			ssh_message_reply_default(msg);
		}

		ssh_message_free(msg);
	}
}

static void handle_sigchld(void)
{
	int status, child_dead, child_exit_status;
	pid_t pid;

	while ((pid = waitpid(0, &status, WNOHANG)) > 0) {
		child_dead = 0;

		if (WIFEXITED(status)) {
			child_dead = 1;
			child_exit_status = WEXITSTATUS(status);
		}

		if (WIFSIGNALED(status)) {
			child_dead = 1; child_exit_status = EXIT_FAILURE;
		}

		if (!child_dead)
			continue;

		tmate_debug("Child reaped pid=%d exit=%d", pid, child_exit_status);
	} while (pid > 0);
}

static void handle_sigalrm(void)
{
	log_fatal("Connection grace period (%d) passed", SSH_GRACE_PERIOD);
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGCHLD: handle_sigchld(); break;
	case SIGALRM: handle_sigalrm(); break;
	}
}

static void setup_signals(void)
{
	signal(SIGCHLD, signal_handler);
	signal(SIGALRM, signal_handler);
}

static void ssh_log_cb(ssh_session session, int priority,
		    const char *message, void *userdata)
{
	tmate_debug("[%d] %s", priority, message);
}

static struct ssh_callbacks_struct ssh_session_callbacks = {
	.log_function = ssh_log_cb
};

void tmate_ssh_server_main(int port)
{
	struct tmate_ssh_client _client;
	struct tmate_ssh_client *client = &_client;
	ssh_bind bind;
	pid_t pid;

	int verbosity = SSH_LOG_NOLOG;
	//int verbosity = SSH_LOG_PACKET;

	setup_signals();
	ssh_callbacks_init(&ssh_session_callbacks);

	bind = ssh_bind_new();
	if (!bind)
		log_fatal("Cannot initialize ssh");

	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BANNER, SSH_BANNER);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_DSAKEY, "keys/ssh_host_dsa_key");
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY, "keys/ssh_host_rsa_key");

	if (ssh_bind_listen(bind) < 0)
		log_fatal("Error listening to socket: %s\n", ssh_get_error(bind));

	for (;;) {
		client->session = ssh_new();
		client->channel = NULL;
		if (!client->session)
			tmate_fatal("Cannot initialize session");

		ssh_set_callbacks(client->session, &ssh_session_callbacks);

		if (ssh_bind_accept(bind, client->session) < 0)
			tmate_fatal("Error accepting connection: %s", ssh_get_error(bind));

		if ((pid = fork()) < 0)
			tmate_fatal("Can't fork");

		if (pid) {
			ssh_free(client->session);
		} else {
			ssh_bind_free(bind);
			tmate_debug("Child spawned pid=%d", getpid());
			client_bootstrap(client);
		}
	}
}
