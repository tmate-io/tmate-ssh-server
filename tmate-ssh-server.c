#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sched.h>
#include <stdio.h>
#include <event.h>

#include "tmate.h"

#define SSH_GRACE_PERIOD 60

#define REPLY_DEFAULT	1
#define STEP_COMPLETE	2

typedef int (*bootstrap_step_cb)(struct tmate_ssh_client *client,
				 ssh_message msg);

static void bootstrap_step(struct tmate_ssh_client *client,
			   bootstrap_step_cb step)
{
	ssh_message msg;

	for (;;) {
		msg = ssh_message_get(client->session);

		switch (step(client, msg)) {
		case STEP_COMPLETE:
			return;
		case REPLY_DEFAULT:
			ssh_message_reply_default(msg);
		}

		ssh_message_free(msg);
	}
}

static int user_auth_step(struct tmate_ssh_client *client,
			  ssh_message msg)
{
	if (!msg)
		tmate_fatal("Authentification error");

	if (ssh_message_type(msg) != SSH_REQUEST_AUTH)
		return REPLY_DEFAULT;

	if (ssh_message_subtype(msg) != SSH_AUTH_METHOD_PUBLICKEY) {
		ssh_message_auth_set_methods(msg, SSH_AUTH_METHOD_PUBLICKEY);
		return REPLY_DEFAULT;
	}

	switch (ssh_message_auth_publickey_state(msg)) {
	case SSH_PUBLICKEY_STATE_NONE:
		ssh_message_auth_reply_pk_ok_simple(msg);
		return 0;

	case SSH_PUBLICKEY_STATE_VALID:
		client->username = xstrdup(ssh_message_auth_user(msg));
		if (ssh_pki_export_pubkey_base64(ssh_message_auth_pubkey(msg),
						 &client->pubkey) != SSH_OK)
			tmate_fatal("error getting public key");

		ssh_message_auth_reply_success(msg, 0);
		return STEP_COMPLETE;
	default:
		return REPLY_DEFAULT;
	}
}

static int channel_open_step(struct tmate_ssh_client *client,
			     ssh_message msg)
{
	if (!msg)
		tmate_fatal("Error getting channel");

	if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL_OPEN &&
	    ssh_message_subtype(msg) == SSH_CHANNEL_SESSION) {
		client->channel = ssh_message_channel_request_open_reply_accept(msg);
		if (!client->channel)
			tmate_fatal("Error getting channel");

		return STEP_COMPLETE;
	}

	return REPLY_DEFAULT;
}

static int init_client_step(struct tmate_ssh_client *client,
			    ssh_message msg)
{
	if (!msg)
		tmate_fatal("Error getting subsystem");

	/* pty request */
	if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
	    ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_PTY) {
		client->winsize_pty.ws_col = ssh_message_channel_request_pty_width(msg);
		client->winsize_pty.ws_row = ssh_message_channel_request_pty_height(msg);
		ssh_message_channel_request_reply_success(msg);
		return 0;
	}

	/* tmate subsystem request (master) */
	if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
	    ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_SUBSYSTEM &&
	    !strcmp(ssh_message_channel_request_subsystem(msg), "tmate")) {
		client->role = TMATE_ROLE_SERVER;
	}

	/* shell request (slave client) */
	if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
	    ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_SHELL) {
		client->role = TMATE_ROLE_CLIENT;
	}

	if (client->role) {
		alarm(0);
		ssh_message_channel_request_reply_success(msg);
		tmate_spawn_slave(client);
		/* never reached */
	}

	return REPLY_DEFAULT;
}

static void client_bootstrap(struct tmate_ssh_client *client)
{
	int auth = 0;
	ssh_session session = client->session;
	ssh_channel channel = NULL;
	ssh_message msg;

	int flag = 1;
	setsockopt(ssh_get_fd(session), IPPROTO_TCP, TCP_NODELAY,
		   &flag, sizeof(flag));

	alarm(SSH_GRACE_PERIOD);

	ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes");

	tmate_debug("Exchanging DH keys");
	if (ssh_handle_key_exchange(session) < 0)
		tmate_fatal("Error doing the key exchange");

	tmate_debug("Authenticating with public key");
	bootstrap_step(client, user_auth_step);

	tmate_debug("Opening channel");
	bootstrap_step(client, channel_open_step);

	tmate_debug("Getting client type");
	bootstrap_step(client, init_client_step);

	/* never reached */
}

static void handle_sigchld(void)
{
	int status, child_dead, child_exit_status;
	pid_t pid;

	/* TODO cleanup the socket when the client dies */

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

static pid_t namespace_fork(void)
{
	/* XXX we are breaking getpid() libc cache. Bad libc. */
	unsigned long flags;
	flags = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET;
	return syscall(SYS_clone, flags | SIGCHLD, NULL, NULL, NULL);
}

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

		if ((pid = namespace_fork()) < 0)
			tmate_fatal("Can't fork in new namespace");

		if (pid) {
			ssh_free(client->session);
		} else {
			ssh_bind_free(bind);
			tmate_debug("Child spawned pid=%d", getpid());
			client_bootstrap(client);
		}
	}
}
