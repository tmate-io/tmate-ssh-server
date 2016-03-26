#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <stdio.h>
#include <event.h>
#include <arpa/inet.h>

#include "tmate.h"

static int pty_request(__unused ssh_session session,
		       __unused ssh_channel channel,
		       __unused const char *term,
		       int width, int height,
		       __unused int pxwidth, __unused int pwheight,
		       void *userdata)
{
	struct tmate_ssh_client *client = userdata;

	client->winsize_pty.ws_col = width;
	client->winsize_pty.ws_row = height;

	return 0;
}

static int shell_request(__unused ssh_session session,
			 __unused ssh_channel channel,
			 void *userdata)
{
	struct tmate_ssh_client *client = userdata;

	if (client->role)
		return 1;

	client->role = TMATE_ROLE_PTY_CLIENT;

	return 0;
}

static int subsystem_request(__unused ssh_session session,
			     __unused ssh_channel channel,
			     const char *subsystem, void *userdata)
{
	struct tmate_ssh_client *client = userdata;

	if (client->role)
		return 1;

	if (!strcmp(subsystem, "tmate"))
		client->role = TMATE_ROLE_DAEMON;

	return 0;
}

static int exec_request(__unused ssh_session session,
			__unused ssh_channel channel,
			const char *command, void *userdata)
{
	struct tmate_ssh_client *client = userdata;

	if (client->role)
		return 1;

	if (!tmate_has_proxy())
		return 1;

	client->role = TMATE_ROLE_EXEC;
	client->exec_command = xstrdup(command);

	return 0;
}

static ssh_channel channel_open_request_cb(ssh_session session, void *userdata)
{
	struct tmate_ssh_client *client = userdata;

	if (!client->username) {
		/* The authentication did not go through yet */
		return NULL;
	}

	if (client->channel) {
		/*
		 * We already have a channel, and we don't support multi
		 * channels yet. Returning NULL means the channel request will
		 * be denied.
		 */
		return NULL;
	}

	client->channel = ssh_channel_new(session);
	if (!client->channel)
		tmate_fatal("Error getting channel");

	memset(&client->channel_cb, 0, sizeof(client->channel_cb));
	ssh_callbacks_init(&client->channel_cb);
	client->channel_cb.userdata = client;
	client->channel_cb.channel_pty_request_function = pty_request;
	client->channel_cb.channel_shell_request_function = shell_request;
	client->channel_cb.channel_subsystem_request_function = subsystem_request;
	client->channel_cb.channel_exec_request_function = exec_request;
	ssh_set_channel_callbacks(client->channel, &client->channel_cb);

	return client->channel;
}

static int auth_pubkey_cb(__unused ssh_session session,
			  const char *user,
			  struct ssh_key_struct *pubkey,
			  char signature_state, void *userdata)
{
	struct tmate_ssh_client *client = userdata;

	switch (signature_state) {
	case SSH_PUBLICKEY_STATE_VALID:
		client->username = xstrdup(user);
		if (ssh_pki_export_pubkey_base64(pubkey, &client->pubkey) != SSH_OK)
			tmate_fatal("error getting public key");
		return SSH_AUTH_SUCCESS;
	case SSH_PUBLICKEY_STATE_NONE:
		return SSH_AUTH_SUCCESS;
	default:
		return SSH_AUTH_DENIED;
	}
}

static struct ssh_server_callbacks_struct ssh_server_cb = {
	.auth_pubkey_function = auth_pubkey_cb,
	.channel_open_request_session_function = channel_open_request_cb,
};

static void on_ssh_read(__unused evutil_socket_t fd, __unused short what, void *arg)
{
	struct tmate_ssh_client *client = arg;
	ssh_execute_message_callbacks(client->session);

	if (!ssh_is_connected(client->session)) {
		tmate_warn("SSH Disconnected");

		event_del(&client->ev_ssh);

		/* For graceful tmux client termination */
		request_server_termination();
	}
}

static void register_on_ssh_read(struct tmate_ssh_client *client)
{
	event_set(&client->ev_ssh, ssh_get_fd(client->session),
		  EV_READ | EV_PERSIST, on_ssh_read, client);
	event_add(&client->ev_ssh, NULL);
}

static void handle_sigalrm(__unused int sig)
{
	tmate_fatal("Connection grace period (%d) passed", TMATE_SSH_GRACE_PERIOD);
}

static void client_bootstrap(struct tmate_session *_session)
{
	struct tmate_ssh_client *client = &_session->ssh_client;
	int grace_period = TMATE_SSH_GRACE_PERIOD;
	ssh_event mainloop;
	ssh_session session = client->session;

	tmate_notice("Bootstrapping ssh client ip=%s", client->ip_address);

	_session->ev_base = osdep_event_init();

	/* new process group, we don't want to die with our parent (upstart) */
	setpgid(0, 0);

	{
	int flag = 1;
	setsockopt(ssh_get_fd(session), IPPROTO_TCP, TCP_NODELAY,
		   &flag, sizeof(flag));
	}

	signal(SIGALRM, handle_sigalrm);
	alarm(grace_period);

	/*
	 * We should die early if we can't connect to proxy. This way the
	 * tmate daemon will pick another server to work on.
	 */
	_session->proxy_fd = -1;
	if (tmate_has_proxy())
		_session->proxy_fd = tmate_connect_to_proxy();

	ssh_server_cb.userdata = client;
	ssh_callbacks_init(&ssh_server_cb);
	ssh_set_server_callbacks(client->session, &ssh_server_cb);

	ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &grace_period);
	ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes");

	ssh_set_auth_methods(client->session, SSH_AUTH_METHOD_PUBLICKEY);

	tmate_info("Exchanging DH keys");
	if (ssh_handle_key_exchange(session) < 0)
		tmate_fatal("Error doing the key exchange: %s",
				    ssh_get_error(session));

	mainloop = ssh_event_new();
	ssh_event_add_session(mainloop, session);

	while (!client->role) {
		if (ssh_event_dopoll(mainloop, -1) == SSH_ERROR)
			tmate_fatal("Error polling ssh socket: %s", ssh_get_error(session));
	}

	alarm(0);

	/* The latency is callback set later */
	tmate_start_ssh_latency_probes(client, &ssh_server_cb, TMATE_SSH_KEEPALIVE * 1000);
	register_on_ssh_read(client);

	tmate_spawn_slave(_session);
	/* never reached */
}

static int get_ip(int fd, char *dst, size_t len)
{
	struct sockaddr sa;
	socklen_t sa_len = sizeof(sa);

	if (getpeername(fd, &sa, &sa_len) < 0)
		return -1;


	switch (sa.sa_family) {
	case AF_INET:
		if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&sa)->sin_addr,
			       dst, len))
			return -1;
		break;
	case AF_INET6:
		if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sa)->sin6_addr,
			       dst, len))
			return -1;
		break;
	default:
		return -1;
	}

	return 0;
}

static void ssh_log_function(int priority, const char *function,
			     const char *buffer, __unused void *userdata)
{
	tmate_info("[%d] [%s] %s", priority, function, buffer);
}

static ssh_bind prepare_ssh(const char *keys_dir, int port)
{
	ssh_bind bind;
	char buffer[PATH_MAX];
	int verbosity = SSH_LOG_NOLOG;

	ssh_set_log_callback(ssh_log_function);

	bind = ssh_bind_new();
	if (!bind)
		tmate_fatal("Cannot initialize ssh");

	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BANNER, TMATE_SSH_BANNER);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);

	sprintf(buffer, "%s/ssh_host_rsa_key", keys_dir);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY, buffer);

	sprintf(buffer, "%s/ssh_host_ecdsa_key", keys_dir);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_ECDSAKEY, buffer);

	if (ssh_bind_listen(bind) < 0)
		tmate_fatal("Error listening to socket: %s\n", ssh_get_error(bind));

	tmate_notice("Accepting connections on %d", port);

	return bind;
}

static void handle_sigchld(__unused int sig)
{
	int status;
	pid_t pid;

	while ((pid = waitpid(WAIT_ANY, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status))
			tmate_info("Child %d exited (%d)", pid, WEXITSTATUS(status));
		if (WIFSIGNALED(status))
			tmate_info("Child %d killed (%d)", pid, WTERMSIG(status));
		if (WIFSTOPPED(status))
			tmate_info("Child %d stopped (%d)", pid, WSTOPSIG(status));
	}
}

static void handle_sigsegv(__unused int sig)
{
	tmate_info("CRASH, printing stack trace");
	tmate_print_stack_trace();
	tmate_fatal("CRASHED");
}

void tmate_ssh_server_main(struct tmate_session *session,
			   const char *keys_dir, int port)
{
	sigset_t sigchld_set;
	struct tmate_ssh_client *client = &session->ssh_client;
	ssh_bind bind;
	pid_t pid;

	signal(SIGSEGV, handle_sigsegv);
	signal(SIGCHLD, handle_sigchld);

	sigemptyset(&sigchld_set);
	sigaddset(&sigchld_set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sigchld_set, NULL);

	bind = prepare_ssh(keys_dir, port);

	for (;;) {
		client->session = ssh_new();
		client->channel = NULL;
		client->winsize_pty.ws_col = 80;
		client->winsize_pty.ws_row = 24;

		if (!client->session)
			tmate_fatal("Cannot initialize session");

		sigprocmask(SIG_UNBLOCK, &sigchld_set, NULL);
		if (ssh_bind_accept(bind, client->session) < 0)
			tmate_fatal("Error accepting connection: %s", ssh_get_error(bind));
		sigprocmask(SIG_BLOCK, &sigchld_set, NULL);

		if (get_ip(ssh_get_fd(client->session),
			   client->ip_address, sizeof(client->ip_address)) < 0)
			tmate_fatal("Error getting IP address from connection");

		if ((pid = fork()) < 0)
			tmate_fatal("Can't fork");

		if (pid) {
			tmate_info("Child spawned pid=%d, ip=%s",
				    pid, client->ip_address);
			ssh_free(client->session);
		} else {
			ssh_bind_free(bind);
			session->session_token = "init";
			client_bootstrap(session);
		}
	}
}
