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
#include <arpa/inet.h>

#include "tmate.h"

#define SSH_GRACE_PERIOD 60

#define REPLY_DEFAULT	1
#define STEP_COMPLETE	2

static void on_keepalive_timer(evutil_socket_t fd, short what, void *arg)
{
	struct tmate_ssh_client *client = arg;
	ssh_send_keepalive(client->session);
	tmate_start_keepalive_timer(client);
}

void tmate_start_keepalive_timer(struct tmate_ssh_client *client)
{
	struct timeval tv;
	tv.tv_sec = TMATE_KEEPALIVE;
	tv.tv_usec = 0;

	evtimer_assign(&client->ev_keepalive_timer, ev_base,
		       on_keepalive_timer, client);
	evtimer_add(&client->ev_keepalive_timer, &tv);
}

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
	int grace_period = SSH_GRACE_PERIOD;
	ssh_session session = client->session;
	ssh_channel channel = NULL;
	ssh_message msg;

	/* new process group, we don't want to die with our parent (upstart) */
	setpgid(0, 0);

	int flag = 1;
	setsockopt(ssh_get_fd(session), IPPROTO_TCP, TCP_NODELAY,
		   &flag, sizeof(flag));

	alarm(SSH_GRACE_PERIOD);

	ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &grace_period);
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
	siginfo_t si;

	/* TODO cleanup the socket when the client dies */
	while (waitid(P_ALL, 0, &si, WEXITED | WNOHANG) >= 0 && si.si_pid) {
		tmate_info("Child %d %s (%d)",
			   si.si_pid,
			   si.si_code == CLD_EXITED ? "exited" : "killed",
			   si.si_status);
	}
}

static void handle_sigalrm(void)
{
	tmate_fatal("Connection grace period (%d) passed", SSH_GRACE_PERIOD);
}

static void handle_sigsegv(void)
{
	tmate_info("CRASH, printing stack trace");
	tmate_print_trace();
	tmate_fatal("CRASHED");
}

static void handle_sigusr1(void)
{
	tmate_reopen_logfile();
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGCHLD: handle_sigchld(); break;
	case SIGALRM: handle_sigalrm(); break;
	case SIGSEGV: handle_sigsegv(); break;
	case SIGUSR1: handle_sigusr1(); break;
	}
}

static void setup_signals(void)
{
	signal(SIGCHLD, signal_handler);
	signal(SIGALRM, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGUSR1, signal_handler);
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

struct tmate_ssh_client tmate_client;

static ssh_bind prepare_ssh(const char *keys_dir, int port)
{
	ssh_bind bind;
	char buffer[PATH_MAX];
	int verbosity = SSH_LOG_NOLOG;
	//int verbosity = SSH_LOG_PACKET;

	ssh_callbacks_init(&ssh_session_callbacks);

	bind = ssh_bind_new();
	if (!bind)
		tmate_fatal("Cannot initialize ssh");

	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BANNER, TMATE_SSH_BANNER);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);

	sprintf(buffer, "%s/ssh_host_dsa_key", keys_dir);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_DSAKEY, buffer);

	sprintf(buffer, "%s/ssh_host_rsa_key", keys_dir);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY, buffer);

	if (ssh_bind_listen(bind) < 0)
		tmate_fatal("Error listening to socket: %s\n", ssh_get_error(bind));

	tmate_info("Accepting connections on %d", port);

	return bind;
}

void tmate_ssh_server_main(const char *keys_dir, int port)
{
	struct tmate_ssh_client *client = &tmate_client;
	ssh_bind bind;
	pid_t pid;

	setup_signals();
	bind = prepare_ssh(keys_dir, port);

	for (;;) {
		client->session = ssh_new();
		client->channel = NULL;
		if (!client->session)
			tmate_fatal("Cannot initialize session");

		ssh_set_callbacks(client->session, &ssh_session_callbacks);

		if (ssh_bind_accept(bind, client->session) < 0)
			tmate_fatal("Error accepting connection: %s", ssh_get_error(bind));

		if (get_ip(ssh_get_fd(client->session),
			   client->ip_address, sizeof(client->ip_address)) < 0)
			tmate_fatal("Error getting IP address from connection");

		if ((pid = namespace_fork()) < 0) {
			if (getuid() == 0)
				tmate_fatal("Can't fork in new namespace, are you running a recent kernel?");
			else
				tmate_fatal("Can't fork in new namespace, run me with root priviledges");
		}

		if (pid) {
			tmate_info("Child spawned pid=%d, ip=%s",
				    pid, client->ip_address);
			ssh_free(client->session);
		} else {
			ssh_bind_free(bind);
			tmate_session_token = ".........................";
			client_bootstrap(client);
		}
	}
}
