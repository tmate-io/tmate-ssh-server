#include <libssh/server.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>
#include "tmate.h"

static int on_ssh_channel_read(__unused ssh_session _session,
			       __unused ssh_channel channel,
			       void *_data, uint32_t total_len,
			       __unused int is_stderr, void *userdata)
{
	struct tmate_session *session = userdata;
	char *data = _data;
	size_t written = 0;
	ssize_t len;

	if (session->readonly)
		return total_len;

	setblocking(session->pty, 1);
	while (total_len) {
		len = write(session->pty, data, total_len);
		if (len < 0)
			tmate_fatal("Error writing to pty");

		total_len -= len;
		written += len;
		data += len;
	}
	setblocking(session->pty, 0);

	return written;
}

static int on_ssh_message_callback(__unused ssh_session _session,
				   ssh_message msg, void *arg)
{
	struct tmate_session *session = arg;

	if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
	    ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
		struct winsize ws;

		ws.ws_col = ssh_message_channel_request_pty_width(msg);
		ws.ws_row = ssh_message_channel_request_pty_height(msg);

		ioctl(session->pty, TIOCSWINSZ, &ws);
		client_signal(SIGWINCH);

		return 1;
	}
	return 0;
}

static void on_pty_event(struct tmate_session *session)
{
	ssize_t len, written;
	char buf[4096];

	for (;;) {
		len = read(session->pty, buf, sizeof(buf));
		if (len < 0) {
			if (errno == EAGAIN)
				return;
			tmate_fatal("pty read error");
		}

		if (len == 0)
			tmate_fatal("pty reached EOF");

		written = ssh_channel_write(session->ssh_client.channel, buf, len);
		if (written < 0)
			tmate_fatal("Error writing to channel: %s",
				    ssh_get_error(session->ssh_client.session));
		if (len != written)
			tmate_fatal("Cannot write %d bytes, wrote %d",
				    (int)len, (int)written);
	}
}

static void __on_pty_event(__unused evutil_socket_t fd, __unused short what, void *arg)
{
	on_pty_event(arg);
}

static void tmate_flush_pty(struct tmate_session *session)
{
	on_pty_event(session);
	close(session->pty);
}

static void tmate_client_pty_init(struct tmate_session *session)
{
	struct tmate_ssh_client *client = &session->ssh_client;

	ioctl(session->pty, TIOCSWINSZ, &session->ssh_client.winsize_pty);

	memset(&client->channel_cb, 0, sizeof(client->channel_cb));
	ssh_callbacks_init(&client->channel_cb);
	client->channel_cb.userdata = session;
	client->channel_cb.channel_data_function = on_ssh_channel_read,
	ssh_set_channel_callbacks(client->channel, &client->channel_cb);

	ssh_set_message_callback(session->ssh_client.session,
				 on_ssh_message_callback, session);

	setblocking(session->pty, 0);
	event_set(&session->ev_pty, session->pty,
		  EV_READ | EV_PERSIST, __on_pty_event, session);
	event_add(&session->ev_pty, NULL);
}

static void random_sleep(void)
{
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 50000000 + (tmate_get_random_long() % 150000000);
	nanosleep(&ts, NULL);
}

#define BAD_TOKEN_ERROR_STR						\
"Invalid session token"						 "\r\n"

#define EXPIRED_TOKEN_ERROR_STR						\
"Invalid or expired session token"				 "\r\n"

static void ssh_echo(struct tmate_ssh_client *ssh_client,
		     const char *str)
{
	ssh_channel_write(ssh_client->channel, str, strlen(str));
}


/*
 * Note: get_socket_path() replaces '/' and '.' by '_' to
 * avoid wondering around the file system.
 */
static char valid_digits[] = "abcdefghjklmnopqrstuvwxyz"
                             "ABCDEFGHJKLMNOPQRSTUVWXYZ"
			     "0123456789-_/";

int tmate_validate_session_token(const char *token)
{
	int len;
	int i;

	len = strlen(token);
	if (len <= 2)
		return -1;

	for (i = 0; i < len; i++) {
		if (!strchr(valid_digits, token[i]))
			return -1;
	}

	return 0;
}

void tmate_spawn_pty_client(struct tmate_session *session)
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

	if (tmate_validate_session_token(token) < 0) {
		ssh_echo(client, BAD_TOKEN_ERROR_STR);
		tmate_fatal("Invalid token");
	}

	set_session_token(session, token);

	tmate_info("Spawning pty client ip=%s", client->ip_address);

	session->tmux_socket_fd = client_connect(session->ev_base, socket_path, 0);
	if (session->tmux_socket_fd < 0) {
		if (tmate_has_websocket()) {
			/* Turn the response into an exec to show a better error */
			client->exec_command = xstrdup("explain-session-not-found");
			tmate_spawn_exec(session);
			/* No return */
		}

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
	get_in_jail();
	event_reinit(session->ev_base);

	ret = client_main(session->ev_base, argc, argv,
			  CLIENT_UTF8 | CLIENT_256COLOURS, NULL);
	tmate_flush_pty(session);
	exit(ret);
}
