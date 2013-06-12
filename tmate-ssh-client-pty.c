#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <errno.h>
#include "tmate.h"

extern void client_write_server(enum msgtype type, void *buf, size_t len);

static void consume_channel(struct tmate_ssh_client *client)
{
	ssize_t len, written;
	char buf[4096];
	char *ptr;

	for (;;) {
		len = ssh_channel_read_nonblocking(client->channel,
						   buf, sizeof(buf), 0);
		if (len < 0) {
			tmate_debug("Error reading from channel: %s",
				    ssh_get_error(client->session));
			exit(1);
		}

		if (len == 0)
			return;

		ptr = buf;
		setblocking(client->pty, 1);
		while (len > 0) {
			written = write(client->pty, ptr, len);
			if (written < 0)
				tmate_fatal("Error writing to pty");

			ptr += written;
			len -= written;
		}
		setblocking(client->pty, 0);
	}
}

static void on_session_event(struct tmate_ssh_client *client)
{
	ssh_execute_message_callbacks(client->session);

	consume_channel(client);

	if (!ssh_is_connected(client->session)) {
		tmate_debug("Disconnected");
		exit(1);
	}
}

static void __on_session_event(evutil_socket_t fd, short what, void *arg)
{
	on_session_event(arg);
}

static int message_callback(struct tmate_ssh_client *client,
			    ssh_message msg)
{
	if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL &&
	    ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
		struct winsize ws;

		ws.ws_col = ssh_message_channel_request_pty_width(msg);
		ws.ws_row = ssh_message_channel_request_pty_height(msg);

		ioctl(client->pty, TIOCSWINSZ, &ws);
		client_write_server(MSG_RESIZE, NULL, 0);

		return 1;
	}
	return 0;
}

static int __message_callback(ssh_session session, ssh_message msg, void *arg)
{
	return message_callback(arg, msg);
}

static void register_session_fd_event(struct tmate_ssh_client *client)
{
	ssh_set_message_callback(client->session, __message_callback, client);

	event_assign(&client->ev_ssh, ev_base, ssh_get_fd(client->session),
		     EV_READ | EV_PERSIST, __on_session_event, client);
	event_add(&client->ev_ssh, NULL);
}

static void on_pty_event(struct tmate_ssh_client *client)
{
	ssize_t len, written;
	char buf[4096];

	for (;;) {
		len = read(client->pty, buf, sizeof(buf));
		if (len < 0) {
			if (errno == EAGAIN)
				return;
			tmate_fatal("pty read error");
		}

		if (len == 0)
			tmate_fatal("pty reached EOF");

		written = ssh_channel_write(client->channel, buf, len);
		if (written < 0) {
			tmate_debug("Error writing to channel: %s",
				    ssh_get_error(client->session));
			exit(1);
		}
		if (len != written) {
			tmate_fatal("Cannot write %d bytes, wrote %d",
				    (int)len, (int)written);
		}
	}
}

static void __on_pty_event(evutil_socket_t fd, short what, void *arg)
{
	on_pty_event(arg);
}

void tmate_flush_pty(struct tmate_ssh_client *client)
{
	on_pty_event(client);
	close(client->pty);
}

static void register_pty_event(struct tmate_ssh_client *client)
{
	setblocking(client->pty, 0);
	event_assign(&client->ev_pty, ev_base, client->pty,
		     EV_READ | EV_PERSIST, __on_pty_event, client);
	event_add(&client->ev_pty, NULL);
}

void tmate_ssh_client_pty_init(struct tmate_ssh_client *client)
{
	ioctl(client->pty, TIOCSWINSZ, &client->winsize_pty);
	register_session_fd_event(client);
	register_pty_event(client);
}
