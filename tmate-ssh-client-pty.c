#include <libssh/server.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include "tmate.h"

extern void client_signal(int sig);

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

void tmate_flush_pty(struct tmate_session *session)
{
	on_pty_event(session);
	close(session->pty);
}

void tmate_client_pty_init(struct tmate_session *session)
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
