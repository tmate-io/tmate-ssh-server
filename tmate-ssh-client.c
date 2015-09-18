#include "tmate.h"
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

extern int server_shutdown;
extern void server_send_shutdown(void);

#define request_termination(str, ...) do {	\
	tmate_info(str, ## __VA_ARGS__);	\
	server_shutdown = 1;			\
	server_send_shutdown();			\
} while(0)

static void consume_channel(struct tmate_ssh_client *client)
{
	char *buf;
	ssize_t len;

	for (;;) {
		tmate_decoder_get_buffer(client->decoder, &buf, &len);
		if (len == 0) {
			request_termination("Decoder buffer full");
			break;
		}

		len = ssh_channel_read_nonblocking(client->channel,
						   buf, len, 0);
		if (len < 0) {
			if (!ssh_is_connected(client->session))
				request_termination("Disconnected");
			else
				request_termination("Error reading from channel: %s",
						    ssh_get_error(client->session));
			break;
		}
		if (len == 0)
			break;

		tmate_decoder_commit(client->decoder, len);
	}
}

static void on_session_event(struct tmate_ssh_client *client)
{
	ssh_execute_message_callbacks(client->session);
	consume_channel(client);
}

static void __on_session_event(evutil_socket_t fd, short what, void *arg)
{
	on_session_event(arg);
}

static void register_session_fd_event(struct tmate_ssh_client *client)
{
	event_assign(&client->ev_ssh, ev_base, ssh_get_fd(client->session),
		     EV_READ | EV_PERSIST, __on_session_event, client);
	event_add(&client->ev_ssh, NULL);
}

static void flush_input_stream(struct tmate_ssh_client *client)
{
	struct evbuffer *evb = client->encoder->buffer;
	ssize_t len, written;
	char *buf;

	if (server_shutdown)
		return;

	for (;;) {
		len = evbuffer_get_length(evb);
		if (!len)
			break;

		buf = evbuffer_pullup(evb, -1);

		written = ssh_channel_write(client->channel, buf, len);
		if (written < 0) {
			request_termination("Error writing to channel: %s",
					    ssh_get_error(client->session));
			break;
		}

		evbuffer_drain(evb, written);
	}
}

static void __flush_input_stream(evutil_socket_t fd, short what, void *arg)
{
	flush_input_stream(arg);
}

static void register_input_stream_event(struct tmate_ssh_client *client)
{
	event_assign(&client->encoder->ev_readable, ev_base, -1,
		     EV_READ | EV_PERSIST, __flush_input_stream, client);
	event_add(&client->encoder->ev_readable, NULL);
}


void tmate_ssh_client_init(struct tmate_ssh_client *client,
			   struct tmate_encoder *encoder,
			   struct tmate_decoder *decoder)
{
	client->winsize_pty.ws_col = 80;
	client->winsize_pty.ws_row = 24;

	client->encoder = encoder;
	client->decoder = decoder;

	register_session_fd_event(client);
	register_input_stream_event(client);

	tmate_start_keepalive_timer(client);
}
