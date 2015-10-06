#include "tmate.h"
#include <errno.h>

static void on_proxy_decoder_read(void *userdata, struct tmate_unpacker *uk)
{
	struct tmate_session *session = userdata;
	tmate_dispatch_proxy_message(session, uk);
}

static void on_proxy_read(struct bufferevent *bev, void *_session)
{
	struct tmate_session *session = _session;
	struct evbuffer *proxy_in;
	ssize_t written;
	char *buf;
	size_t len;

	proxy_in = bufferevent_get_input(session->bev_proxy);

	while (evbuffer_get_length(proxy_in)) {
		tmate_decoder_get_buffer(&session->proxy_decoder, &buf, &len);

		if (len == 0)
			tmate_fatal("No more room in client decoder. Message too big?");

		written = evbuffer_remove(proxy_in, buf, len);
		if (written < 0)
			tmate_fatal("Cannot read proxy buffer");

		tmate_decoder_commit(&session->proxy_decoder, written);
	}
}

static void on_proxy_encoder_write(void *userdata, struct evbuffer *buffer)
{
	struct tmate_session *session = userdata;
	struct evbuffer *proxy_out;
	size_t len;

	proxy_out = bufferevent_get_output(session->bev_proxy);

	if (evbuffer_add_buffer(proxy_out, buffer) < 0)
		tmate_fatal("Cannot write to proxy buffer");
}

static void on_proxy_event(struct bufferevent *bev, short events, void *_session)
{
	if (events & BEV_EVENT_EOF)
		tmate_fatal("Connection to proxy closed");

	if (events & BEV_EVENT_ERROR)
		tmate_fatal("Connection to proxy error: %s",
			    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}

static void on_daemon_decoder_read(void *userdata, struct tmate_unpacker *uk)
{
	struct tmate_session *session = userdata;

	tmate_send_proxy_daemon_msg(session, uk);
	tmate_dispatch_daemon_message(session, uk);
}

static int on_ssh_channel_read(ssh_session _session, ssh_channel channel,
			       void *_data, uint32_t total_len,
			       int is_stderr, void *userdata)
{
	struct tmate_session *session = userdata;
	char *data = _data;
	size_t written = 0;
	char *buf;
	size_t len;

	while (total_len) {
		tmate_decoder_get_buffer(&session->daemon_decoder, &buf, &len);

		if (len == 0)
			tmate_fatal("No more room in client decoder. Message too big?");

		if (len > total_len)
			len = total_len;

		memcpy(buf, data, len);

		tmate_decoder_commit(&session->daemon_decoder, len);

		total_len -= len;
		written += len;
		data += len;
	}

	return written;
}

static void on_daemon_encoder_write(void *userdata, struct evbuffer *buffer)
{
	struct tmate_session *session = userdata;
	ssize_t len, written;
	unsigned char *buf;

	for(;;) {
		len = evbuffer_get_length(buffer);
		if (!len)
			break;

		buf = evbuffer_pullup(buffer, -1);

		written = ssh_channel_write(session->ssh_client.channel, buf, len);
		if (written < 0) {
			tmate_warn("Error writing to channel: %s",
				    ssh_get_error(session->ssh_client.session));
			request_server_termination();
			break;
		}

		evbuffer_drain(buffer, written);
	}
}

static void init_proxy(struct tmate_session *session)
{
	/* session->proxy_fd is already connected */
	session->bev_proxy = bufferevent_socket_new(ev_base, session->proxy_fd,
						     BEV_OPT_CLOSE_ON_FREE);
	if (!session->bev_proxy)
		tmate_fatal("Cannot setup socket bufferevent");

	bufferevent_setcb(session->bev_proxy,
			  on_proxy_read, NULL, on_proxy_event, session);
	bufferevent_enable(session->bev_proxy, EV_READ | EV_WRITE);

	tmate_encoder_init(&session->proxy_encoder, on_proxy_encoder_write, session);
	tmate_decoder_init(&session->proxy_decoder, on_proxy_decoder_read, session);

	tmate_init_proxy_session(session);
	tmate_send_proxy_header(session);
}

void tmate_daemon_init(struct tmate_session *session)
{
	struct tmate_ssh_client *client = &session->ssh_client;

	memset(&client->channel_cb, 0, sizeof(client->channel_cb));
	ssh_callbacks_init(&client->channel_cb);
	client->channel_cb.userdata = session;
	client->channel_cb.channel_data_function = on_ssh_channel_read,
	ssh_set_channel_callbacks(client->channel, &client->channel_cb);

	tmate_encoder_init(&session->daemon_encoder, on_daemon_encoder_write, session);
	tmate_decoder_init(&session->daemon_decoder, on_daemon_decoder_read, session);

	if (tmate_has_proxy())
		init_proxy(session);
}
