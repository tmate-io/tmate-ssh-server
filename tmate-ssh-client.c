#include "tmate.h"

static void on_decoder_read(void *userdata, struct tmate_unpacker *uk)
{
	struct tmate_session *session = userdata;
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
		tmate_decoder_get_buffer(&session->client_decoder, &buf, &len);

		if (len == 0)
			tmate_fatal("No more room in client decoder. Message too big?");

		if (len > total_len)
			len = total_len;

		memcpy(buf, data, len);

		tmate_decoder_commit(&session->client_decoder, len);

		total_len -= len;
		written += len;
		data += len;
	}

	return written;
}

static void on_encoder_write(void *userdata, struct evbuffer *buffer)
{
	struct tmate_session *session = userdata;
	ssize_t len, written;
	char *buf;

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

void tmate_daemon_init(struct tmate_session *session)
{
	struct tmate_ssh_client *client = &session->ssh_client;

	memset(&client->channel_cb, 0, sizeof(client->channel_cb));
	ssh_callbacks_init(&client->channel_cb);
	client->channel_cb.userdata = session;
	client->channel_cb.channel_data_function = on_ssh_channel_read,
	ssh_set_channel_callbacks(client->channel, &client->channel_cb);

	tmate_encoder_init(&session->client_encoder, on_encoder_write, session);
	tmate_decoder_init(&session->client_decoder, on_decoder_read, session);
}
