#include "tmate.h"
#include <errno.h>

static void on_master_decoder_read(void *userdata, struct tmate_unpacker *uk)
{
	/* struct tmate_session *session = userdata; */
	tmate_info("Received master data!");
}

static void on_master_read(struct bufferevent *bev, void *_session)
{
	struct tmate_session *session = _session;
	struct evbuffer *master_in;
	ssize_t written;
	char *buf;
	size_t len;

	master_in = bufferevent_get_input(session->bev_master);

	while (evbuffer_get_length(master_in)) {
		tmate_decoder_get_buffer(&session->daemon_decoder, &buf, &len);

		if (len == 0)
			tmate_fatal("No more room in client decoder. Message too big?");

		written = evbuffer_remove(master_in, buf, len);
		if (written < 0)
			tmate_fatal("Cannot read master buffer");
	}
}

static void on_master_encoder_write(void *userdata, struct evbuffer *buffer)
{
	struct tmate_session *session = userdata;
	struct evbuffer *master_out;
	size_t len;

	master_out = bufferevent_get_output(session->bev_master);

	len = evbuffer_get_length(buffer);

	if (session->keyframe_size + len > TMATE_KEYFRAME_MAX_SIZE) {
		if (session->keyframe_size == 0)
			tmate_fatal("keyframe max size too small");
		tmate_send_master_keyframe(session);
	}

	session->keyframe_size += len;

	if (evbuffer_add_buffer(master_out, buffer) < 0)
		tmate_fatal("Cannot write to master buffer");

}

static void on_master_event(struct bufferevent *bev, short events, void *_session)
{
	if (events & BEV_EVENT_EOF)
		tmate_fatal("Connection to master closed");

	if (events & BEV_EVENT_ERROR)
		tmate_fatal("Connection to master error: %s",
			    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}

static void on_daemon_decoder_read(void *userdata, struct tmate_unpacker *uk)
{
	struct tmate_session *session = userdata;
	struct timespec time_diff, current_time;

	if (tmate_has_master()) {
		if (clock_gettime(CLOCK_MONOTONIC, &current_time) < 0)
			tmate_fatal("Cannot get time");

		timespec_subtract(&time_diff, &current_time,
				  &session->keyframe_start_time);
		if (time_diff.tv_sec > TMATE_KEYFRAME_INTERVAL_SEC - 1)
			tmate_send_master_keyframe(session);

		tmate_send_master_daemon_msg(session, uk);
	}

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

static void init_master(struct tmate_session *session)
{
	/* session->master_fd is already connected */
	session->bev_master = bufferevent_socket_new(ev_base, session->master_fd,
						     BEV_OPT_CLOSE_ON_FREE);
	if (!session->bev_master)
		tmate_fatal("Cannot setup socket bufferevent");

	bufferevent_setcb(session->bev_master,
			  on_master_read, NULL, on_master_event, session);
	bufferevent_enable(session->bev_master, EV_READ | EV_WRITE);

	tmate_encoder_init(&session->master_encoder, on_master_encoder_write, session);
	tmate_decoder_init(&session->master_decoder, on_master_decoder_read, session);

	tmate_init_master_session(session);
	tmate_send_master_header(session);

	tmate_send_master_keyframe(session);
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

	if (tmate_has_master())
		init_master(session);
}
