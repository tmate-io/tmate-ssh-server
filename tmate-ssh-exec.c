#include "tmate.h"
#include <errno.h>
#include <libssh/server.h>

void tmate_dump_exec_response(struct tmate_session *session,
			      int exit_code, const char *message)
{
	struct tmate_ssh_client *client = &session->ssh_client;

	ssh_channel_write(client->channel, message, strlen(message));
	ssh_channel_request_send_exit_status(client->channel, exit_code);

	ssh_channel_send_eof(client->channel);
	ssh_channel_close(client->channel);

	if (event_base_loopexit(session->ev_base, NULL) < 0)
		tmate_fatal("Cannot stop event loop");
}

static void on_websocket_error(struct tmate_session *session, __unused short events)
{
	tmate_info("Lost websocket server connection");
	tmate_dump_exec_response(session, 1, "Internal Error\r\n");
}

static void tmate_client_exec_init(struct tmate_session *session)
{
	struct tmate_ssh_client *client = &session->ssh_client;

	memset(&client->channel_cb, 0, sizeof(client->channel_cb));
	ssh_callbacks_init(&client->channel_cb);
	ssh_set_channel_callbacks(client->channel, &client->channel_cb);

	tmate_init_websocket(session, on_websocket_error);

	tmate_websocket_exec(session, client->exec_command);
}

void tmate_spawn_exec(struct tmate_session *session)
{
	struct tmate_ssh_client *client = &session->ssh_client;

	tmate_info("Spawning exec client ip=%s", client->ip_address);

	close_fds_except((int[]){ssh_get_fd(session->ssh_client.session),
				 log_file ? fileno(log_file) : -1,
				 session->websocket_fd}, 3);
	get_in_jail();
	event_reinit(session->ev_base);

	tmate_client_exec_init(session);

	if (event_base_dispatch(session->ev_base) < 0)
		tmate_fatal("Cannot run event loop");
	exit(0);
}
