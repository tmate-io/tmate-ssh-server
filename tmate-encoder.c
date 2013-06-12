#include "tmate.h"

static int msgpack_write(void *data, const char *buf, unsigned int len)
{
	struct tmate_encoder *encoder = data;

	evbuffer_add(encoder->buffer, buf, len);

	if ((encoder->ev_readable.ev_flags & EVLIST_INSERTED) &&
	    !(encoder->ev_readable.ev_flags & EVLIST_ACTIVE)) {
		event_active(&encoder->ev_readable, EV_READ, 0);
	}

	return 0;
}

void tmate_encoder_init(struct tmate_encoder *encoder)
{
	encoder->buffer = evbuffer_new();
	msgpack_packer_init(&encoder->pk, encoder, &msgpack_write);
}

#define msgpack_pack_string(pk, str) do {		\
	int __strlen = strlen(str);			\
	msgpack_pack_raw(pk, __strlen);			\
	msgpack_pack_raw_body(pk, str, __strlen);	\
} while(0)

#define pack(what, ...) msgpack_pack_##what(&tmate_encoder->pk, __VA_ARGS__)

void tmate_client_resize(u_int sx, u_int sy)
{
	pack(array, 3);
	pack(int, TMATE_CLIENT_RESIZE);
	/* cast to signed, -1 == no clients */
	pack(int, sx);
	pack(int, sy);
}

void tmate_client_pane_key(int pane_id, int key)
{
	/*
	 * We don't specify the pane id because the current active pane is
	 * behind, so we'll let master send the key to its active pane.
	 */

	pack(array, 2);
	pack(int, TMATE_CLIENT_PANE_KEY);
	pack(int, key);
}

static const struct cmd_entry *local_cmds[] = {
	&cmd_detach_client_entry,
	&cmd_attach_session_entry,
	NULL
};

int tmate_should_exec_cmd_locally(const struct cmd_entry *cmd)
{
	const struct cmd_entry **ptr;

	for (ptr = local_cmds; *ptr; ptr++)
		if (*ptr == cmd)
			return 1;
	return 0;
}

void tmate_client_cmd(const char *cmd)
{
	pack(array, 2);
	pack(int, TMATE_CLIENT_CMD);
	pack(string, cmd);
}

void tmate_client_set_active_pane(int win_id, int pane_id)
{
	char cmd[1024];

	sprintf(cmd, "select-pane -t %d.%d", win_id, pane_id);
	tmate_client_cmd(cmd);
}
