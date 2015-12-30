#include "tmate.h"
#include "tmate-protocol.h"

#define pack(what, ...) _pack(&tmate_session->daemon_encoder, what, __VA_ARGS__)

static void __tmate_notify(const char *msg)
{
	pack(array, 2);
	pack(int, TMATE_IN_NOTIFY);
	pack(string, msg);
}

void tmate_notify(const char *fmt, ...)
{
	va_list ap;
	char msg[1024];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	__tmate_notify(msg);
}

static void __tmate_notify_later(__unused evutil_socket_t fd,
				 __unused short what, void *arg)
{
	char *msg = arg;
	__tmate_notify(msg);
}

void tmate_notify_later(int timeout, const char *fmt, ...)
{
	struct timeval tv;
	va_list ap;
	char *msg;

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	va_start(ap, fmt);
	xvasprintf(&msg, fmt, ap);
	va_end(ap);

	/*
	 * FIXME leaks when calling tmate_notify_later()
	 * multiple times.
	 */

	evtimer_set(&tmate_session->ev_notify_timer,
		    __tmate_notify_later, msg);
	evtimer_add(&tmate_session->ev_notify_timer, &tv);
}

void tmate_send_client_ready(void)
{
	if (tmate_session->client_protocol_version < 4)
		return;

	pack(array, 1);
	pack(int, TMATE_IN_READY);
}

void tmate_send_env(const char *name, const char *value)
{
	if (tmate_session->client_protocol_version < 4)
		return;

	pack(array, 3);
	pack(int, TMATE_IN_SET_ENV);
	pack(string, name);
	pack(string, value);
}

void tmate_client_resize(u_int sx, u_int sy)
{
	pack(array, 3);
	pack(int, TMATE_IN_RESIZE);
	/* cast to signed, -1 == no clients */
	pack(int, sx);
	pack(int, sy);
}

void tmate_client_legacy_pane_key(__unused int pane_id, int key)
{
	/*
	 * We don't specify the pane id because the current active pane is
	 * behind, so we'll let master send the key to its active pane.
	 */

	pack(array, 2);
	pack(int, TMATE_IN_LEGACY_PANE_KEY);
	pack(int, key);
}

void tmate_client_pane_key(int pane_id, key_code key)
{
	if (key == KEYC_NONE || key == KEYC_UNKNOWN)
		return;

	/* Mouse keys not supported yet */
	if (KEYC_IS_MOUSE(key))
		return;

	if (tmate_session->client_protocol_version < 5) {
		int legacy_key = tmate_translate_legacy_key(key);
		tmate_client_legacy_pane_key(pane_id, legacy_key);
		return;
	}

	pack(array, 3);
	pack(int, TMATE_IN_PANE_KEY);
	pack(int, pane_id);
	pack(uint64, key);
}

extern const struct cmd_entry cmd_bind_key_entry;
extern const struct cmd_entry cmd_unbind_key_entry;
extern const struct cmd_entry cmd_set_option_entry;
extern const struct cmd_entry cmd_set_window_option_entry;
extern const struct cmd_entry cmd_detach_client_entry;
extern const struct cmd_entry cmd_attach_session_entry;

static const struct cmd_entry *local_cmds[] = {
	&cmd_bind_key_entry,
	&cmd_unbind_key_entry,
	&cmd_set_option_entry,
	&cmd_set_window_option_entry,
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

void tmate_client_cmd(int client_id, const char *cmd)
{
	pack(array, 3);
	pack(int, TMATE_IN_EXEC_CMD);
	pack(int, client_id);
	pack(string, cmd);
}

void tmate_client_set_active_pane(int client_id, int win_idx, int pane_id)
{
	char cmd[1024];

	sprintf(cmd, "select-pane -t %d.%d", win_idx, pane_id);
	tmate_client_cmd(client_id, cmd);
}

void tmate_send_mc_obj(msgpack_object *obj)
{
	pack(object, *obj);
}
