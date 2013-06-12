#include "tmate.h"

char *tmate_left_status, *tmate_right_status;

static struct session *main_session;

struct tmate_unpacker {
	msgpack_object *argv;
	int argc;
};

static void decoder_error(void)
{
#ifdef DEBUG
	tmate_print_trace();
#endif
	tmate_fatal("Received a bad message");
}

static void init_unpacker(struct tmate_unpacker *uk,
			  msgpack_object obj)
{
	if (obj.type != MSGPACK_OBJECT_ARRAY)
		decoder_error();

	uk->argv = obj.via.array.ptr;
	uk->argc = obj.via.array.size;
}

static int64_t unpack_int(struct tmate_unpacker *uk)
{
	int64_t val;

	if (uk->argc == 0)
		decoder_error();

	if (uk->argv[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
	    uk->argv[0].type != MSGPACK_OBJECT_NEGATIVE_INTEGER)
		decoder_error();

	val = uk->argv[0].via.i64;

	uk->argv++;
	uk->argc--;

	return val;
}

static void unpack_raw(struct tmate_unpacker *uk,
		       const char **buf, size_t *len)
{
	if (uk->argc == 0)
		decoder_error();

	if (uk->argv[0].type != MSGPACK_OBJECT_RAW)
		decoder_error();

	*len = uk->argv[0].via.raw.size;
	*buf = uk->argv[0].via.raw.ptr;

	uk->argv++;
	uk->argc--;
}

static char *unpack_string(struct tmate_unpacker *uk)
{
	const char *buf;
	char *alloc_buf;
	size_t len;

	unpack_raw(uk, &buf, &len);

	alloc_buf = xmalloc(len + 1);
	memcpy(alloc_buf, buf, len);
	alloc_buf[len] = '\0';

	return alloc_buf;
}

static void unpack_array(struct tmate_unpacker *uk,
			 struct tmate_unpacker *nested)
{
	if (uk->argc == 0)
		decoder_error();

	init_unpacker(nested, uk->argv[0]);

	uk->argv++;
	uk->argc--;
}

#define unpack_each(nested_uk, tmp_uk, uk)	\
	for (unpack_array(uk, tmp_uk);		\
	     (tmp_uk)->argc > 0 && (init_unpacker(nested_uk, (tmp_uk)->argv[0]), 1); \
	     (tmp_uk)->argv++, (tmp_uk)->argc--)

static void tmate_header(struct tmate_unpacker *uk)
{
	int protocol = unpack_int(uk);

	if (protocol != 1)
		decoder_error();

	tmate_debug("new master, protocol: %d", protocol);
}

extern u_int next_window_pane_id;

static void tmate_sync_window_panes(struct window *w,
				    struct tmate_unpacker *w_uk)
{
	struct tmate_unpacker uk, tmp_uk;
	struct window_pane *wp, *wp_tmp;
	int active_pane_id;

	TAILQ_FOREACH(wp, &w->panes, entry)
		wp->flags |= PANE_KILL;

	unpack_each(&uk, &tmp_uk, w_uk) {
		int id = unpack_int(&uk);
		int sx = unpack_int(&uk);
		int sy = unpack_int(&uk);
		int xoff = unpack_int(&uk);
		int yoff = unpack_int(&uk);

		wp = window_pane_find_by_id(id);
		if (!wp) {
			next_window_pane_id = id;
			wp = window_add_pane(w, TMATE_HLIMIT);
			window_set_active_pane(w, wp);
		}
		wp->flags &= ~PANE_KILL;

		wp->xoff = xoff;
		wp->yoff = yoff;
		window_pane_resize(wp, sx, sy);

		wp->flags |= PANE_REDRAW;
	}

	TAILQ_FOREACH_SAFE(wp, &w->panes, entry, wp_tmp) {
		if (wp->flags & PANE_KILL)
			window_remove_pane(w, wp);
	}

	active_pane_id = unpack_int(w_uk);
	wp = window_pane_find_by_id(active_pane_id);
	window_set_active_pane(w, wp);
}

static void tmate_sync_windows(struct session *s,
			       struct tmate_unpacker *s_uk)
{
	struct tmate_unpacker uk, tmp_uk;
	struct winlink *wl, *wl_tmp;
	struct window *w;
	int active_window_id;
	char *cause;

	RB_FOREACH(wl, winlinks, &s->windows)
		wl->window->flags |= WINDOW_KILL;

	unpack_each(&uk, &tmp_uk, s_uk) {
		int id     = unpack_int(&uk);
		char *name = unpack_string(&uk);

		wl = winlink_find_by_window_id(&s->windows, id);
		if (!wl) {
			wl = session_new(s, name, "", NULL, id, &cause);
			if (!wl)
				tmate_fatal("can't create window id=%d", id);
		}
		w = wl->window;
		w->flags &= ~WINDOW_KILL;

		free(w->name);
		w->name = name;
		w->sx = s->sx;
		w->sy = s->sy;

		tmate_sync_window_panes(w, &uk);
	}

	RB_FOREACH_SAFE(wl, winlinks, &s->windows, wl_tmp) {
		if (wl->window->flags & WINDOW_KILL)
			winlink_remove(&s->windows, wl);
	}

	active_window_id = unpack_int(s_uk);
	wl = winlink_find_by_window_id(&s->windows, active_window_id);

	session_set_current(s, wl);
	server_redraw_window(wl->window);
}

static void tmate_sync_layout(struct tmate_unpacker *uk)
{
	struct session *s;
	char *cause;

	int sx = unpack_int(uk);
	int sy = unpack_int(uk);

	s = RB_MIN(sessions, &sessions);
	if (!s) {
		s = session_create("default", NULL, "default", NULL,
				   NULL, 0, sx, sy, &cause);
		if (!s)
			tmate_fatal("can't create main session");
	}

	s->sx = sx;
	s->sy = sy;

	tmate_sync_windows(s, uk);
}

static void tmate_pty_data(struct tmate_unpacker *uk)
{
	struct window_pane *wp;
	const char *buf;
	size_t len;
	int id;

	id = unpack_int(uk);
	unpack_raw(uk, &buf, &len);

	wp = window_pane_find_by_id(id);
	if (!wp)
		tmate_fatal("can't find pane id=%d", id);

	evbuffer_add(wp->event_input, buf, len);
	input_parse(wp);

	wp->window->flags |= WINDOW_SILENCE;
}

static void tmate_cmd(struct tmate_unpacker *uk)
{
	struct cmd_q *cmd_q;
	struct cmd_list *cmdlist;
	char *cmd_str;
	char *cause;

	cmd_str = unpack_string(uk);
	if (cmd_string_parse(cmd_str, &cmdlist, NULL, 0, &cause) != 0) {
		free(cause);
		goto out;
	}

	cmd_q = cmdq_new(NULL);
	cmdq_run(cmd_q, cmdlist);
	cmd_list_free(cmdlist);
	cmdq_free(cmd_q);
out:
	free(cmd_str);
}

static void tmate_status(struct tmate_unpacker *uk)
{
	struct client *c;
	unsigned int i;

	free(tmate_left_status);
	free(tmate_right_status);
	tmate_left_status = unpack_string(uk);
	tmate_right_status = unpack_string(uk);

	for (i = 0; i < ARRAY_LENGTH(&clients); i++) {
		c = ARRAY_ITEM(&clients, i);
		if (c)
			c->flags |= CLIENT_STATUS;
	}
}

static void handle_message(msgpack_object obj)
{
	struct tmate_unpacker _uk;
	struct tmate_unpacker *uk = &_uk;
	int cmd;

	init_unpacker(uk, obj);

	switch (unpack_int(uk)) {
	case TMATE_HEADER:	tmate_header(uk);	break;
	case TMATE_SYNC_LAYOUT:	tmate_sync_layout(uk);	break;
	case TMATE_PTY_DATA:	tmate_pty_data(uk);	break;
	case TMATE_CMD:		tmate_cmd(uk);		break;
	case TMATE_STATUS:	tmate_status(uk);	break;
	default:		decoder_error();
	}
}

void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len)
{
	msgpack_unpacked result;

	msgpack_unpacker_buffer_consumed(&decoder->unpacker, len);

	msgpack_unpacked_init(&result);
	while (msgpack_unpacker_next(&decoder->unpacker, &result)) {
		handle_message(result.data);
	}
	msgpack_unpacked_destroy(&result);

	if (msgpack_unpacker_message_size(&decoder->unpacker) >
						TMATE_MAX_MESSAGE_SIZE) {
		tmate_fatal("Message too big");
	}
}

void tmate_decoder_get_buffer(struct tmate_decoder *decoder,
			      char **buf, size_t *len)
{
	/* rewind the buffer if possible */
	if (msgpack_unpacker_buffer_capacity(&decoder->unpacker) <
						TMATE_MAX_MESSAGE_SIZE) {
		msgpack_unpacker_expand_buffer(&decoder->unpacker, 0);
	}

	*buf = msgpack_unpacker_buffer(&decoder->unpacker);
	*len = msgpack_unpacker_buffer_capacity(&decoder->unpacker);
}

void tmate_decoder_init(struct tmate_decoder *decoder)
{
	if (!msgpack_unpacker_init(&decoder->unpacker, 2*TMATE_MAX_MESSAGE_SIZE))
		tmate_fatal("cannot initialize the unpacker");
}
