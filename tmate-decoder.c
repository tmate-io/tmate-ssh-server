#include <ctype.h>
#include <unistd.h>
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

static void tmate_header(struct tmate_decoder *decoder,
			 struct tmate_unpacker *uk)
{
	char port_arg[16] = {0};
	char *client_version = xstrdup("< 1.8.6");
	char tmp[512];

	decoder->protocol = unpack_int(uk);
	if (decoder->protocol >= 3) {
		free(client_version);
		client_version = unpack_string(uk);
	}

	tmate_debug("new master, client version: %s, protocol version: %d",
		    client_version, decoder->protocol);

#if 0
	if (strcmp(client_version, TMATE_LATEST_VERSION))
		tmate_notify_later(10, "A new version is available, please upgrade :)");
#endif

	free(client_version);

	if (tmate_port != 22)
		sprintf(port_arg, " -p%d", tmate_port);

	sprintf(tmp, "ssh%s ro-%s@%s", port_arg, tmate_session_token_ro, tmate_host);
	tmate_notify("Remote session read only: %s (clear your screen if you share this)", tmp);
	tmate_send_env("tmate_ssh_ro", tmp);

	sprintf(tmp, "ssh%s %s@%s", port_arg, tmate_session_token, tmate_host);
	tmate_notify("Remote session: %s", tmp);
	tmate_send_env("tmate_ssh", tmp);

	tmate_send_client_ready();
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
		u_int sx = unpack_int(&uk);
		u_int sy = unpack_int(&uk);
		u_int xoff = unpack_int(&uk);
		u_int yoff = unpack_int(&uk);

		wp = window_pane_find_by_id(id);
		if (!wp) {
			next_window_pane_id = id;
			wp = window_add_pane(w, TMATE_HLIMIT);
			window_set_active_pane(w, wp);
		}
		wp->flags &= ~PANE_KILL;

		if (wp->xoff != xoff || wp->yoff != yoff ||
		    wp->sx != sx || wp->sx != sy) {
			wp->xoff = xoff;
			wp->yoff = yoff;
			window_pane_resize(wp, sx, sy);

			wp->flags |= PANE_REDRAW;
		}
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
	int active_window_idx;
	char *cause;

	RB_FOREACH(wl, winlinks, &s->windows)
		wl->flags |= WINLINK_KILL;

	unpack_each(&uk, &tmp_uk, s_uk) {
		int idx    = unpack_int(&uk);
		char *name = unpack_string(&uk);

		wl = winlink_find_by_index(&s->windows, idx);
		if (!wl) {
			/* Avoid memory bloats with the scroll buffer */
			options_set_number(&s->options,
					   "history-limit", TMATE_HLIMIT);
			wl = session_new(s, name, "", NULL, idx, &cause);
			if (!wl)
				tmate_fatal("can't create window idx=%d", idx);
		}

		wl->flags &= ~WINLINK_KILL;
		w = wl->window;

		free(w->name);
		w->name = name;
		w->sx = s->sx;
		w->sy = s->sy;

		tmate_sync_window_panes(w, &uk);
	}

	RB_FOREACH_SAFE(wl, winlinks, &s->windows, wl_tmp) {
		if (wl->flags & WINLINK_KILL)
			session_detach(s, wl);
	}

	active_window_idx = unpack_int(s_uk);
	wl = winlink_find_by_index(&s->windows, active_window_idx);
	if (!wl)
		tmate_fatal("no valid active window");

	session_set_current(s, wl);
	server_redraw_window(wl->window);
}

static void tmate_sync_layout(struct tmate_decoder *decoder,
			      struct tmate_unpacker *uk)
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

static void tmate_pty_data(struct tmate_decoder *decoder,
			   struct tmate_unpacker *uk)
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

static void tmate_exec_cmd(struct tmate_decoder *decoder,
			   struct tmate_unpacker *uk)
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

static void tmate_failed_cmd(struct tmate_decoder *decoder,
			     struct tmate_unpacker *uk)
{
	struct client *c;
	unsigned int i;
	int client_id;
	char *cause;

	client_id = unpack_int(uk);
	cause = unpack_string(uk);

	for (i = 0; i < ARRAY_LENGTH(&clients); i++) {
		c = ARRAY_ITEM(&clients, i);
		if (c && c->id == client_id) {
			*cause = toupper((u_char) *cause);
			status_message_set(c, "%s", cause);
			break;
		}
	}

	free(cause);
}

static void tmate_status(struct tmate_decoder *decoder,
			 struct tmate_unpacker *uk)
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

extern void window_copy_redraw_screen(struct window_pane *);
extern int window_copy_update_selection(struct window_pane *);
extern void window_copy_init_for_output(struct window_pane *);

static void tmate_sync_copy_mode(struct tmate_decoder *decoder,
				 struct tmate_unpacker *uk)
{
	struct tmate_unpacker cm_uk, sel_uk, input_uk;
	struct window_copy_mode_data *data;
	struct screen_write_ctx ctx;
	struct window_pane *wp;
	int pane_id;
	int base_backing = 1;

	pane_id = unpack_int(uk);
	wp = window_pane_find_by_id(pane_id);
	if (!wp)
		tmate_fatal("can't find window pane=%d", pane_id);

	unpack_array(uk, &cm_uk);

	if (cm_uk.argc == 0) {
		if (wp->mode) {
			data = wp->modedata;
			free((char *)data->inputprompt);
			window_pane_reset_mode(wp);
		}
		return;
	}

	if (decoder->protocol >= 2)
		base_backing = unpack_int(&cm_uk);

	if (window_pane_set_mode(wp, &window_copy_mode) == 0) {
		if (base_backing)
			window_copy_init_from_pane(wp);
		else
			window_copy_init_for_output(wp);
	}
	data = wp->modedata;

	data->oy = unpack_int(&cm_uk);
	data->cx = unpack_int(&cm_uk);
	data->cy = unpack_int(&cm_uk);

	unpack_array(&cm_uk, &sel_uk);

	if (sel_uk.argc) {
		data->screen.sel.flag = 1;
		data->selx = unpack_int(&sel_uk);
		if (decoder->protocol >= 2) {
			data->sely = -unpack_int(&sel_uk) + screen_hsize(data->backing)
							  + screen_size_y(data->backing)
							  - 1;
		} else
			data->sely = unpack_int(&sel_uk);
		data->rectflag = unpack_int(&sel_uk);
	} else
		data->screen.sel.flag = 0;

	unpack_array(&cm_uk, &input_uk);

	if (input_uk.argc) {
		/*
		 * XXX In the original tmux code, inputprompt is not a
		 * malloced string, the two piece of code must not run at the
		 * same time, otherwise, we'll either get a memory leak, or a
		 * crash.
		 */
		data->inputtype = unpack_int(&input_uk);

		free((char *)data->inputprompt);
		data->inputprompt = unpack_string(&input_uk);

		free(data->inputstr);
		data->inputstr = unpack_string(&input_uk);
	} else {
		data->inputtype = WINDOW_COPY_OFF;
		free((char *)data->inputprompt);
		data->inputprompt = NULL;
	}

	window_copy_update_selection(wp);
	window_copy_redraw_screen(wp);
}

static void tmate_write_copy_mode(struct tmate_decoder *decoder,
				  struct tmate_unpacker *uk)
{
	struct window_pane *wp;
	int id;
	char *str;

	id = unpack_int(uk);
	wp = window_pane_find_by_id(id);
	if (!wp)
		tmate_fatal("can't find pane id=%d", id);

	str = unpack_string(uk);

	if (window_pane_set_mode(wp, &window_copy_mode) == 0)
		window_copy_init_for_output(wp);

	window_copy_add(wp, "%s", str);
	free(str);
}

static void handle_message(struct tmate_decoder *decoder, msgpack_object obj)
{
	struct tmate_unpacker _uk;
	struct tmate_unpacker *uk = &_uk;
	int cmd;

	init_unpacker(uk, obj);

	cmd = unpack_int(uk);

#if 0
	/* Really verbose tracers */
	if (cmd != TMATE_PTY_DATA) {
		msgpack_object_print(stderr, obj);
		fprintf(stderr, "\n");
	}
#endif

	switch (cmd) {
	case TMATE_HEADER:		tmate_header(decoder, uk);		break;
	case TMATE_SYNC_LAYOUT:		tmate_sync_layout(decoder, uk);		break;
	case TMATE_PTY_DATA:		tmate_pty_data(decoder, uk);		break;
	case TMATE_EXEC_CMD:		tmate_exec_cmd(decoder, uk);		break;
	case TMATE_FAILED_CMD:		tmate_failed_cmd(decoder, uk);		break;
	case TMATE_STATUS:		tmate_status(decoder, uk);		break;
	case TMATE_SYNC_COPY_MODE:	tmate_sync_copy_mode(decoder, uk);	break;
	case TMATE_WRITE_COPY_MODE:	tmate_write_copy_mode(decoder, uk);	break;
	default:			decoder_error();
	}
}

void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len)
{
	msgpack_unpacked result;

	msgpack_unpacker_buffer_consumed(&decoder->unpacker, len);

	msgpack_unpacked_init(&result);
	while (msgpack_unpacker_next(&decoder->unpacker, &result)) {
		handle_message(decoder, result.data);
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
