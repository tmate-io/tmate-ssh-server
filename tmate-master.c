#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>

#include "tmate.h"
#include "tmate-protocol.h"

#define CONTROL_PROTOCOL_VERSION 1

#define pack(what, ...) _pack(&tmate_session->master_encoder, what, __VA_ARGS__)

static void ctl_daemon_fwd_msg(struct tmate_session *session,
			       struct tmate_unpacker *uk)
{
	if (uk->argc != 1)
		tmate_decoder_error();
	tmate_send_mc_obj(&uk->argv[0]);
}

static void do_snapshot(struct tmate_unpacker *uk,
			unsigned int max_history_lines,
			struct window_pane *pane)
{
	struct screen *screen;
	struct grid *grid;
	struct grid_line *line;
	struct grid_cell *cell;
	struct utf8_data utf8;
	unsigned int line_i, i;
	unsigned int max_lines;
	size_t str_len;

	screen = &pane->base;
	grid = screen->grid;

	pack(array, 4);
	pack(int, pane->id);

	pack(array, 2);
	pack(int, screen->cx);
	pack(int, screen->cy);

	pack(unsigned_int, screen->mode);

	max_lines = max_history_lines + grid->sy;

#define grid_num_lines(grid) (grid->hsize + grid->sy)

	if (grid_num_lines(grid) > max_lines)
		line_i = grid_num_lines(grid) - max_lines;
	else
		line_i = 0;

	pack(array, grid_num_lines(grid) - line_i);
	for (; line_i < grid_num_lines(grid); line_i++) {
		line = &grid->linedata[line_i];

		pack(array, 2);
		str_len = 0;
		for (i = 0; i < line->cellsize; i++) {
			cell = &line->celldata[i];
			grid_cell_get(cell, &utf8);
			str_len += utf8.size;
		}

		pack(raw, str_len);
		for (i = 0; i < line->cellsize; i++) {
			cell = &line->celldata[i];
			grid_cell_get(cell, &utf8);
			pack(raw_body, utf8.data, utf8.size);
		}

		pack(array, line->cellsize);
		for (i = 0; i < line->cellsize; i++) {
			cell = &line->celldata[i];
			pack(unsigned_int, ((cell->flags << 24) |
					    (cell->attr  << 16) |
					    (cell->bg    << 8)  |
					     cell->fg        ));
		}
	}
}

static void ctl_daemon_request_snapshot(struct tmate_session *session,
					struct tmate_unpacker *uk)
{
	struct session *s;
	struct winlink *wl;
	struct window *w;
	struct window_pane *pane;
	int max_history_lines;
	int num_panes;

	max_history_lines = unpack_int(uk);

	pack(array, 2);
	pack(int, TMATE_CTL_SNAPSHOT);

	s = RB_MIN(sessions, &sessions);
	if (!s)
		tmate_fatal("no session?");

	num_panes = 0;
	RB_FOREACH(wl, winlinks, &s->windows) {
		w = wl->window;
		if (!w)
			continue;

		TAILQ_FOREACH(pane, &w->panes, entry)
			num_panes++;
	}

	pack(array, num_panes);
	RB_FOREACH(wl, winlinks, &s->windows) {
		w = wl->window;
		if (!w)
			continue;

		TAILQ_FOREACH(pane, &w->panes, entry)
			do_snapshot(uk, max_history_lines, pane);
	}
}

static void ctl_pane_keys(struct tmate_session *session,
			  struct tmate_unpacker *uk)
{
	int i;
	int pane_id;
	char *str;

	pane_id = unpack_int(uk);
	str = unpack_string(uk);

	/* a new protocol might be useful :) */
	/* TODO Make pane_id active! the pane_id arg is ignored! */
	for (i = 0; str[i]; i++)
		tmate_client_pane_key(pane_id, str[i]);

	free(str);
}

void tmate_dispatch_master_message(struct tmate_session *session,
				   struct tmate_unpacker *uk)
{
	int cmd = unpack_int(uk);
	switch (cmd) {
#define dispatch(c, f) case c: f(session, uk); break
	dispatch(TMATE_CTL_DEAMON_FWD_MSG,	ctl_daemon_fwd_msg);
	dispatch(TMATE_CTL_REQUEST_SNAPSHOT,	ctl_daemon_request_snapshot);
	dispatch(TMATE_CTL_PANE_KEYS,		ctl_pane_keys);
	default: tmate_fatal("Bad master message type: %d", cmd);
	}
}

void tmate_send_master_daemon_msg(struct tmate_session *session,
				  struct tmate_unpacker *uk)
{
	struct timespec time_diff, current_time;
	int i;

	if (!tmate_has_master())
		return;

	pack(array, 2);
	pack(int, TMATE_CTL_DEAMON_OUT_MSG);

	pack(array, uk->argc);
	for (i = 0; i < uk->argc; i++)
		pack(object, uk->argv[i]);
}

void tmate_send_master_header(struct tmate_session *session)
{
	if (!tmate_has_master())
		return;

	pack(array, 6);
	pack(int, TMATE_CTL_AUTH);
	pack(int, CONTROL_PROTOCOL_VERSION);
	pack(string, session->ssh_client.ip_address);
	pack(string, session->ssh_client.pubkey);
	pack(string, session->session_token);
	pack(string, session->session_token_ro);
}

void tmate_init_master_session(struct tmate_session *session)
{
	if (!tmate_has_master())
		return;

	/* Further init */
}

static int _tmate_connect_to_master(const char *hostname, int port)
{
	int sockfd = -1;
	struct sockaddr_in servaddr;
	struct hostent *host;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		tmate_fatal("Cannot create socket");

	host = gethostbyname(hostname);
	if (!host)
		tmate_fatal("Cannot resolve %s", hostname);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = host->h_addrtype;
	memcpy(&servaddr.sin_addr, host->h_addr, host->h_length);
	servaddr.sin_port = htons(port);

	if (connect(sockfd, &servaddr, sizeof(servaddr)) < 0)
		tmate_fatal("Cannot connect to master at %s:%d", hostname, port);

	int flag = 1;
	if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
		tmate_fatal("Can't set master socket to TCP_NODELAY");

	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)
		tmate_fatal("Can't set master socket to non-blocking");

	tmate_notice("Connected to master at %s:%d", hostname, port);

	return sockfd;
}

int tmate_connect_to_master(void)
{
	return _tmate_connect_to_master(tmate_settings->master_hostname,
					tmate_settings->master_port);
}
