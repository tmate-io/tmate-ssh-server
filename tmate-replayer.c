#include <ctype.h>
#include <unistd.h>
#include "tmate.h"

#ifdef TMATE_RECORD_REPLAY

#define READ_MAX_SIZE 1024
#define TIMER_INERVAL_USEC 1000

extern int server_shutdown;
extern void server_send_shutdown(void);

static void start_timer(struct tmate_replayer *replayer);

static void on_read_timer(evutil_socket_t fd, short what, void *arg)
{
	struct tmate_replayer *replayer = arg;
	char *buf;
	ssize_t len;

	if (replayer->log_fd < 0) {
		evtimer_del(&replayer->ev_read_timer);
		server_shutdown = 1;
		server_send_shutdown();
		return;
	}

	tmate_decoder_get_buffer(replayer->decoder, &buf, &len);
	if (len == 0)
		tmate_fatal("Decoder buffer full");

	if (len > READ_MAX_SIZE)
		len = READ_MAX_SIZE;

	len = read(replayer->log_fd, buf, len);
	if (len < 0)
		tmate_fatal("cannot read from replay log file");

	if (len == 0) {
		tmate_info("Replay file reached EOF");
		replayer->log_fd = -1;
	} else {
		tmate_decoder_commit(replayer->decoder, len);
	}

	start_timer(replayer);
}

static void start_timer(struct tmate_replayer *replayer)
{
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = TIMER_INERVAL_USEC;

	evtimer_assign(&replayer->ev_read_timer, ev_base,
		       on_read_timer, replayer);
	evtimer_add(&replayer->ev_read_timer, &tv);
}

void tmate_replayer_init(struct tmate_replayer *replayer,
			 struct tmate_decoder *decoder,
			 int log_fd)
{
	replayer->decoder = decoder;
	replayer->log_fd = log_fd;

	start_timer(replayer);
}

#endif
