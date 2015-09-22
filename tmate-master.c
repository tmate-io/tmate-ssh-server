#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>

#include "tmate.h"
#include "tmate-protocol.h"

static void ctl_daemon_fwd_msg(struct tmate_session *session,
			       struct tmate_unpacker *uk)
{
	if (uk->argc != 1)
		tmate_decoder_error();
	tmate_send_mc_obj(&uk->argv[0]);
}

void tmate_dispatch_master_message(struct tmate_session *session,
				   struct tmate_unpacker *uk)
{
	int cmd = unpack_int(uk);
	switch (cmd) {
#define dispatch(c, f) case c: f(session, uk); break
	dispatch(TMATE_CTL_DEAMON_FWD_MSG,	ctl_daemon_fwd_msg);
	default: tmate_fatal("Bad master message type: %d", cmd);
	}
}

#define pack(what, ...) _pack(&tmate_session->master_encoder, what, __VA_ARGS__)

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

void timespec_subtract(struct timespec *result,
		       struct timespec *x, struct timespec *y)
{
	if (x->tv_nsec < y->tv_nsec) {
		result->tv_sec = x->tv_sec - y->tv_sec - 1;
		result->tv_nsec = x->tv_nsec - y->tv_nsec + 1000000000;
	} else {
		result->tv_sec = x->tv_sec - y->tv_sec;
		result->tv_nsec = x->tv_nsec - y->tv_nsec;
	}
}

unsigned long long timespec_to_millisec(struct timespec *ts)
{
	return ts->tv_sec * 1000ULL + ts->tv_nsec / 1000000ULL;
}
