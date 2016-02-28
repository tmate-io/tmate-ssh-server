#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <stdio.h>
#include <event.h>
#include <arpa/inet.h>
#include <time.h>

#include "tmate.h"

static void on_keepalive_timer(evutil_socket_t fd, short what, void *arg);

static void start_keepalive_timer(struct tmate_ssh_client *client,
				  int timeout_ms)
{
	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000)*1000;

	evtimer_set(&client->ev_keepalive_timer, on_keepalive_timer, client);
	evtimer_add(&client->ev_keepalive_timer, &tv);
}

static void on_keepalive_timer(__unused evutil_socket_t fd,
			       __unused short what, void *arg)
{
	struct tmate_ssh_client *client = arg;

	if (ssh_send_keepalive(client->session) == SSH_ERROR)
		return;

#ifdef ENABLE_LATENCY
	if (client->keepalive_sent_at.tv_sec == 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &client->keepalive_sent_at) < 0)
		    tmate_fatal("cannot clock_gettime()");
	}
#endif

	/*
	 * We restart the timer here as opposed to the ssh_pong callback,
	 * because some clients may be broken and our callback may not be
	 * called, and we must ensure that we send keepalives periodically
	 * because some connections may get closed for inactivity due to the
	 * presence of hostile routers.
	 */
	start_keepalive_timer(client, client->keepalive_interval_ms);
}


#ifdef ENABLE_LATENCY
static void timespec_subtract(struct timespec *result,
			      struct timespec *x, struct timespec *y);

static unsigned long long timespec_to_millisec(struct timespec *ts);

static void ssh_pong(struct tmate_ssh_client *client)
{
	struct timespec now, tmp;
	int latency_ms;

	if (!client->latency_cb)
		return;

	if (!client->keepalive_sent_at.tv_sec)
		return;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		tmate_fatal("cannot clock_gettime()");

	timespec_subtract(&tmp, &now, &client->keepalive_sent_at);
	latency_ms = timespec_to_millisec(&tmp);
	client->latency_cb(client->latency_cb_userdata, latency_ms);

	client->keepalive_sent_at.tv_sec = 0;
}

static void ssh_request_denied_callback(__unused ssh_session session, void *userdata)
{
	ssh_pong(userdata);
}

static void ssh_unimplemented_packet_callback(__unused ssh_session session,
					      __unused uint32_t seq, void *userdata)
{
	ssh_pong(userdata);
}

void tmate_start_ssh_latency_probes(struct tmate_ssh_client *client,
				    struct ssh_server_callbacks_struct *server_callbacks,
				    int keepalive_interval_ms)
{
	client->keepalive_interval_ms = keepalive_interval_ms;
	client->latency_cb = NULL;
	server_callbacks->client_unimplemented_packet_function = ssh_unimplemented_packet_callback;
	server_callbacks->client_request_denied_function = ssh_request_denied_callback;
	client->keepalive_sent_at.tv_sec = 0;
	start_keepalive_timer(client, 3000);
}

void tmate_add_ssh_latency_callback(struct tmate_ssh_client *client,
				    ssh_client_latency_cb cb, void *userdata)
{
	if (client->latency_cb)
		tmate_fatal("only one latency callback for now");

	client->latency_cb = cb;
	client->latency_cb_userdata = userdata;
}

static void timespec_subtract(struct timespec *result,
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

static unsigned long long timespec_to_millisec(struct timespec *ts)
{
	return ts->tv_sec * 1000ULL + ts->tv_nsec / 1000000ULL;
}

#else

void tmate_start_ssh_latency_probes(struct tmate_ssh_client *client,
				    __unused struct ssh_server_callbacks_struct *server_callbacks,
				    int keepalive_interval_ms)
{
	client->keepalive_interval_ms = keepalive_interval_ms;
	start_keepalive_timer(client, 3000);
}

void tmate_add_ssh_latency_callback(__unused struct tmate_ssh_client *client,
				    __unused ssh_client_latency_cb cb, __unused void *userdata)
{
}


#endif
