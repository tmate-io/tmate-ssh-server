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

void start_keepalive_timer(struct tmate_ssh_client *client, int timeout_ms)
{
	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000)*1000;

	client->keepalive_interval_ms = timeout_ms;

	evtimer_set(&client->ev_keepalive_timer, on_keepalive_timer, client);
	evtimer_add(&client->ev_keepalive_timer, &tv);
}

static void on_keepalive_timer(__unused evutil_socket_t fd,
			       __unused short what, void *arg)
{
	struct tmate_ssh_client *client = arg;

	/*
	 * libssh 0.8.4, 0.8.5, and 0.8.6 can't handle the response of the
	 * keepalives due to packet filtering.
	 */

	if (ssh_version(SSH_VERSION_INT(0,8,4)) && !ssh_version(SSH_VERSION_INT(0,8,7)))
		return;

	if (ssh_send_keepalive(client->session) == SSH_ERROR)
		return;

	start_keepalive_timer(client, client->keepalive_interval_ms);
}
