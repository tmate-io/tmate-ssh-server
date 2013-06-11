#ifndef TMATE_H
#define TMATE_H

#include <sys/types.h>
#include <msgpack.h>
#include <event.h>

#include "tmux.h"

#define tmate_debug(str, ...) log_debug("[tmate] " str, ##__VA_ARGS__)
#define tmate_warn(str, ...)   log_warn("[tmate] " str, ##__VA_ARGS__)
#define tmate_info(str, ...)   log_info("[tmate] " str, ##__VA_ARGS__)
#define tmate_fatal(str, ...) log_fatal("[tmate] " str, ##__VA_ARGS__)

/* tmate-encoder.c */

enum tmate_notifications {
	TMATE_CLIENT_KEY,
	TMATE_CLIENT_RESIZE,
};

struct tmate_encoder {
	struct evbuffer *buffer;
	struct event ev_readable;
	msgpack_packer pk;
};

extern void tmate_encoder_init(struct tmate_encoder *encoder);

extern void tmate_write_header(void);
extern void tmate_write_pane(int pane, const char *data, size_t size);

extern void tmate_client_key(int key);
extern void tmate_client_resize(u_int sx, u_int sy);

/* tmate-decoder.c */

#define TMATE_HLIMIT 1000
#define TMATE_MAX_MESSAGE_SIZE (16*1024)

enum tmate_commands {
	TMATE_HEADER,
	TMATE_SYNC_WINDOW,
	TMATE_PTY_DATA,
};

#define TMATE_PANE_ACTIVE 1

struct tmate_decoder {
	struct msgpack_unpacker unpacker;
};

extern void tmate_decoder_init(struct tmate_decoder *decoder);
extern void tmate_decoder_get_buffer(struct tmate_decoder *decoder,
				     char **buf, size_t *len);
extern void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len);

/* tmate-ssh-client.c */

typedef struct ssh_session_struct* ssh_session;
typedef struct ssh_channel_struct* ssh_channel;

struct tmate_ssh_client {
	ssh_session session;
	ssh_channel channel;

	struct tmate_encoder *encoder;
	struct tmate_decoder *decoder;

	char *username;
	char *pubkey;

	struct winsize winsize_pty;

	struct event ev_ssh;
};
extern void tmate_ssh_client_init(struct tmate_ssh_client *ssh_client,
				  struct tmate_encoder *encoder,
				  struct tmate_decoder *decoder);

/* tmate-ssh-client-pty.c */

struct tmate_ssh_client_pty {
	ssh_session session;
	ssh_channel channel;

	int pty;
	struct winsize winsize_pty;

	struct event ev_ssh;
	struct event ev_pty;
};

extern void tmate_ssh_client_pty_init(struct tmate_ssh_client_pty *client);
extern void tmate_flush_pty(struct tmate_ssh_client_pty *client);

/* tmate-ssh-server.c */

#define SSH_BANNER "tmate"

extern void tmate_ssh_server_main(int port);

/* tmate-server.c */

extern struct tmate_encoder *tmate_encoder;

extern void tmate_spawn_slave_server(struct tmate_ssh_client *client);
extern void tmate_spawn_slave_client(struct tmate_ssh_client *client);

/* tmate-debug.c */
extern void tmate_print_trace(void);

#endif
