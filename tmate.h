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

enum tmate_client_commands {
	TMATE_REPLY_HEADER,
	TMATE_CLIENT_PANE_KEY,
	TMATE_CLIENT_RESIZE,
	TMATE_CLIENT_EXEC_CMD,
};

struct tmate_encoder {
	struct evbuffer *buffer;
	struct event ev_readable;
	msgpack_packer pk;
};

extern void tmate_encoder_init(struct tmate_encoder *encoder);

extern void tmate_reply_header(unsigned long flags);
extern void tmate_client_resize(u_int sx, u_int sy);
extern void tmate_client_pane_key(int pane_id, int key);
extern void tmate_client_cmd(int client_id, const char *cmd);
extern void tmate_client_set_active_pane(int client_id, int win_idx, int pane_id);
extern int tmate_should_exec_cmd_locally(const struct cmd_entry *cmd);

/* tmate-decoder.c */

#define TMATE_HLIMIT 2000
#define TMATE_MAX_MESSAGE_SIZE (16*1024)

extern char *tmate_left_status, *tmate_right_status;

enum tmate_commands {
	TMATE_HEADER,
	TMATE_SYNC_LAYOUT,
	TMATE_PTY_DATA,
	TMATE_EXEC_CMD,
	TMATE_FAILED_CMD,
	TMATE_STATUS,
	TMATE_SYNC_COPY_MODE,
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

#define TMATE_ROLE_SERVER 1
#define TMATE_ROLE_CLIENT 2

struct tmate_ssh_client {
	ssh_session session;
	ssh_channel channel;

	int role;

	struct tmate_encoder *encoder;
	struct tmate_decoder *decoder;

	char *username;
	char *pubkey;

	struct winsize winsize_pty;

	struct event ev_ssh;

	/* only for client-pty */
	int pty;
	struct event ev_pty;
};
extern void tmate_ssh_client_init(struct tmate_ssh_client *client,
				  struct tmate_encoder *encoder,
				  struct tmate_decoder *decoder);

/* tmate-ssh-client-pty.c */

extern void tmate_ssh_client_pty_init(struct tmate_ssh_client *client);
extern void tmate_flush_pty(struct tmate_ssh_client *client);

/* tmate-ssh-server.c */

#define SSH_BANNER "tmate"

extern void tmate_ssh_server_main(int port);

/* tmate-slave.c */

#ifdef DEVENV
#define TMATE_DEFAULT_PORT 2200
#else
#define TMATE_DEFAULT_PORT 22
#endif

#define TMATE_TOKEN_LEN 25
#define TMATE_WORKDIR "/tmp/tmate"
#define TMATE_JAIL_USER "nobody"

extern struct tmate_encoder *tmate_encoder;
extern int tmux_socket_fd;
extern const char *tmate_session_token;

extern void tmate_spawn_slave(struct tmate_ssh_client *client);

/* tmate-debug.c */
extern void tmate_print_trace(void);

/* tmux-bare.c */

extern void tmux_server_init(int flags);

#endif
