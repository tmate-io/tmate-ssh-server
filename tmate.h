#ifndef TMATE_H
#define TMATE_H

#include <sys/types.h>
#include <msgpack.h>
#include <libssh/libssh.h>
#include <event.h>

#include "tmux.h"

// #define TMATE_RECORD_REPLAY /* useful to debug crashes */

#define tmate_debug(str, ...) log_debug("[tmate] " str, ##__VA_ARGS__)
#define tmate_info(str, ...)   log_info("[tmate] " str, ##__VA_ARGS__)
#define tmate_fatal(str, ...)				\
do {							\
	log_info("[tmate] FATAL " str, ##__VA_ARGS__);	\
	exit(-1);					\
} while (0)

/* tmate-encoder.c */

#define TMATE_LATEST_VERSION "1.8.10"

enum tmate_client_commands {
	TMATE_NOTIFY,
	TMATE_CLIENT_PANE_KEY,
	TMATE_CLIENT_RESIZE,
	TMATE_CLIENT_EXEC_CMD,
	TMATE_CLIENT_ENV,
	TMATE_CLIENT_READY,
};

struct tmate_encoder {
	struct evbuffer *buffer;
	struct event ev_readable;
	struct event ev_notify_timer;
	msgpack_packer pk;
};

extern void tmate_encoder_init(struct tmate_encoder *encoder);

extern void printflike1 tmate_notify(const char *fmt, ...);
extern void printflike2 tmate_notify_later(int timeout, const char *fmt, ...);
extern void tmate_notify_client_join(struct client *c);
extern void tmate_notify_client_left(struct client *c);

extern void tmate_client_resize(u_int sx, u_int sy);
extern void tmate_client_pane_key(int pane_id, int key);
extern void tmate_client_cmd(int client_id, const char *cmd);
extern void tmate_client_set_active_pane(int client_id, int win_idx, int pane_id);
extern int tmate_should_exec_cmd_locally(const struct cmd_entry *cmd);
extern void tmate_send_env(const char *name, const char *value);
extern void tmate_send_client_ready(void);

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
	TMATE_WRITE_COPY_MODE,
};

#define TMATE_PANE_ACTIVE 1

struct tmate_decoder {
	int protocol;

	struct msgpack_unpacker unpacker;
};

extern void tmate_decoder_init(struct tmate_decoder *decoder);
extern void tmate_decoder_get_buffer(struct tmate_decoder *decoder,
				     char **buf, size_t *len);
extern void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len);

#ifdef TMATE_RECORD_REPLAY
/* tmate-replayer.c */

struct tmate_replayer {
	struct tmate_decoder *decoder;
	int log_fd;

	struct event ev_read_timer;
};

extern void tmate_replayer_init(struct tmate_replayer *replayer,
				struct tmate_decoder *decoder,
				int log_fd);
#endif


/* tmate-ssh-client.c */

#define TMATE_ROLE_SERVER 1
#define TMATE_ROLE_CLIENT 2

struct tmate_ssh_client {
	char ip_address[64];

	ssh_session session;
	ssh_channel channel;

	int role;

	struct tmate_encoder *encoder;
	struct tmate_decoder *decoder;

	char *username;
	char *pubkey;

	struct winsize winsize_pty;

	struct event ev_ssh;
	struct event ev_keepalive_timer;

	/* only for client-pty */
	int pty;
	struct event ev_pty;
	int readonly;
};
extern void tmate_ssh_client_init(struct tmate_ssh_client *client,
				  struct tmate_encoder *encoder,
				  struct tmate_decoder *decoder);

/* tmate-ssh-client-pty.c */

extern void tmate_ssh_client_pty_init(struct tmate_ssh_client *client);
extern void tmate_flush_pty(struct tmate_ssh_client *client);

/* tmate-ssh-server.c */

#define TMATE_SSH_BANNER "tmate"
#define TMATE_KEEPALIVE 60

#ifdef TMATE_RECORD_REPLAY
extern int tmate_session_log_fd;
#endif

extern struct tmate_ssh_client tmate_client;
extern void tmate_start_keepalive_timer(struct tmate_ssh_client *client);
extern void tmate_ssh_server_main(const char *keys_dir, int port);

/* tmate-slave.c */

#ifdef DEVENV
#define TMATE_DEFAULT_PORT 2200
#else
#define TMATE_DEFAULT_PORT 22
#endif

#define TMATE_TOKEN_LEN 25
#define TMATE_WORKDIR "/tmp/tmate"
#define TMATE_JAIL_USER "nobody"

extern int tmate_port;
extern struct tmate_encoder *tmate_encoder;
extern struct tmate_decoder *tmate_decoder;
extern int tmux_socket_fd;
extern char *tmate_host;
extern const char *tmate_session_token;
extern const char *tmate_session_token_ro;

extern void tmate_get_random_bytes(void *buffer, ssize_t len);
extern long tmate_get_random_long(void);

extern void tmate_reopen_logfile(void);
extern void tmate_spawn_slave(struct tmate_ssh_client *client);

/* tmate-debug.c */

extern void tmate_preload_trace_lib(void);
extern void tmate_print_trace(void);

/* tmux-bare.c */

extern void tmux_server_init(int flags);

#endif
