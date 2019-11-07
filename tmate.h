#ifndef TMATE_H
#define TMATE_H

#include <sys/syslog.h>
#include <sys/types.h>
#include <msgpack.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <event.h>
#include <time.h>

#include "tmux.h"
struct tmate_session;

/* log.c */

extern void init_logging(const char *program_name, bool use_syslog, int log_level);
extern void printflike(2, 3) tmate_log(int level, const char *msg, ...);

#define tmate_debug(str, ...)	tmate_log(LOG_DEBUG, str, ##__VA_ARGS__)
#define tmate_info(str, ...)	tmate_log(LOG_INFO, str, ##__VA_ARGS__)
#define tmate_notice(str, ...)	tmate_log(LOG_NOTICE, str, ##__VA_ARGS__)
#define tmate_warn(str, ...)	tmate_log(LOG_WARNING, str, ##__VA_ARGS__)
#define tmate_crit(str, ...)	tmate_log(LOG_CRIT, str, ##__VA_ARGS__)
#define tmate_fatal(str, ...)					\
({								\
	tmate_crit("fatal: " str, ##__VA_ARGS__);		\
 	exit(1);						\
})
#define tmate_fatal_info(str, ...)				\
({								\
	tmate_info("fatal: " str, ##__VA_ARGS__);		\
 	exit(1);						\
})

/* tmate-auth-keys.c */
extern void tmate_hook_set_option(const char *name, const char *val);
extern bool tmate_allow_auth(const char *pubkey);
extern bool would_tmate_session_allow_auth(const char *token, const char *pubkey);
extern int get_num_authorized_keys(ssh_key *keys);

/* tmate-msgpack.c */

typedef void tmate_encoder_write_cb(void *userdata, struct evbuffer *buffer);

struct tmate_encoder {
	msgpack_packer pk;
	int mpac_version;
	tmate_encoder_write_cb *ready_callback;
	void *userdata;
	struct evbuffer *buffer;
	struct event ev_buffer;
	bool ev_active;
};

extern void tmate_encoder_init(struct tmate_encoder *encoder,
			       tmate_encoder_write_cb *callback,
			       void *userdata);

/* These functions deal with dual v4/v5 support through mpac_version */
extern void msgpack_pack_string(msgpack_packer *pk, const char *str);
extern void msgpack_pack_boolean(msgpack_packer *pk, bool value);
extern int _msgpack_pack_object(msgpack_packer *pk, msgpack_object d);
#define msgpack_pack_object _msgpack_pack_object

#define _pack(enc, what, ...) msgpack_pack_##what(&(enc)->pk, ##__VA_ARGS__)

struct tmate_unpacker;
struct tmate_decoder;
typedef void tmate_decoder_reader(void *userdata, struct tmate_unpacker *uk);

struct tmate_decoder {
	struct msgpack_unpacker unpacker;
	tmate_decoder_reader *reader;
	void *userdata;
};

extern void tmate_decoder_init(struct tmate_decoder *decoder, tmate_decoder_reader *reader, void *userdata);
extern void tmate_decoder_get_buffer(struct tmate_decoder *decoder, char **buf, size_t *len);
extern void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len);

struct tmate_unpacker {
	int argc;
	msgpack_object *argv;
};

extern void init_unpacker(struct tmate_unpacker *uk, msgpack_object obj);
extern void tmate_decoder_error(void);
extern int64_t unpack_int(struct tmate_unpacker *uk);
extern bool unpack_bool(struct tmate_unpacker *uk);
extern void unpack_buffer(struct tmate_unpacker *uk, const char **buf, size_t *len);
extern char *unpack_string(struct tmate_unpacker *uk);
extern void unpack_array(struct tmate_unpacker *uk, struct tmate_unpacker *nested);
extern msgpack_object_type unpack_peek_type(struct tmate_unpacker *uk);

#define unpack_each(nested_uk, tmp_uk, uk)						\
	for (unpack_array(uk, tmp_uk);							\
	     (tmp_uk)->argc > 0 && (init_unpacker(nested_uk, (tmp_uk)->argv[0]), 1);	\
	     (tmp_uk)->argv++, (tmp_uk)->argc--)

/* tmate-daemon-encoder.c */

extern void printflike(1, 2) tmate_notify(const char *fmt, ...);
extern void printflike(2, 3) tmate_notify_later(int timeout, const char *fmt, ...);

extern void tmate_client_resize(u_int sx, u_int sy);
extern void tmate_client_legacy_pane_key(int pane_id, int key);
extern void tmate_client_pane_key(int pane_id, key_code key);
extern void tmate_client_cmd_str(int client_id, const char *cmd);
extern void tmate_client_cmd_args(int client_id, int argc, const char **argv);
extern void tmate_client_cmd(int client_id, struct cmd *cmd);
extern void tmate_client_set_active_pane(int client_id, int win_idx, int pane_id);
extern int tmate_should_exec_cmd_locally(const struct cmd_entry *cmd);
extern void tmate_set_env(const char *name, const char *value);
extern void tmate_send_client_ready(void);
extern void tmate_send_mc_obj(msgpack_object *obj);

/* tmate-daemon-legacy.c */

extern void tmate_translate_legacy_key(int pane_id, key_code key);

/* tmate-daemon-decoder.c */

#define TMATE_HLIMIT 2000
#define TMATE_PANE_ACTIVE 1

extern char *tmate_left_status, *tmate_right_status;
extern void tmate_dispatch_daemon_message(struct tmate_session *session,
					  struct tmate_unpacker *uk);

/* tmate-ssh-daemon.c */

#define TMATE_KEYFRAME_INTERVAL_SEC 10
#define TMATE_KEYFRAME_MAX_SIZE 1024*1024

extern void tmate_spawn_daemon(struct tmate_session *session);

/* tmate-ssh-exec.c */
extern void tmate_spawn_exec(struct tmate_session *session);
extern void tmate_dump_exec_response(struct tmate_session *session,
				     int exit_code, const char *message);

/* tmate-ssh-client-pty.c */
extern void tmate_spawn_pty_client(struct tmate_session *session);
extern int tmate_validate_session_token(const char *token);

/* tmate-ssh-server.c */

#define TMATE_SSH_BANNER "tmate"
#define TMATE_SSH_KEEPALIVE_SEC 300

#define TMATE_ROLE_DAEMON	1
#define TMATE_ROLE_PTY_CLIENT	2
#define TMATE_ROLE_EXEC		3

struct tmate_ssh_client;
typedef void ssh_client_latency_cb(void *userdata, int latency_ms);
extern char *get_ssh_conn_string(const char *session_token);
extern void start_keepalive_timer(struct tmate_ssh_client *client, int timeout_ms);

struct tmate_ssh_client {
	char ip_address[64];

	ssh_session session;
	ssh_channel channel;
	/*
	 * We need to store the entire callback struct because
	 * libssh stores the userdata within the cb struct...
	 */
	struct ssh_channel_callbacks_struct channel_cb;

	int role;

	char *username;
	char *pubkey;

	char *exec_command;

	struct winsize winsize_pty;

	struct event ev_ssh;

	struct event ev_keepalive_timer;
	int keepalive_interval_ms;
};

extern void tmate_ssh_server_main(struct tmate_session *session,
				  const char *keys_dir, const char *bind_addr, int port);

/* tmate-main.c */

#ifdef DEVENV
#define TMATE_SSH_DEFAULT_PORT 2200
#else
#define TMATE_SSH_DEFAULT_PORT 22
#endif

#define TMATE_SSH_GRACE_PERIOD 20

#define TMATE_SSH_DEFAULT_KEYS_DIR "keys"

#define TMATE_DEFAULT_WEBSOCKET_PORT 4002

#define TMATE_TOKEN_LEN 25
#define TMATE_WORKDIR "/tmp/tmate"
#define TMATE_JAIL_USER "nobody"

struct tmate_settings {
	const char *keys_dir;
	const char *authorized_keys_path;
	int ssh_port;
	int ssh_port_advertized;
	const char *websocket_hostname;
	int websocket_port;
	const char *tmate_host;
	const char *bind_addr;
	int log_level;
	bool use_proxy_protocol;
	bool use_syslog;
};
extern struct tmate_settings *tmate_settings;

typedef void on_websocket_error_cb(struct tmate_session *session, short events);

struct tmate_session {
	struct event_base *ev_base;
	struct tmate_ssh_client ssh_client;
	int tmux_socket_fd;

	/* only for role deamon */
	ssh_key *authorized_keys; /* array with NULL as last element */

	const char *session_token;
	const char *session_token_ro;
	const char *obfuscated_session_token; /* for logging purposes */

	struct tmate_encoder daemon_encoder;
	struct tmate_decoder daemon_decoder;
	const char *client_version;
	int client_protocol_version;
	struct event ev_notify_timer;
	bool fin_received;

	int websocket_fd;
	struct bufferevent *bev_websocket;
	struct tmate_encoder websocket_encoder;
	struct tmate_decoder websocket_decoder;
	u_int websocket_sx, websocket_sy;
	on_websocket_error_cb *on_websocket_error;

	/* only for role client-pty */
	int pty;
	struct event ev_pty;
	bool readonly;

	/* only for role-exec */
	bool response_received;
	bool response_status;
	const char *response_message;
};

extern struct tmate_session *tmate_session;
extern void tmate_get_random_bytes(void *buffer, ssize_t len);
extern long tmate_get_random_long(void);
extern void request_server_termination(void);
extern char *get_socket_path(const char *_token);
extern void set_session_token(struct tmate_session *session, const char *token);

extern void close_fds_except(int *fd_to_preserve, int num_fds);
extern void get_in_jail(void);

/* tmate-rand.c */
#define RS_BUF_SIZE 256

struct random_stream {
	char bytes[RS_BUF_SIZE];
	off_t pos;
};

extern void tmate_init_rand(void);
extern void tmate_get_random_bytes(void *buffer, ssize_t len);
extern long tmate_get_random_long(void);
extern void random_stream_init(struct random_stream *rs);
extern char *random_stream_get(struct random_stream *rs, size_t count);
extern void setup_ncurse(int fd, const char *name);

/* tmate-websocket.c */

extern void tmate_websocket_exec(struct tmate_session *session, const char *command);
extern void tmate_notify_client_join(struct tmate_session *s, struct client *c);
extern void tmate_notify_client_left(struct tmate_session *s, struct client *c);

extern void tmate_send_websocket_daemon_msg(struct tmate_session *session,
					struct tmate_unpacker *uk);
extern void tmate_send_websocket_header(struct tmate_session *session);
extern void tmate_init_websocket(struct tmate_session *session,
				 on_websocket_error_cb on_websocket_error);

extern int tmate_connect_to_websocket(void);
static inline bool tmate_has_websocket(void)
{
	return !!tmate_settings->websocket_hostname;
}

/* tmate-debug.c */

extern void tmate_preload_trace_lib(void);
extern void tmate_print_stack_trace(void);
extern void tmate_catch_sigsegv(void);

/* tmux.c */

extern void tmux_server_init(void);

/* server.c */
extern int server_create_socket(void);

/* log.c */
extern FILE *log_file;

/* client.c */
extern void client_signal(int sig);
extern int client_connect(struct event_base *base, const char *path, int start_server);

#endif
