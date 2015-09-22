#ifndef TMATE_PROTOCOL_H
#define TMATE_PROTOCOL_H

 /* 17 and not 16 because the sender does not takes into account envelope size */
#define TMATE_MAX_MESSAGE_SIZE (17*1024)

#define CONTROL_PROTOCOL_VERSION 1

/* TODO document each msg */

enum tmate_control_out_msg_types {
	TMATE_CTL_AUTH,
	TMATE_CTL_DEAMON_OUT_MSG,
};

enum tmate_control_in_msg_types {
	TMATE_CTL_DEAMON_FWD_MSG,
};

enum tmate_daemon_out_msg_types {
	TMATE_OUT_HEADER,
	TMATE_OUT_SYNC_LAYOUT,
	TMATE_OUT_PTY_DATA,
	TMATE_OUT_EXEC_CMD,
	TMATE_OUT_FAILED_CMD,
	TMATE_OUT_STATUS,
	TMATE_OUT_SYNC_COPY_MODE,
	TMATE_OUT_WRITE_COPY_MODE,
};
enum tmate_daemon_in_msg_types {
	TMATE_IN_NOTIFY,
	TMATE_IN_PANE_KEY,
	TMATE_IN_RESIZE,
	TMATE_IN_EXEC_CMD,
	TMATE_IN_SET_ENV,
	TMATE_IN_READY,
};

#endif
