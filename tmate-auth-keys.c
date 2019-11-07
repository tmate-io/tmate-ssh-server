#include <sys/socket.h>
#include <sys/un.h>

#include "tmate.h"

static void reset_and_enable_authorized_keys(void)
{
	ssh_key *keys = tmate_session->authorized_keys;
	if (keys) {
		for (ssh_key *k = keys; *k; k++)
			ssh_key_free(*k);
		free(keys);
	}

	keys = xreallocarray(NULL, sizeof(ssh_key), 1);
	keys[0] = NULL;

	tmate_session->authorized_keys = keys;
}

static ssh_key import_ssh_pubkey64(const char *_keystr)
{
	/* key is formatted as "type base64_key" */

	char * const keystr = xstrdup(_keystr);
	char *s = keystr;
	ssh_key ret = NULL;

	char *key_type = strsep(&s, " ");
	char *key_content = strsep(&s, " ");

	if (!key_content)
		goto out;

	enum ssh_keytypes_e type = ssh_key_type_from_name(key_type);
	if (type == SSH_KEYTYPE_UNKNOWN)
		goto out;

	if (ssh_pki_import_pubkey_base64(key_content, type, &ret) != SSH_OK) {
		ret = NULL;
		goto out;
	}
out:
	free(keystr);
	return ret;
}

int get_num_authorized_keys(ssh_key *keys)
{
	if (!keys)
		return 0;

	int count = 0;
	for (ssh_key *k = keys; *k; k++)
		count++;
	return count;
}

static void append_authorized_key(const char *keystr)
{
	if (!tmate_session->authorized_keys)
		reset_and_enable_authorized_keys();

	ssh_key pkey = import_ssh_pubkey64(keystr);
	if (!pkey)
		return;

	ssh_key *keys = tmate_session->authorized_keys;
	int count = get_num_authorized_keys(keys);
	keys = xreallocarray(keys, sizeof(ssh_key), count+2);
	tmate_session->authorized_keys = keys;

	keys[count++] = pkey;
	keys[count] = NULL;
}

static void tmate_set(char *key, char *value)
{
	if (!strcmp(key, "authorized_keys"))
		append_authorized_key(value);
}

void tmate_hook_set_option_auth(const char *name, const char *val)
{
	if (!strcmp(name, "tmate-authorized-keys")) {
		reset_and_enable_authorized_keys();
	} else if (!strcmp(name, "tmate-set")) {
		char *key_value = xstrdup(val);
		char *s = key_value;

		char *key = strsep(&s, "=");
		char *value = s;
		if (value)
			tmate_set(key, value);

		free(key_value);
	}
}

bool tmate_allow_auth(const char *pubkey)
{
	/*
	 * Note that we don't accept connections on the tmux socket until we
	 * get the tmate ready message.
	 */
	if (!tmate_session->authorized_keys)
		return true;

	if (!pubkey)
		return false;

	ssh_key client_pkey = import_ssh_pubkey64(pubkey);
	if (!client_pkey)
		return false;

	bool ret = false;
	for (ssh_key *k = tmate_session->authorized_keys; *k; k++) {
		if (!ssh_key_cmp(client_pkey, *k, SSH_KEY_CMP_PUBLIC)) {
			ret = true;
			break;
		}
	}

	ssh_key_free(client_pkey);

	return ret;
}

static int write_all(int fd, const char *buf, size_t len)
{
	for (size_t i = 0; i < len;)  {
		size_t ret = write(fd, buf+i, len-i);
		if (ret <= 0)
			return -1;
		i += ret;
	}
	return 0;
}

static int read_all(int fd, char *buf, size_t len)
{
	for (size_t i = 0; i < len;)  {
		size_t ret = read(fd, buf+i, len-i);
		if (ret <= 0)
			return -1;
		i += ret;
	}

	return 0;
}

/*
 * The following is executed in the context of the SSH server
 */
bool would_tmate_session_allow_auth(const char *token, const char *pubkey)
{
	/*
	 * The existance of this function is a bit unpleasant:
	 * In order to have the right SSH public key from the SSH client,
	 * we need to ask the tmate session for a match. Denying the key
	 * to the SSH client will make it cycle through its keys.
	 * We briefly connect to the session to get an answer.
	 *
	 * Note that the client will get reauthenticated later (see
	 * server-client.c when identifying the client).
	 */
	int sock_fd = -1;
	int ret = true;

	if (tmate_validate_session_token(token) < 0)
		goto out;

	char *sock_path = get_socket_path(token);

	struct sockaddr_un sa;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	size_t size = strlcpy(sa.sun_path, sock_path, sizeof(sa.sun_path));
	free(sock_path);
	if (size >= sizeof sa.sun_path)
		goto out;

	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_fd < 0)
		goto out;

	if (connect(sock_fd, (struct sockaddr *)&sa, sizeof sa) == -1)
		goto out;

	struct imsg_hdr hdr = {
		.type = pubkey ? MSG_IDENTIFY_TMATE_AUTH_PUBKEY :
				 MSG_IDENTIFY_TMATE_AUTH_NONE,
		.len = IMSG_HEADER_SIZE + (pubkey ? strlen(pubkey)+1 : 0),
		.flags = 0,
		.peerid = PROTOCOL_VERSION,
		.pid = -1,
	};

	if (write_all(sock_fd, (void*)&hdr, sizeof(hdr)) < 0)
		goto out;

	if (pubkey) {
		if (write_all(sock_fd, pubkey, strlen(pubkey)+1) < 0)
			goto out;
	}

	struct {
		struct imsg_hdr hdr;
		bool allow;
	} __packed recv_msg;

	if (read_all(sock_fd, (void*)&recv_msg, sizeof(recv_msg)) < 0)
		goto out;

	if (recv_msg.hdr.type == MSG_TMATE_AUTH_STATUS &&
	    recv_msg.hdr.len == sizeof(recv_msg))
		ret = recv_msg.allow;

	tmate_info("(preauth) allow=%d", ret);

out:
	if (sock_fd != -1)
		close(sock_fd);
	return ret;
}
