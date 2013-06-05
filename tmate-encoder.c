#include "tmate.h"

static int msgpack_write(void *data, const char *buf, unsigned int len)
{
	struct tmate_encoder *encoder = data;

	evbuffer_add(encoder->buffer, buf, len);

	if ((encoder->ev_readable.ev_flags & EVLIST_INSERTED) &&
	    !(encoder->ev_readable.ev_flags & EVLIST_ACTIVE)) {
		event_active(&encoder->ev_readable, EV_READ, 0);
	}

	return 0;
}

void tmate_encoder_init(struct tmate_encoder *encoder)
{
	encoder->buffer = evbuffer_new();
	msgpack_packer_init(&encoder->pk, encoder, &msgpack_write);
}

#define pack(what, ...) msgpack_pack_##what(&tmate_encoder->pk, __VA_ARGS__)

void tmate_client_key(int key)
{
	pack(array, 2);
	pack(int, TMATE_CLIENT_KEY);
	pack(int, key);
}

void tmate_client_resize(u_int sx, u_int sy)
{
	pack(array, 3);
	pack(int, TMATE_CLIENT_RESIZE);
	/* cast to signed, -1 == no clients */
	pack(int, sx);
	pack(int, sy);
}
