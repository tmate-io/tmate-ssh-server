#include "tmate.h"
#include <fcntl.h>

static int dev_urandom_fd;

void tmate_init_rand(void)
{
	if ((dev_urandom_fd = open("/dev/urandom", O_RDONLY)) < 0)
		tmate_fatal("Cannot open /dev/urandom");
}

void tmate_get_random_bytes(void *buffer, ssize_t len)
{
	if (read(dev_urandom_fd, buffer, len) != len)
		tmate_fatal("Cannot read from /dev/urandom");
}

long tmate_get_random_long(void)
{
	long val;
	tmate_get_random_bytes(&val, sizeof(val));
	return val;
}

void random_stream_init(struct random_stream *rs)
{
	rs->pos = RS_BUF_SIZE;
}

char *random_stream_get(struct random_stream *rs, size_t count)
{
	char *ret;

	if (count > RS_BUF_SIZE) {
		tmate_fatal("buffer too small");
	}

	if (rs->pos + count > RS_BUF_SIZE) {
		tmate_get_random_bytes(rs->bytes, RS_BUF_SIZE);
		rs->pos = 0;
	}


	ret = &rs->bytes[rs->pos];
	rs->pos += count;
	return ret;
}
