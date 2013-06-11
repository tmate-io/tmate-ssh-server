#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "tmux.h"
#include "tmate.h"

struct event_base *ev_base;

struct options	 global_options;	/* server options */
struct options	 global_s_options;	/* session options */
struct options	 global_w_options;	/* window options */
struct environ	 global_environ;

char		*cfg_file;
char		*shell_cmd;
int		 debug_level;
time_t		 start_time;
char	 	 socket_path[MAXPATHLEN];
int		 login_shell;
char		*environ_path;
pid_t		 environ_pid = -1;
int		 environ_session_id = -1;

void
setblocking(int fd, int state)
{
	int mode;

	if ((mode = fcntl(fd, F_GETFL)) != -1) {
		if (!state)
			mode |= O_NONBLOCK;
		else
			mode &= ~O_NONBLOCK;
		fcntl(fd, F_SETFL, mode);
	}
}

const char*
get_full_path(const char *wd, const char *path)
{
	static char	newpath[MAXPATHLEN];
	char		oldpath[MAXPATHLEN];

	if (getcwd(oldpath, sizeof oldpath) == NULL)
		return (NULL);
	if (chdir(wd) != 0)
		return (NULL);
	if (realpath(path, newpath) != 0)
		return (NULL);
	chdir(oldpath);
	return (newpath);
}

void tmux_server_init(int flags)
{
	int quiet = 0;

	environ_init(&global_environ);

	options_init(&global_options, NULL);
	options_table_populate_tree(server_options_table, &global_options);
	options_set_number(&global_options, "quiet", quiet);

	options_init(&global_s_options, NULL);
	options_table_populate_tree(session_options_table, &global_s_options);

	options_init(&global_w_options, NULL);
	options_table_populate_tree(window_options_table, &global_w_options);

	if (flags & IDENTIFY_UTF8) {
		options_set_number(&global_s_options, "status-utf8", 1);
		options_set_number(&global_s_options, "mouse-utf8", 1);
		options_set_number(&global_w_options, "utf8", 1);
	}

	server_start(0, NULL);
}
