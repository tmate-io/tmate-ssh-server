#ifndef WINDOW_COPY_H
#define WINDOW_COPY_H

#include "tmux.h"

struct screen *window_copy_init(struct window_pane *);
void	window_copy_free(struct window_pane *);
void    window_copy_pagedown(struct window_pane *);
void	window_copy_resize(struct window_pane *, u_int, u_int);
void	window_copy_key(struct window_pane *, struct client *, struct session *,
	    key_code, struct mouse_event *);
int	window_copy_key_input(struct window_pane *, key_code);
int	window_copy_key_numeric_prefix(struct window_pane *, key_code);

void	window_copy_redraw_selection(struct window_pane *, u_int);
void	window_copy_redraw_lines(struct window_pane *, u_int, u_int);
void	window_copy_redraw_screen(struct window_pane *);
void	window_copy_write_line(struct window_pane *, struct screen_write_ctx *,
	    u_int);
void	window_copy_write_lines(struct window_pane *,
	    struct screen_write_ctx *, u_int, u_int);

void	window_copy_scroll_to(struct window_pane *, u_int, u_int);
int	window_copy_search_compare(struct grid *, u_int, u_int, struct grid *,
	    u_int, int);
int	window_copy_search_lr(struct grid *, struct grid *, u_int *, u_int,
	    u_int, u_int, int);
int	window_copy_search_rl(struct grid *, struct grid *, u_int *, u_int,
	    u_int, u_int, int);
void	window_copy_search_up(struct window_pane *, const char *);
void	window_copy_search_down(struct window_pane *, const char *);
void	window_copy_goto_line(struct window_pane *, const char *);
void	window_copy_update_cursor(struct window_pane *, u_int, u_int);
void	window_copy_start_selection(struct window_pane *);
int	window_copy_update_selection(struct window_pane *, int);
void   *window_copy_get_selection(struct window_pane *, size_t *);
void	window_copy_copy_buffer(struct window_pane *, const char *, void *,
	    size_t);
void	window_copy_copy_pipe(struct window_pane *, struct session *,
	    const char *, const char *);
void	window_copy_copy_selection(struct window_pane *, const char *);
void	window_copy_append_selection(struct window_pane *, const char *);
void	window_copy_clear_selection(struct window_pane *);
void	window_copy_copy_line(struct window_pane *, char **, size_t *, u_int,
	    u_int, u_int);
int	window_copy_in_set(struct window_pane *, u_int, u_int, const char *);
u_int	window_copy_find_length(struct window_pane *, u_int);
void	window_copy_cursor_start_of_line(struct window_pane *);
void	window_copy_cursor_back_to_indentation(struct window_pane *);
void	window_copy_cursor_end_of_line(struct window_pane *);
void	window_copy_other_end(struct window_pane *);
void	window_copy_cursor_left(struct window_pane *);
void	window_copy_cursor_right(struct window_pane *);
void	window_copy_cursor_up(struct window_pane *, int);
void	window_copy_cursor_down(struct window_pane *, int);
void	window_copy_cursor_jump(struct window_pane *);
void	window_copy_cursor_jump_back(struct window_pane *);
void	window_copy_cursor_jump_to(struct window_pane *, int);
void	window_copy_cursor_jump_to_back(struct window_pane *, int);
void	window_copy_cursor_next_word(struct window_pane *, const char *);
void	window_copy_cursor_next_word_end(struct window_pane *, const char *);
void	window_copy_cursor_previous_word(struct window_pane *, const char *);
void	window_copy_scroll_up(struct window_pane *, u_int);
void	window_copy_scroll_down(struct window_pane *, u_int);
void	window_copy_rectangle_toggle(struct window_pane *);
void	window_copy_drag_update(struct client *, struct mouse_event *);
void	window_copy_drag_release(struct client *, struct mouse_event *);

extern const struct window_mode window_copy_mode;

enum window_copy_input_type {
	WINDOW_COPY_OFF,
	WINDOW_COPY_NAMEDBUFFER,
	WINDOW_COPY_NUMERICPREFIX,
	WINDOW_COPY_SEARCHUP,
	WINDOW_COPY_SEARCHDOWN,
	WINDOW_COPY_JUMPFORWARD,
	WINDOW_COPY_JUMPBACK,
	WINDOW_COPY_JUMPTOFORWARD,
	WINDOW_COPY_JUMPTOBACK,
	WINDOW_COPY_GOTOLINE,
};

/*
 * Copy-mode's visible screen (the "screen" field) is filled from one of
 * two sources: the original contents of the pane (used when we
 * actually enter via the "copy-mode" command, to copy the contents of
 * the current pane), or else a series of lines containing the output
 * from an output-writing tmux command (such as any of the "show-*" or
 * "list-*" commands).
 *
 * In either case, the full content of the copy-mode grid is pointed at
 * by the "backing" field, and is copied into "screen" as needed (that
 * is, when scrolling occurs). When copy-mode is backed by a pane,
 * backing points directly at that pane's screen structure (&wp->base);
 * when backed by a list of output-lines from a command, it points at
 * a newly-allocated screen structure (which is deallocated when the
 * mode ends).
 */

struct window_copy_mode_data {
	struct screen		 screen;

	struct screen		*backing;
	int			 backing_written; /* backing display started */

	struct mode_key_data	 mdata;

	u_int			 oy;

	u_int			 selx;
	u_int			 sely;

	int			 rectflag;	/* in rectangle copy mode? */
	int			 scroll_exit;	/* exit on scroll to end? */

	u_int			 cx;
	u_int			 cy;

	u_int			 lastcx; /* position in last line w/ content */
	u_int			 lastsx; /* size of last line w/ content */

	enum window_copy_input_type inputtype;
	const char		*inputprompt;
	char			*inputstr;
	int			 inputexit;

	int			 numprefix;

	enum window_copy_input_type searchtype;
	char			*searchstr;

	enum window_copy_input_type jumptype;
	char			 jumpchar;
};

#endif
