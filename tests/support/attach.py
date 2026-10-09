# Keeps a tmate client attached in a large pty so the session has a message
# log and status text, like a person's terminal would. Output is discarded.
#
# The pty is large so this client never limits the pane size (tmux uses the
# smallest attached client), and it is sized before tmate starts so the
# shell does not reprint its prompt at a run-dependent moment.
import fcntl, os, pty, struct, sys, termios

SIZE = struct.pack("HHHH", 60, 200, 0, 0)

pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, SIZE)
    os.execvp(sys.argv[1], sys.argv[1:])
while True:
    try:
        data = os.read(fd, 65536)
    except OSError:
        break
    if not data:
        break
