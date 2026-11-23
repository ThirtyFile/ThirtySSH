import os
import queue
import signal
import sys
import threading


def print_line(message):
    print(message, flush=True)


def enable_windows_terminal():
    import ctypes
    from ctypes import wintypes

    console = ctypes.WinDLL("kernel32", use_last_error=True)
    console.GetStdHandle.argtypes = [wintypes.DWORD]
    console.GetStdHandle.restype = wintypes.HANDLE
    console.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    console.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    output = console.GetStdHandle(-11)
    mode = wintypes.DWORD()
    if not console.GetConsoleMode(output, ctypes.byref(mode)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not console.SetConsoleMode(output, mode.value | 4):
        raise ctypes.WinError(ctypes.get_last_error())


def exit_after_interrupt(_sig, _frame):
    sys.stdout.write("\x1b[?1049l")
    print_line("INTERRUPTED")
    os._exit(43)


def read_input(commands):
    for line in sys.stdin:
        commands.put(line.rstrip("\r\n"))
    commands.put(None)


def main():
    if os.name == "nt":
        enable_windows_terminal()
    signal.signal(signal.SIGINT, exit_after_interrupt)
    if os.name != "nt":
        # Make the lifecycle cases exercise cleanup even when SIGHUP is ignored.
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

    seen_size = os.get_terminal_size()
    print_line(f"READY-{os.getpid()}-{os.environ.get('TERM')}")
    sys.stdout.write("\x1b[?1049h")
    print_line(f"SIZE-{seen_size.columns}x{seen_size.lines}")
    commands = queue.Queue()
    threading.Thread(target=read_input, args=(commands,), daemon=True).start()
    while True:
        size = os.get_terminal_size()
        if size != seen_size:
            print_line(f"SIZE-{size.columns}x{size.lines}")
            seen_size = size
        try:
            command = commands.get(timeout=0.03)
        except queue.Empty:
            continue
        if command:
            print_line(f"ECHO-{command}")


if __name__ == "__main__":
    main()
