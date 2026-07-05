# ProcSpy

ProcSpy is a small Linux process inspection tool written in C. I built it to better understand how the Linux `/proc` filesystem exposes process information and how basic security inspection tools work internally.

Instead of relying on tools like `ps` or `lsof`, ProcSpy reads information directly from `/proc` and provides both a system-wide process overview and a deeper inspection mode for individual processes.

The project was mainly an exercise in learning Linux internals, process management, and memory layout.

---

## Features

- List all running processes
- Display process state
- Count open file descriptors
- Show the command line used to start a process
- Inspect a process's memory mappings
- Detect writable + executable (RWX) memory regions
- Simple command-line interface

---

## How it works

ProcSpy gathers information directly from the Linux `/proc` filesystem.

Some of the files it reads include:

- `/proc/<pid>/stat`
- `/proc/<pid>/cmdline`
- `/proc/<pid>/fd`
- `/proc/<pid>/maps`

During deep inspection, it scans the process memory map and reports any memory regions that are both writable and executable. Although not always malicious, RWX pages are generally uncommon and can sometimes indicate injected code or shellcode.

---

## Build

```bash
gcc main.c -o procspy
```

---

## Usage

List all processes:

```bash
./procspy
```

or

```bash
./procspy -a
```

Inspect a specific process:

```bash
./procspy -p <PID>
```

Example:

```bash
./procspy -p 1234
```

Show help:

```bash
./procspy -h
```

---

## Sample Output

### Process Scan

```
PID        NAME                     STATE      OPEN FDs
-------------------------------------------------------
1          systemd                  S          193
834        NetworkManager           S          57
1260       firefox                  S          198
```

### Deep Inspection

```
DEEP INSPECTION: PID 1260

Command Line:
firefox

Open File Descriptors: 198

Memory Map Security Analysis

MEMORY ADDRESS                     PERMS      MAPPED PATH
---------------------------------------------------------
7f23c0000000-7f23c0010000          rwxp       [anonymous]
```

---

## Why I built this

I wanted to understand what tools like `ps`, `top`, and `lsof` actually do under the hood.

Writing ProcSpy helped me learn more about:

- Linux process management
- The `/proc` virtual filesystem
- Memory mappings
- File descriptors
- Command-line parsing in C
- Working with POSIX APIs

---

## Limitations

- Reading information from processes owned by other users may require root privileges.
- RWX memory regions are only a heuristic and should not be treated as definitive evidence of malicious activity.
- This project focuses on Linux systems.

---

## Future Improvements

Some ideas I'd like to explore later:

- Display loaded shared libraries
- Detect hidden processes
- Export results as JSON
- Monitor processes continuously
- Compare process snapshots over time
- Add eBPF-based event monitoring

---

## Author

Chirag
