# Simple Rootkit (Educational Purposes Only)

**⚠️ DISCLAIMER: This project is for educational and research purposes only. Misuse of this code may violate laws or regulations. The author does not take any responsibility for damage caused by improper or illegal use.**

## Overview

This is a simple Linux kernel rootkit that demonstrates several common rootkit techniques:

- Hiding the kernel module from `lsmod`
- Hiding a TCP port from `/proc/net/tcp` and `/proc/net/tcp6`
- Privilege escalation via a character device (`/dev/sdd1`)
- Reverse shell using `kthread` and `usermodehelper`

## Features

- **Module hiding** using list manipulation and sysfs trickery.
- **TCP port hiding** by hooking `tcp4_seq_show` and `tcp6_seq_show` using `ftrace`.
- **Privilege escalation** by writing `"root"` to `/dev/sdd1`.
- **Reverse shell** activation if a specific process name is not found.

## File Descriptions

- `rootkit.c`: The main kernel module implementing the rootkit features.
- `ftrace_helper.h`: A helper header file to simplify hooking using `ftrace`.

## Installation

> ⚠️ Make sure your system is suitable for kernel module development and debugging.

1. Prepare your kernel headers:
```bash
sudo apt install linux-headers-$(uname -r)
```

2. Build the module:
```bash
make
```

3. Load the module:
```bash
sudo insmod rootkit.ko
```

4. Set permissions:
```bash
sudo chmod 777 /dev/sdd1
```

## Usage

### Get Root Access

Write the word `"root"` into the device:

```bash
echo "root" > /dev/sdd1
```

Your current process will now run as UID 0.

### Hidden Port

Any traffic on TCP port `8087` will not appear in `/proc/net/tcp` or `/proc/net/tcp6`.

### Reverse Shell

If no process named `noprocname` is running, a reverse shell is attempted to:

```bash
127.0.0.1:8087
```

## Uninstall

```bash
sudo rmmod rootkit
```

## Security and Research Notice

This code is intended to demonstrate how kernel rootkits can operate in controlled environments. Do **NOT** deploy this in production systems. Always use safe and isolated environments such as virtual machines.

## Author

Linus Torvalds (just kidding 😉 — code adapted for demonstration purposes)

