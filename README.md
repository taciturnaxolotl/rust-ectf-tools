# rust-ectf-tools

Drop-in replacement for MITRE's `uvx ectf tools` host tools, rewritten in Rust with reliable serial I/O. Uses raw termios instead of pyserial to avoid macOS CDC-ACM data corruption bugs.

## Usage

```bash
cargo build --release
```

```bash
# List files on the HSM
./target/release/ectf-tools /dev/tty.usbmodemXXX list 1a2b3c

# Write a file
./target/release/ectf-tools /dev/tty.usbmodemXXX write 1a2b3c 0 0x4321 myfile.bin

# Read a file
./target/release/ectf-tools /dev/tty.usbmodemXXX read 1a2b3c 1 ./output/

# Interrogate a connected HSM
./target/release/ectf-tools /dev/tty.usbmodemXXX interrogate 1a2b3c

# Listen for another HSM
./target/release/ectf-tools /dev/tty.usbmodemXXX listen

# Receive a file from another HSM
./target/release/ectf-tools /dev/tty.usbmodemXXX receive 1a2b3c 0 1
```

### Verbosity

- `-v` — protocol-level debug (headers, ACKs, chunk sizes)
- `-vv` — raw byte-level trace with xxd-style hexdump

## Why not pyserial?

pyserial has known data corruption issues on macOS with CDC-ACM devices (like the MAX78000). This tool opens the serial port directly with proper termios configuration, flushes the input buffer on open, and uses `O_NONBLOCK` to avoid blocking on carrier detect.

<p align="center">
    <img src="https://raw.githubusercontent.com/taciturnaxolotl/carriage/main/.github/images/line-break.svg" />
</p>

<p align="center">
    <i><code>&copy; 2026-present <a href="https://dunkirk.sh">Kieran Klukas</a></code></i>
</p>

<p align="center">
    <a href="https://github.com/taciturnaxolotl/rust-ectf-tools/blob/main/LICENSE.md"><img src="https://img.shields.io/static/v1.svg?style=for-the-badge&label=License&message=MIT&logoColor=d9e0ee&colorA=363a4f&colorB=b7bdf8"/></a>
</p>
