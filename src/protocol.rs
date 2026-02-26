use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;

use anyhow::{Result, bail};

use crate::log;

const MAGIC: u8 = 0x25; // '%'
const BLOCK_LEN: usize = 256;
const HDR_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    List = 0x4C,
    Read = 0x52,
    Write = 0x57,
    Receive = 0x43,
    Interrogate = 0x49,
    Listen = 0x4E,
    Ack = 0x41,
    Debug = 0x44,
    Error = 0x45,
}

impl Opcode {
    fn from_u8(b: u8) -> Result<Self> {
        match b {
            0x4C => Ok(Self::List),
            0x52 => Ok(Self::Read),
            0x57 => Ok(Self::Write),
            0x43 => Ok(Self::Receive),
            0x49 => Ok(Self::Interrogate),
            0x4E => Ok(Self::Listen),
            0x41 => Ok(Self::Ack),
            0x44 => Ok(Self::Debug),
            0x45 => Ok(Self::Error),
            _ => bail!("Unknown opcode: 0x{b:02X}"),
        }
    }

    fn needs_ack(self) -> bool {
        !matches!(self, Self::Ack | Self::Debug)
    }
}

pub struct Message {
    pub opcode: Opcode,
    pub body: Vec<u8>,
}

pub struct HSMIntf {
    file: File,
    stream: Vec<u8>,
}

impl HSMIntf {
    pub fn open(port: &str) -> Result<Self> {
        // Open with O_NONBLOCK to avoid blocking on carrier detect (macOS CDC-ACM).
        // Then clear O_NONBLOCK so subsequent reads are blocking.
        let c_port = std::ffi::CString::new(port)?;
        let fd = unsafe { libc::open(c_port.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK) };
        if fd < 0 {
            bail!("Failed to open {port}: {}", io::Error::last_os_error());
        }

        // Clear O_NONBLOCK now that we're past the open
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
                libc::close(fd);
                bail!("Failed to clear O_NONBLOCK: {}", io::Error::last_os_error());
            }
        }

        let file = unsafe { File::from_raw_fd(fd) };

        // Configure termios for raw serial at 115200
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut termios) != 0 {
                bail!("tcgetattr failed: {}", io::Error::last_os_error());
            }

            // Input flags: disable all processing
            termios.c_iflag &= !(libc::IGNBRK
                | libc::BRKINT
                | libc::PARMRK
                | libc::ISTRIP
                | libc::INLCR
                | libc::IGNCR
                | libc::ICRNL
                | libc::IXON
                | libc::IXOFF
                | libc::IXANY);

            // Output flags: disable all processing
            termios.c_oflag &= !libc::OPOST;

            // Control flags: 8N1, no flow control
            termios.c_cflag &= !(libc::CSIZE | libc::PARENB | libc::CSTOPB | libc::CRTSCTS);
            termios.c_cflag |= libc::CS8 | libc::CLOCAL | libc::CREAD;

            // Local flags: raw mode
            termios.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);

            // Blocking read: VMIN=1, VTIME=0
            termios.c_cc[libc::VMIN] = 1;
            termios.c_cc[libc::VTIME] = 0;

            // Set baud rate to 115200
            libc::cfsetispeed(&mut termios, libc::B115200);
            libc::cfsetospeed(&mut termios, libc::B115200);

            if libc::tcsetattr(fd, libc::TCSAFLUSH, &termios) != 0 {
                bail!("tcsetattr failed: {}", io::Error::last_os_error());
            }

            // Flush input buffer (the MITRE tool doesn't do this — we should)
            libc::tcflush(fd, libc::TCIFLUSH);
        }

        Ok(Self {
            file,
            stream: Vec::new(),
        })
    }

    fn read_byte(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.file.read_exact(&mut buf)?;
        log::trace(&format!("RX byte: {:02x}", buf[0]));
        Ok(buf[0])
    }

    fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.file.read_exact(&mut buf)?;
        log::trace_hex("RX", &buf);
        Ok(buf)
    }

    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        log::trace_hex("TX", data);
        self.file.write_all(data)?;
        self.file.flush()?;
        Ok(())
    }

    fn pack_header(opcode: Opcode, size: u16) -> [u8; HDR_LEN] {
        let size_bytes = size.to_le_bytes();
        [MAGIC, opcode as u8, size_bytes[0], size_bytes[1]]
    }

    fn send_ack(&mut self) -> Result<()> {
        log::trace("TX ACK");
        let hdr = Self::pack_header(Opcode::Ack, 0);
        self.write_all(&hdr)
    }

    fn get_ack(&mut self) -> Result<()> {
        let msg = self.get_msg()?;
        if msg.opcode != Opcode::Ack {
            bail!("Expected ACK, got {:?}", msg.opcode);
        }
        Ok(())
    }

    /// Try to parse a header from the internal stream buffer.
    /// Returns Some((opcode, size)) if found, consuming up through the header.
    fn try_parse_header(&mut self) -> Option<(Opcode, u16)> {
        if let Some(pos) = self.stream.iter().position(|&b| b == MAGIC) {
            // Need at least 3 more bytes after magic
            if pos + 4 <= self.stream.len() {
                let opc = self.stream[pos + 1];
                let size = u16::from_le_bytes([self.stream[pos + 2], self.stream[pos + 3]]);
                self.stream.drain(..pos + 4);
                if let Ok(opcode) = Opcode::from_u8(opc) {
                    return Some((opcode, size));
                }
            }
        }
        None
    }

    /// Read a raw message from the device (may be DEBUG, ACK, ERROR, or data).
    fn get_raw_msg(&mut self) -> Result<Message> {
        // Read bytes until we can parse a header
        let (opcode, size) = loop {
            if let Some(hdr) = self.try_parse_header() {
                break hdr;
            }
            let b = self.read_byte()?;
            self.stream.push(b);
        };

        log::debug(&format!("Found header: opcode={opcode:?}, size={size}"));

        if opcode.needs_ack() {
            self.send_ack()?;
        }

        // Read body in BLOCK_LEN chunks
        let mut body = Vec::with_capacity(size as usize);
        let mut remaining = size as usize;
        while remaining > 0 {
            let chunk_size = remaining.min(BLOCK_LEN);
            let chunk = self.read_exact(chunk_size)?;
            body.extend_from_slice(&chunk);
            remaining -= chunk_size;
            if opcode.needs_ack() {
                self.send_ack()?;
            }
            log::debug(&format!("Read block ({chunk_size} bytes)"));
        }

        Ok(Message { opcode, body })
    }

    /// Read a message, filtering out DEBUG and raising on ERROR.
    fn get_msg(&mut self) -> Result<Message> {
        loop {
            let msg = self.get_raw_msg()?;
            match msg.opcode {
                Opcode::Error => {
                    let text = String::from_utf8_lossy(&msg.body);
                    bail!("HSM error: {text}");
                }
                Opcode::Debug => {
                    match std::str::from_utf8(&msg.body) {
                        Ok(text) => log::hsm_debug(text.trim()),
                        Err(_) => log::hsm_debug_hex(&msg.body),
                    }
                    continue;
                }
                _ => return Ok(msg),
            }
        }
    }

    /// Send a message with ACK flow control (header + chunked body).
    fn send_msg(&mut self, opcode: Opcode, body: &[u8]) -> Result<()> {
        let hdr = Self::pack_header(opcode, body.len() as u16);
        log::debug(&format!("Sending header: opcode={opcode:?}, size={}", body.len()));

        self.write_all(&hdr)?;
        self.get_ack()?;

        for chunk in body.chunks(BLOCK_LEN) {
            log::debug(&format!("Sending chunk ({} bytes)", chunk.len()));
            self.write_all(chunk)?;
            self.get_ack()?;
        }

        Ok(())
    }

    /// Send a command and wait for the matching response.
    pub fn send_respond(&mut self, opcode: Opcode, body: &[u8]) -> Result<Message> {
        self.send_msg(opcode, body)?;
        let resp = self.get_msg()?;
        if resp.opcode != opcode {
            bail!(
                "Response opcode mismatch: expected {:?}, got {:?}",
                opcode,
                resp.opcode
            );
        }
        Ok(resp)
    }
}
