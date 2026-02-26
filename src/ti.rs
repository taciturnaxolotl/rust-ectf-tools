use std::fs::File;
use std::io::{Read, Write};
use std::time::Instant;

use anyhow::{Context, Result, bail};

use crate::log;
use crate::serial::open_serial;

const CRC_SIZE: usize = 4;
const NAME_SIZE: usize = 8;
const PKT_HDR: u8 = 0x80;
const RESP_HDR: u8 = 0x08;

pub const SECTOR_SIZE: usize = 1024;
pub const CHUNK_SIZE: usize = 0x2C00; // 11264

/// CRC-32/JAMCRC = bitwise NOT of standard CRC-32
fn crc32_jamcrc(data: &[u8]) -> u32 {
    !crc32fast::hash(data)
}

// --- Command types ---

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum Cmd {
    Connection = b'C',
    Identity = b'I',
    Erase = b'E',
    Update = b'U',
    Program = b'P',
    Verify = b'V',
    Digest = b'D',
    Start = b'S',
}

// --- ACK values ---

fn check_ack(val: u8) -> Result<()> {
    match val {
        0x00 => Ok(()),
        0x51 => bail!("NACK: header incorrect"),
        0x52 => bail!("NACK: checksum incorrect"),
        0x53 => bail!("NACK: packet size zero"),
        0x54 => bail!("NACK: packet size too big"),
        0x55 => bail!("NACK: unknown error"),
        other => bail!("Bad ACK value: 0x{other:02x}"),
    }
}

// --- Response types ---

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum RespType {
    Message = b'M',
    Identity = b'I',
    Digest = b'D',
}

impl RespType {
    fn from_u8(b: u8) -> Result<Self> {
        match b {
            b'M' => Ok(Self::Message),
            b'I' => Ok(Self::Identity),
            b'D' => Ok(Self::Digest),
            _ => bail!("Unknown response type: 0x{b:02x}"),
        }
    }
}

fn check_message(val: u8) -> Result<()> {
    match val {
        0x00 => Ok(()),
        0x04 => bail!("Unknown command"),
        0x05 => bail!("Invalid memory range"),
        0x06 => bail!("Invalid command"),
        0x0A => bail!("Invalid address"),
        0xF0 => bail!("Command rejected"),
        0xF1 => bail!("Program failed"),
        0xF2 => bail!("Erase failed"),
        0xF3 => bail!("Verify failed"),
        other => bail!("Unknown message code: 0x{other:02x}"),
    }
}

// --- Parsed responses ---

#[derive(Debug)]
#[allow(dead_code)]
pub struct IdentityResponse {
    pub year: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub secure: u8,
    pub buf_size: u32,
    pub app_start: u32,
    pub sector_size: u32,
    pub app_clear: u16,
    pub app_ready: u16,
    pub installed: Option<Vec<u8>>,
}

enum Response {
    None,
    Message,
    Identity(IdentityResponse),
    Digest(Vec<u8>),
}

fn parse_response(body: &[u8]) -> Result<Response> {
    if body.is_empty() {
        bail!("Empty response body");
    }
    let resp_type = RespType::from_u8(body[0])?;
    let data = &body[1..];

    match resp_type {
        RespType::Message => {
            if data.len() != 1 {
                bail!("Bad MESSAGE data length: {}", data.len());
            }
            check_message(data[0])?;
            Ok(Response::Message)
        }
        RespType::Identity => {
            // BBBBIIIHH = 1+1+1+1+4+4+4+2+2 = 20 bytes, then NAME_SIZE
            if data.len() < 20 + NAME_SIZE {
                bail!("Identity response too short: {} bytes", data.len());
            }
            let installed_raw = &data[20..20 + NAME_SIZE];
            let installed = if installed_raw == [0xFF; NAME_SIZE] {
                None
            } else {
                Some(installed_raw.to_vec())
            };
            Ok(Response::Identity(IdentityResponse {
                year: data[0],
                major_version: data[1],
                minor_version: data[2],
                secure: data[3],
                buf_size: u32::from_le_bytes(data[4..8].try_into().unwrap()),
                app_start: u32::from_le_bytes(data[8..12].try_into().unwrap()),
                sector_size: u32::from_le_bytes(data[12..16].try_into().unwrap()),
                app_clear: u16::from_le_bytes(data[16..18].try_into().unwrap()),
                app_ready: u16::from_le_bytes(data[18..20].try_into().unwrap()),
                installed,
            }))
        }
        RespType::Digest => Ok(Response::Digest(data.to_vec())),
    }
}

// --- Image ---

pub struct Image {
    pub name: String,
    pub size: u32,
    pub protected: bool,
    pub verification_data: Vec<u8>,
    pub chunks: Vec<(u32, Vec<u8>)>, // (offset, data)
}

impl Image {
    const PROTECTED_MAGIC: &[u8] = b"SECURE!!";
    // Protected header: 8s magic + 8s name + I size + 32s verification_data = 52 bytes
    const PROT_HDR_SIZE: usize = 8 + NAME_SIZE + 4 + 32;
    const CHUNK_META_SIZE: usize = 32;

    pub fn deserialize(raw: &[u8], name: Option<&str>) -> Result<Self> {
        if raw.starts_with(Self::PROTECTED_MAGIC) {
            Self::deserialize_protected(raw)
        } else {
            let name = name.context("Must provide --name for unprotected image")?;
            Self::deserialize_unprotected(raw, name)
        }
    }

    fn deserialize_protected(raw: &[u8]) -> Result<Self> {
        if raw.len() < Self::PROT_HDR_SIZE {
            bail!("Protected image too short");
        }
        let name_bytes = &raw[8..8 + NAME_SIZE];
        let name = String::from_utf8_lossy(
            &name_bytes[..name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(NAME_SIZE)],
        )
        .into_owned();
        let size = u32::from_le_bytes(raw[16..20].try_into().unwrap());
        let ver_data = raw[20..52].to_vec();
        let body = &raw[Self::PROT_HDR_SIZE..];

        // Chunk protected image: each chunk is prefixed with a 4-byte LE size
        let mut chunks = Vec::new();
        let mut offset: u32 = 0;
        let mut remaining = body;
        while !remaining.is_empty() {
            if remaining.len() < 4 {
                bail!("Truncated protected chunk header");
            }
            let chunk_size = u32::from_le_bytes(remaining[..4].try_into().unwrap()) as usize;
            remaining = &remaining[4..];
            if remaining.len() < chunk_size {
                bail!("Truncated protected chunk data");
            }
            chunks.push((offset, remaining[..chunk_size].to_vec()));
            offset += (chunk_size - Self::CHUNK_META_SIZE) as u32;
            remaining = &remaining[chunk_size..];
        }

        Ok(Self {
            name,
            size,
            protected: true,
            verification_data: ver_data,
            chunks,
        })
    }

    fn deserialize_unprotected(raw: &[u8], name: &str) -> Result<Self> {
        let ver_data = crc32_jamcrc(raw).to_le_bytes().to_vec();
        let step = ((CHUNK_SIZE / SECTOR_SIZE) - 1) * SECTOR_SIZE;
        let mut chunks = Vec::new();
        let mut offset: u32 = 0;
        for chunk_start in (0..raw.len()).step_by(step) {
            let end = (chunk_start + step).min(raw.len());
            let mut block = raw[chunk_start..end].to_vec();
            // Pad to sector boundary
            let pad = (SECTOR_SIZE - (block.len() % SECTOR_SIZE)) % SECTOR_SIZE;
            if pad > 0 {
                block.extend(std::iter::repeat_n(0xFF, pad));
            }
            chunks.push((offset, block));
            offset += step as u32;
        }

        Ok(Self {
            name: name.to_string(),
            size: raw.len() as u32,
            protected: false,
            verification_data: ver_data,
            chunks,
        })
    }
}

// --- Board interface ---

pub struct MSPM0L2228 {
    file: File,
}

impl MSPM0L2228 {
    pub fn open(port: &str) -> Result<Self> {
        let file = open_serial(port, Some(3.0))?;
        Ok(Self { file })
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.file.read_exact(&mut buf)?;
        log::trace_hex("RX", &buf);
        Ok(buf)
    }

    fn read_byte(&mut self) -> Result<Option<u8>> {
        let mut buf = [0u8; 1];
        match self.file.read(&mut buf) {
            Ok(0) => Ok(None), // timeout
            Ok(_) => {
                log::trace(&format!("RX byte: {:02x}", buf[0]));
                Ok(Some(buf[0]))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        log::trace_hex("TX", data);
        self.file.write_all(data)?;
        self.file.flush()?;
        Ok(())
    }

    /// Build and send a command packet: [0x80][len:2 LE][cmd:1][data][crc:4 LE]
    fn send_packet(&mut self, cmd: Cmd, data: &[u8]) -> Result<()> {
        let length = (1 + data.len()) as u16; // cmd byte + data
        let mut cmd_data = vec![cmd as u8];
        cmd_data.extend_from_slice(data);
        let crc = crc32_jamcrc(&cmd_data);

        let mut pkt = Vec::with_capacity(3 + cmd_data.len() + CRC_SIZE);
        pkt.push(PKT_HDR);
        pkt.extend_from_slice(&length.to_le_bytes());
        pkt.extend_from_slice(&cmd_data);
        pkt.extend_from_slice(&crc.to_le_bytes());

        log::debug(&format!("Sending {:?} ({} bytes)", cmd, pkt.len()));
        self.write_bytes(&pkt)
    }

    /// Read ACK byte from bootloader
    fn read_ack(&mut self) -> Result<()> {
        log::trace("Waiting for ACK");
        let ack = self
            .read_byte()?
            .context("Timeout waiting for ACK")?;
        check_ack(ack)
    }

    /// Read a core response: [0x08][len:2 LE][body][crc:4 LE]
    fn read_response(&mut self) -> Result<Response> {
        let hdr_bytes = self.read_bytes(3)?;
        if hdr_bytes[0] != RESP_HDR {
            bail!("Bad response header: 0x{:02x}", hdr_bytes[0]);
        }
        let length = u16::from_le_bytes([hdr_bytes[1], hdr_bytes[2]]) as usize;
        if length == 0 {
            bail!("Zero-length response");
        }

        let body = self.read_bytes(length)?;
        let crc_bytes = self.read_bytes(CRC_SIZE)?;
        let sent_crc = u32::from_le_bytes(crc_bytes[..4].try_into().unwrap());
        let calc_crc = crc32_jamcrc(&body);
        if sent_crc != calc_crc {
            bail!("CRC mismatch: sent={sent_crc:08x} calc={calc_crc:08x}");
        }

        parse_response(&body)
    }

    /// Send command, read ACK, optionally read core response
    fn execute(&mut self, cmd: Cmd, data: &[u8], expect_response: bool) -> Result<Response> {
        let start = Instant::now();
        self.send_packet(cmd, data)?;
        self.read_ack()?;
        let resp = if expect_response {
            self.read_response()?
        } else {
            Response::None
        };
        log::debug(&format!(
            "Executed {:?} in {:.2}s",
            cmd,
            start.elapsed().as_secs_f64()
        ));

        Ok(resp)
    }

    pub fn connect(&mut self) -> Result<()> {
        self.execute(Cmd::Connection, &[], false)
            .context("Could not connect to the bootloader")?;
        Ok(())
    }

    pub fn status(&mut self) -> Result<IdentityResponse> {
        let resp = self
            .execute(Cmd::Identity, &[], true)
            .context("Could not get identity")?;
        match resp {
            Response::Identity(id) => {
                log::debug(&format!(
                    "Identity: v{}.{}.{}, secure={}, clear={}, ready={}",
                    id.year, id.major_version, id.minor_version,
                    id.secure, id.app_clear, id.app_ready
                ));
                Ok(id)
            }
            _ => bail!("Expected Identity response"),
        }
    }

    pub fn erase(&mut self) -> Result<()> {
        log::info("Erasing old image");
        self.execute(Cmd::Erase, &[], true)?;

        let identity = self.status()?;
        if identity.app_clear == 0 {
            bail!("Erase failed");
        }
        Ok(())
    }

    pub fn flash(&mut self, image: &Image) -> Result<()> {
        self.connect()?;
        let identity = self.status()?;

        if image.protected && identity.secure == 0 {
            bail!("Tried to load protected image onto design bootloader");
        }
        if !image.protected && identity.secure != 0 {
            bail!("Tried to load unprotected image onto attack bootloader");
        }
        if identity.app_clear == 0 {
            bail!("Board must be erased before flashing");
        }

        // Send UPDATE
        log::info("Requesting update");
        let mut update_data = Vec::with_capacity(NAME_SIZE + 4 + image.verification_data.len());
        let mut name_buf = [0u8; NAME_SIZE];
        let name_bytes = image.name.as_bytes();
        let copy_len = name_bytes.len().min(NAME_SIZE);
        name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        update_data.extend_from_slice(&name_buf);
        update_data.extend_from_slice(&image.size.to_le_bytes());
        update_data.extend_from_slice(&image.verification_data);
        self.execute(Cmd::Update, &update_data, true)?;

        if identity.sector_size != SECTOR_SIZE as u32 {
            bail!("Bad sector size reported: {}", identity.sector_size);
        }
        if identity.buf_size < CHUNK_SIZE as u32 {
            bail!("Bad chunk size reported: {}", identity.buf_size);
        }

        // Send PROGRAM chunks
        log::debug(&format!("Sending {} chunks", image.chunks.len()));
        let start = Instant::now();
        for (offset, chunk) in &image.chunks {
            let mut prog_data = Vec::with_capacity(4 + chunk.len());
            prog_data.extend_from_slice(&offset.to_le_bytes());
            prog_data.extend_from_slice(chunk);
            self.execute(Cmd::Program, &prog_data, true)?;
        }
        log::debug(&format!(
            "Sent image in {:.2}s",
            start.elapsed().as_secs_f64()
        ));

        // Verify
        self.execute(Cmd::Verify, &[], true)?;

        let identity = self.status()?;
        if identity.app_ready == 0 {
            bail!("Image not ready after verification! Reboot board and try again");
        }

        Ok(())
    }

    pub fn start(&mut self) -> Result<()> {
        self.execute(Cmd::Start, &[], true)?;
        Ok(())
    }

    pub fn digest(&mut self, slot: u8) -> Result<Vec<u8>> {
        let identity = self.status()?;
        if identity.secure == 0 {
            bail!("Digest only possible on secure bootloader");
        }
        if identity.app_ready == 0 {
            bail!("Design must be flashed before requesting digest");
        }
        let resp = self.execute(Cmd::Digest, &[slot], true)?;
        match resp {
            Response::Digest(d) => Ok(d),
            _ => bail!("Expected Digest response"),
        }
    }
}
