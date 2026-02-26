#![allow(dead_code)]

use std::sync::atomic::{AtomicU8, Ordering};

static VERBOSITY: AtomicU8 = AtomicU8::new(0);

pub fn set_verbosity(level: u8) {
    VERBOSITY.store(level, Ordering::Relaxed);
}

fn verbosity() -> u8 {
    VERBOSITY.load(Ordering::Relaxed)
}

// ANSI codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

// 256-color: \x1b[38;5;Nm
const GRAY: &str = "\x1b[38;5;242m";
const BLUE: &str = "\x1b[38;5;75m";
const GREEN: &str = "\x1b[38;5;114m";
const YELLOW: &str = "\x1b[38;5;221m";
const RED: &str = "\x1b[38;5;203m";
const MAGENTA: &str = "\x1b[38;5;183m";
const WHITE: &str = "\x1b[38;5;252m";

// Padding so messages align. Longest tag is [error] = 7 chars.
// Each tag pads to 8 total (tag + spaces) before the message.
const PAD: usize = 8; // "[error] " = 8

macro_rules! tag {
    ($label:expr) => {
        // pad_len = PAD - len("[") - len($label) - len("]") - len(" ")
        // but easier: total visible = 2 + label.len(), pad to PAD
        concat!("[", $label, "]")
    };
}

/// Trace (verbosity >= 2) — gray
pub fn trace(msg: &str) {
    if verbosity() >= 2 {
        eprintln!("{RED}{:<PAD$}{RESET}{msg}", tag!("trace"));
    }
}

/// Debug (verbosity >= 1) — blue
pub fn debug(msg: &str) {
    if verbosity() >= 1 {
        eprintln!("{BLUE}{:<PAD$}{RESET}{msg}", tag!("debug"));
    }
}

/// Info — white
pub fn info(msg: &str) {
    println!("{WHITE}{:<PAD$}{RESET}{msg}", tag!("info"));
}

/// Success — green
pub fn success(msg: &str) {
    println!("{GREEN}{:<PAD$}{RESET}{msg}", tag!("ok"));
}

/// Warning — yellow
pub fn warning(msg: &str) {
    eprintln!("{YELLOW}{:<PAD$}{RESET}{msg}", tag!("warn"));
}

/// Error — bold red
pub fn error(msg: &str) {
    eprintln!("{BOLD}{RED}{:<PAD$}{RESET}{msg}", tag!("error"));
}

/// Error cause — red, indented to match message column
pub fn error_cause(msg: &str) {
    eprintln!("{:PAD$}{RED}{msg}{RESET}", "");
}

/// HSM debug messages from firmware — magenta
pub fn hsm_debug(msg: &str) {
    eprintln!("{MAGENTA}{:<PAD$}{RESET}{msg}", tag!("hsm"));
}

/// HSM debug messages that aren't valid UTF-8 — show as hexdump
pub fn hsm_debug_hex(data: &[u8]) {
    eprintln!("{MAGENTA}{:<PAD$}{RESET}({} bytes)", tag!("hsm"), data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex_part = String::with_capacity(40);
        let mut ascii_part = String::with_capacity(16);
        for (j, &b) in chunk.iter().enumerate() {
            if j > 0 && j % 2 == 0 {
                hex_part.push(' ');
            }
            hex_part.push_str(&format!("{b:02x}"));
            ascii_part.push(if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            });
        }
        eprintln!("{:PAD$}{GRAY}{offset:08x}:{RESET} {hex_part:<39}  {GREEN}{ascii_part}{RESET}", "");
    }
}

/// Trace-level hex+ASCII dump of a byte buffer (verbosity >= 2)
/// Format matches xxd: paired hex bytes, 16 per line.
pub fn trace_hex(label: &str, data: &[u8]) {
    if verbosity() < 2 {
        return;
    }
    eprintln!("{RED}{:<PAD$}{RESET}{label} ({} bytes)", tag!("trace"), data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex_part = String::with_capacity(40);
        let mut ascii_part = String::with_capacity(16);
        for (j, &b) in chunk.iter().enumerate() {
            if j > 0 && j % 2 == 0 {
                hex_part.push(' ');
            }
            hex_part.push_str(&format!("{b:02x}"));
            ascii_part.push(if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            });
        }
        eprintln!("{:PAD$}{GRAY}{offset:08x}:{RESET} {hex_part:<39}  {GREEN}{ascii_part}{RESET}", "");
    }
}
