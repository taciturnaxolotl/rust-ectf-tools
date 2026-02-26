use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;

use anyhow::{Result, bail};

/// Open and configure a serial port with raw termios at 115200 8N1.
///
/// - `timeout`: read timeout in seconds. `None` = blocking (VMIN=1, VTIME=0).
///   `Some(t)` = VMIN=0, VTIME in deciseconds.
pub fn open_serial(port: &str, timeout: Option<f32>) -> Result<File> {
    // Open with O_NONBLOCK to avoid blocking on carrier detect (macOS CDC-ACM).
    let c_port = std::ffi::CString::new(port)?;
    let fd = unsafe {
        libc::open(
            c_port.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        bail!("Failed to open {port}: {}", io::Error::last_os_error());
    }

    // Clear O_NONBLOCK so reads are blocking
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
            libc::close(fd);
            bail!(
                "Failed to clear O_NONBLOCK: {}",
                io::Error::last_os_error()
            );
        }
    }

    let file = unsafe { File::from_raw_fd(fd) };

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
        termios.c_lflag &=
            !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);

        // Timeout configuration
        match timeout {
            None => {
                termios.c_cc[libc::VMIN] = 1;
                termios.c_cc[libc::VTIME] = 0;
            }
            Some(secs) => {
                termios.c_cc[libc::VMIN] = 0;
                // VTIME is in deciseconds (1/10 sec), minimum 1
                termios.c_cc[libc::VTIME] = ((secs * 10.0) as u8).max(1);
            }
        }

        // Baud rate 115200
        libc::cfsetispeed(&mut termios, libc::B115200);
        libc::cfsetospeed(&mut termios, libc::B115200);

        if libc::tcsetattr(fd, libc::TCSAFLUSH, &termios) != 0 {
            bail!("tcsetattr failed: {}", io::Error::last_os_error());
        }

        // Flush stale input
        libc::tcflush(fd, libc::TCIFLUSH);
    }

    Ok(file)
}
