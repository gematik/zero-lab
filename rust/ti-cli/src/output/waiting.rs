//! [`Waiting`]: the state shown while a call waits for the user at the card terminal.
//!
//! On a terminal: a spinner line on stderr with the elapsed time, the terminal's
//! progress state (OSC 9;4, indeterminate; a busy tab in Ghostty, iTerm2, Windows
//! Terminal, cmux) and one desktop notification (OSC 9), so the prompt is noticed
//! when the window is not in front. Elsewhere: one plain line, no escape sequences.

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::{diagnostic, style};

const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const PROGRESS_BUSY: &str = "\x1b]9;4;3;0\x07";
const PROGRESS_CLEAR: &str = "\x1b]9;4;0;0\x07";

/// Shown until dropped.
pub struct Waiting {
    stop: Arc<AtomicBool>,
    spinner: Option<JoinHandle<()>>,
}

impl Waiting {
    /// Starts showing `message` (e.g. `Enter PIN.SMC at the card terminal`), with
    /// `detail` after it and the elapsed time of at most `limit`.
    pub fn start(message: &str, detail: &str, limit: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = std::io::stderr().is_terminal()
            && std::env::var_os("TERM").is_none_or(|term| term != "dumb");
        if !terminal {
            diagnostic(format_args!("{message} · {detail}"));
            return Waiting {
                stop,
                spinner: None,
            };
        }
        // Control characters would end the escape sequence early.
        let notice: String = message.chars().filter(|c| !c.is_control()).collect();
        let _ = write!(std::io::stderr(), "{PROGRESS_BUSY}\x1b]9;{notice}\x07");
        let (message, detail) = (message.to_owned(), detail.to_owned());
        let flag = Arc::clone(&stop);
        let spinner = std::thread::spawn(move || {
            let start = Instant::now();
            let (strong, dim) = (style::EMPHASIS, style::DIM);
            for (tick, frame) in FRAMES.iter().cycle().enumerate() {
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                // Terminals drop a progress state that is not renewed (Ghostty after
                // 15 seconds).
                if tick % 10 == 9 {
                    let _ = write!(std::io::stderr(), "{PROGRESS_BUSY}");
                }
                let elapsed = start.elapsed().as_secs();
                let _ = write!(
                    anstream::stderr(),
                    "\r\x1b[2K{frame} {strong}{message}{strong:#}{dim} · {detail} · {elapsed} s of {} s{dim:#}",
                    limit.as_secs()
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = write!(std::io::stderr(), "\r\x1b[2K{PROGRESS_CLEAR}");
        });
        Waiting {
            stop,
            spinner: Some(spinner),
        }
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(spinner) = self.spinner.take() {
            let _ = spinner.join();
        }
    }
}
