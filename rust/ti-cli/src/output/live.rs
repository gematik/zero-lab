//! [`Live`]: a block of lines on stdout redrawn in place while results arrive, for
//! commands that work in parallel. Only on a terminal; elsewhere [`Live::enabled`] is
//! false and the command prints its lines as they are final.

use std::io::{IsTerminal, Write};

/// The block of lines last drawn.
pub struct Live {
    enabled: bool,
    drawn: usize,
}

impl Live {
    /// Live drawing when stdout is a terminal that understands cursor movement.
    pub fn new() -> Self {
        let terminal = std::io::stdout().is_terminal()
            && std::env::var_os("TERM").is_none_or(|term| term != "dumb");
        Live {
            enabled: terminal,
            drawn: 0,
        }
    }

    /// Whether lines are redrawn in place.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Replaces the block with `lines`, which may carry styles; the stream strips them
    /// where colors are off. Auto-wrap is off while drawing: a line wider than the
    /// terminal is cut at the edge instead of taking a second row, so the cursor-up count
    /// stays right.
    pub fn draw(&mut self, lines: &[String]) {
        self.render(lines, false);
    }

    /// Draws the block a last time with auto-wrap on, so long lines stay whole in the
    /// scrollback; nothing is redrawn after it.
    pub fn finish(&mut self, lines: &[String]) {
        self.render(lines, true);
    }

    fn render(&mut self, lines: &[String], wrap: bool) {
        if !self.enabled {
            return;
        }
        let mut out = super::stdout();
        // A terminal that went away is not worth failing the command for.
        let _ = (|| -> std::io::Result<()> {
            if !wrap {
                write!(out, "\x1b[?7l")?;
            }
            if self.drawn > 0 {
                write!(out, "\x1b[{}A", self.drawn)?;
            }
            // Clearing to the end of the screen also removes what a cut line left behind.
            write!(out, "\r\x1b[J")?;
            for line in lines {
                writeln!(out, "{line}")?;
            }
            if !wrap {
                write!(out, "\x1b[?7h")?;
            }
            out.flush()
        })();
        self.drawn = lines.len();
    }
}
