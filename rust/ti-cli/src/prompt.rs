/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! Questions for the interactive commands (`connector config new`, `edit`, `pin`). They
//! ask only when stdin and stderr are terminals; otherwise every question fails with the
//! option that answers it, so scripts and agents never wait. Questions and answers go
//! through stderr, results stay on stdout.

use std::io::{BufRead as _, IsTerminal as _, Write as _};

use crate::error::CliError;

/// Where questions go.
pub trait Ask {
    /// Whether questions are answered (a terminal), rather than failing.
    fn interactive(&self) -> bool;
    /// A line of text; `default` if the answer is empty. `flag` names the option that
    /// answers it without a terminal.
    fn line(
        &mut self,
        question: &str,
        flag: &str,
        default: Option<&str>,
    ) -> Result<String, CliError>;
    /// A secret, not echoed.
    fn secret(&mut self, question: &str, flag: &str) -> Result<String, CliError>;
    /// Yes or no; `default` if the answer is empty.
    fn confirm(&mut self, question: &str, flag: &str, default: bool) -> Result<bool, CliError>;
    /// One of `options`, by number; the first if the answer is empty.
    fn choose(&mut self, question: &str, flag: &str, options: &[String])
    -> Result<usize, CliError>;
    /// A line of information.
    fn say(&mut self, line: &str);
}

/// The terminal if stdin and stderr are one, else [`NoTerminal`].
pub fn terminal() -> Box<dyn Ask> {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        Box::new(Terminal)
    } else {
        Box::new(NoTerminal)
    }
}

/// Without a terminal: every question is an error naming its option.
pub struct NoTerminal;

fn missing(flag: &str) -> CliError {
    CliError::Arguments(format!(
        "{flag} is required: without a terminal nothing is asked"
    ))
}

impl Ask for NoTerminal {
    fn interactive(&self) -> bool {
        false
    }

    fn line(&mut self, _: &str, flag: &str, _: Option<&str>) -> Result<String, CliError> {
        Err(missing(flag))
    }

    fn secret(&mut self, _: &str, flag: &str) -> Result<String, CliError> {
        Err(missing(flag))
    }

    fn confirm(&mut self, _: &str, flag: &str, _: bool) -> Result<bool, CliError> {
        Err(missing(flag))
    }

    fn choose(&mut self, _: &str, flag: &str, _: &[String]) -> Result<usize, CliError> {
        Err(missing(flag))
    }

    fn say(&mut self, line: &str) {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

/// Questions on stderr, answers from stdin; secrets through rpassword.
pub struct Terminal;

fn read_line() -> Result<String, CliError> {
    let mut answer = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(CliError::Output)?;
    if read == 0 {
        return Err(CliError::Arguments("no answer: stdin ended".into()));
    }
    Ok(answer.trim().to_owned())
}

fn ask(question: &str) -> Result<String, CliError> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{question} ").map_err(CliError::Output)?;
    stderr.flush().map_err(CliError::Output)?;
    read_line()
}

impl Ask for Terminal {
    fn interactive(&self) -> bool {
        true
    }

    fn line(&mut self, question: &str, _: &str, default: Option<&str>) -> Result<String, CliError> {
        loop {
            let prompt = match default {
                Some(d) if !d.is_empty() => format!("{question} [{d}]:"),
                _ => format!("{question}:"),
            };
            let answer = ask(&prompt)?;
            match (answer.is_empty(), default) {
                (false, _) => return Ok(answer),
                (true, Some(d)) => return Ok(d.to_owned()),
                (true, None) => self.say("  an answer is needed"),
            }
        }
    }

    fn secret(&mut self, question: &str, _: &str) -> Result<String, CliError> {
        rpassword::prompt_password(format!("{question}: ")).map_err(CliError::Output)
    }

    fn confirm(&mut self, question: &str, _: &str, default: bool) -> Result<bool, CliError> {
        let choices = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            match ask(&format!("{question} {choices}"))?
                .to_ascii_lowercase()
                .as_str()
            {
                "" => return Ok(default),
                "y" | "yes" | "j" | "ja" => return Ok(true),
                "n" | "no" | "nein" => return Ok(false),
                _ => self.say("  y or n"),
            }
        }
    }

    fn choose(&mut self, question: &str, _: &str, options: &[String]) -> Result<usize, CliError> {
        self.say(question);
        for (i, option) in options.iter().enumerate() {
            self.say(&format!("  {}) {option}", i + 1));
        }
        loop {
            let answer = ask("number [1]:")?;
            if answer.is_empty() {
                return Ok(0);
            }
            match answer.parse::<usize>() {
                Ok(n) if (1..=options.len()).contains(&n) => return Ok(n - 1),
                _ => self.say(&format!("  1 to {}", options.len())),
            }
        }
    }

    fn say(&mut self, line: &str) {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

/// Answers given in advance, for tests of the interactive paths; what is said is kept.
#[cfg(test)]
pub struct Script {
    /// The answers, in order.
    pub answers: std::collections::VecDeque<String>,
    /// Every question and line said.
    pub said: Vec<String>,
}

#[cfg(test)]
impl Script {
    pub fn new(answers: &[&str]) -> Self {
        Script {
            answers: answers.iter().map(|a| (*a).to_owned()).collect(),
            said: Vec::new(),
        }
    }

    fn next(&mut self, question: &str) -> String {
        self.said.push(question.to_owned());
        self.answers
            .pop_front()
            .unwrap_or_else(|| panic!("no answer left for {question:?}"))
    }
}

#[cfg(test)]
impl Ask for Script {
    fn interactive(&self) -> bool {
        true
    }

    fn line(&mut self, question: &str, _: &str, default: Option<&str>) -> Result<String, CliError> {
        let answer = self.next(question);
        Ok(match (answer.is_empty(), default) {
            (true, Some(d)) => d.to_owned(),
            _ => answer,
        })
    }

    fn secret(&mut self, question: &str, _: &str) -> Result<String, CliError> {
        Ok(self.next(question))
    }

    fn confirm(&mut self, question: &str, _: &str, default: bool) -> Result<bool, CliError> {
        Ok(match self.next(question).as_str() {
            "" => default,
            answer => answer == "y",
        })
    }

    fn choose(&mut self, question: &str, _: &str, options: &[String]) -> Result<usize, CliError> {
        self.said.extend(options.iter().cloned());
        Ok(self.next(question).parse::<usize>().map_or(0, |n| n - 1))
    }

    fn say(&mut self, line: &str) {
        self.said.push(line.to_owned());
    }
}
