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

//! `ti probe <ENV>`: whether the TI services of an environment answer, checked by
//! ti-client ([`ti_client::probe`]) in parallel, drawn live as a table in a terminal.
//!
//! The endpoints are grouped by how they are reached: through the TI VPN of a Konnektor
//! or TI-Gateway, or from the internet. Without the VPN none of the first answers, and
//! the probe says so once for the block.

use std::time::Duration;

use ti_client::probe::{self, Access, Agents, Outcome, Probe, Report, Status, UNCHECKED};
use ti_pki::Env;

use super::connector::emit;
use crate::cli::GlobalArgs;
use crate::error::{CliError, Exit};
use crate::http;
use crate::output::live::Live;
use crate::output::{Line, Output, Tone, style, warning};

/// The ePA `x-useragent`, `ClientId/Version`; the aggregators reject other shapes.
const EPA_USER_AGENT: &str = concat!("ti-cli/", env!("CARGO_PKG_VERSION"));

/// Easter egg: `probe def`, a slip for `dev`, answered with a banner before the dev probes: tall
/// letters with spiked ends, filled yellow-orange and edged red.
const DEF: [&str; 8] = [
    "◢◣     ◢◣    ◢◣       ◢◣    ◢◣    ◢◣    ◢◣      ◢◣   ◢◣     ◢◣",
    "███◣   ████◣ ████◣    ██    ████◣ ███◣  ███◣   ◢██◣  ███◣   ███◣",
    "██◥█◣  ██    ██       ██    ██    ██◥█◣ ██◥█◣ ◢█◤◥█◣ ██◥█◣  ██◥█◣",
    "██ ◥█◣ ███◣  ███◣     ██    ███◣  ██◢█◤ ██◢█◤ ██████ ██◢█◤  ██ ◥█◣",
    "██ ◢█◤ ███◤  ███◤     ██    ███◤  ███◤  ███◤  ██  ██ ███◣   ██ ◢█◤",
    "██◢█◤  ██    ██       ██    ██    ██    ██    ██  ██ ██◥█◣  ██◢█◤",
    "███◤   ████◤ ██       ████◣ ████◤ ██    ██    ██  ██ ██ ◥█◣ ███◤",
    "◥◤     ◥◤    ◥◤       ◥◤    ◥◤    ◥◤    ◥◤    ◥◤  ◥◤ ◥◤  ◥◤ ◥◤",
];
const DEF_FILL: anstyle::Style = anstyle::RgbColor(255, 170, 0).on_default().bold();
const DEF_EDGE: anstyle::Style = anstyle::RgbColor(220, 20, 20).on_default().bold();

/// How an access path is named in the table.
fn path_label(access: Access) -> &'static str {
    match access {
        Access::TiVpn => "TI-VPN",
        Access::Internet => "Internet",
        Access::Bestandsnetz => "Bestandsnetze",
    }
}

/// Said once for the block when none of its endpoints answered.
fn not_reachable(access: Access) -> &'static str {
    match access {
        Access::TiVpn => "not reachable: no TI VPN?",
        Access::Internet => "not reachable: no internet?",
        Access::Bestandsnetz => "not reachable: not routed by the Konnektor, or no TI VPN?",
    }
}

/// Runs `ti probe`.
pub fn run(env: Env, def: bool, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let catalog = match std::env::var_os("TI_PROBE_ENDPOINTS_PATH") {
        Some(path) => Some(std::fs::read_to_string(&path).map_err(|e| CliError::Read {
            source_name: path.to_string_lossy().into_owned(),
            source: e,
        })?),
        None => None,
    };
    let endpoints = probe::endpoints(catalog.as_deref(), env)?;
    if global.net.insecure {
        warning("-k: TLS certificates are not checked");
    }
    let client = http::client(&global.net, out.verbosity());
    let agents = Agents::new(
        &client,
        env,
        &endpoints,
        || crate::trust::session(global, false, out),
        EPA_USER_AGENT,
    )?;
    let text = !out.is_json() && !out.is_markdown();
    let mut live = Live::new();
    let live_view = text && live.enabled();
    if def && live_view {
        for line in DEF {
            print_line(&def_line(line));
        }
        let dim = style::DIM;
        print_line(&format!("{dim}pour some sugar on dev{dim:#}\n"));
    }
    let mut tick = 0usize;
    let (probes, elapsed) = probe::run(agents, env, endpoints, |probes| {
        tick += 1;
        if live_view {
            live.draw(&lines(probes, tick));
        }
    });
    let report = Report::new(env, &probes, elapsed);
    let exit = if report.counts.fail > 0 {
        Exit::Invalid
    } else {
        Exit::Ok
    };
    if text {
        if live_view {
            live.finish(&lines(&probes, tick));
        } else {
            // Not a terminal: the groups once every probe is final.
            for line in lines(&probes, tick) {
                print_line(&line);
            }
        }
        print_line("");
        print_line(&summary(&report, elapsed));
        return Ok(exit);
    }
    emit(out, exit, &report, |doc| {
        for path in &report.access_paths {
            doc.section(path_label(path.access));
            if !path.available {
                doc.paragraph(Line::dim(not_reachable(path.access)));
            }
            let group = || report.probes.iter().filter(|p| p.access == path.access);
            let rows = group()
                .filter(|p| p.access.required() || p.answered)
                .map(|p| {
                    vec![
                        Line::strong(&p.name),
                        mark(p.status),
                        Line::code(&p.host),
                        Line::dim(format!("{} ms", p.duration_ms)),
                        match unchecked_note(&p.detail) {
                            (detail, Some(note)) => Line::text(detail).and_status(Tone::Warn, note),
                            (detail, None) => Line::text(detail),
                        },
                    ]
                });
            doc.table(&["SERVICE", "", "HOST", "TIME", "DETAIL"], rows.collect());
            if !path.access.required() && group().any(|p| !p.answered) {
                let silent = group().filter(|p| !p.answered).map(|p| p.name.as_str());
                doc.paragraph(Line::text(not_routed(silent)));
            }
        }
        doc.paragraph(Line::dim(summary_plain(&report, elapsed)));
    })
}

/// A styled line on stdout, through the stream that strips styles where colors are off.
/// A banner line: blocks in the fill colour, the triangles that edge them in red.
fn def_line(line: &str) -> String {
    line.chars()
        .map(|c| match c {
            '█' => format!("{DEF_FILL}{c}{DEF_FILL:#}"),
            '◢' | '◣' | '◤' | '◥' => format!("{DEF_EDGE}{c}{DEF_EDGE:#}"),
            _ => c.to_string(),
        })
        .collect()
}

fn print_line(line: &str) {
    use std::io::Write as _;
    // A closed stdout (`| head`) ends the output, not the probes' outcome.
    let _ = writeln!(crate::output::stdout(), "{line}");
}

fn mark(status: Status) -> Line {
    match status {
        Status::Ok => Line::status(Tone::Good, "✓"),
        Status::Warn => Line::status(Tone::Warn, "!"),
        Status::Fail => Line::status(Tone::Bad, "✗"),
    }
}

/// Column widths of name and host over all rows, so lines align.
fn widths(rows: &[Probe]) -> (usize, usize) {
    rows.iter().fold((7, 4), |(n, h), r| {
        (
            n.max(r.endpoint.name.chars().count()),
            h.max(r.endpoint.host().chars().count()),
        )
    })
}

const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// One row as a styled terminal line: `SERVICE  ✓  HOST  DETAIL  TIME`; all of it gray
/// in a block whose access path is down.
fn line(row: &Probe, (name_width, host_width): &(usize, usize), tick: usize, gray: bool) -> String {
    let (strong, dim) = (style::EMPHASIS, style::DIM);
    let name = |tone: anstyle::Style| format!("{tone}{:name_width$}{tone:#}", row.endpoint.name);
    let host = format!("{:host_width$}", row.endpoint.host());
    if gray && let Some(o) = &row.outcome {
        let ms = o.duration.as_millis();
        return format!(
            "{dim}{:name_width$}  ✗  {host}  {ms:>4} ms  {}{dim:#}",
            row.endpoint.name, o.detail
        );
    }
    match &row.outcome {
        None => {
            let frame = SPINNER[tick % SPINNER.len()];
            format!("{}  {dim}{frame}{dim:#}  {host}", name(strong))
        }
        Some(o) => {
            let (tone, symbol) = match o.status {
                Status::Ok => (style::GOOD, "✓"),
                Status::Warn => (style::WARN, "!"),
                Status::Fail => (style::BAD, "✗"),
            };
            let ms = o.duration.as_millis();
            let plain = anstyle::Style::new().fg_color(tone.get_fg_color());
            let (detail, note) = unchecked_note(&o.detail);
            let warn = style::WARN;
            let note = note.map_or_else(String::new, |note| format!("{warn}{note}{warn:#}"));
            format!(
                "{}  {tone}{symbol}{tone:#}  {host}  {dim}{ms:>4} ms{dim:#}  {plain}{detail}{plain:#}{note}",
                name(tone),
            )
        }
    }
}

/// The detail without the unchecked note, and the note if it ends the detail; the terminal
/// shows the note as a warning, whatever the answer's own verdict.
fn unchecked_note(detail: &str) -> (&str, Option<&str>) {
    match detail.strip_suffix(UNCHECKED) {
        Some(head) => (head, Some(UNCHECKED)),
        None => (detail, None),
    }
}

/// Rows sit this far in under their access path's heading.
const INDENT: &str = "  ";

/// The table: the column headings, then a block per access path, its heading flush left
/// and its rows indented below; a block whose path is down says so on its heading, and
/// its rows are gray.
fn lines(rows: &[Probe], tick: usize) -> Vec<String> {
    let widths = widths(rows);
    let label = style::LABEL;
    let mut lines = vec![format!(
        "{INDENT}{label}{:w0$}     {:w1$}     TIME  DETAIL{label:#}",
        "SERVICE",
        "HOST",
        w0 = widths.0,
        w1 = widths.1
    )];
    for access in Access::ALL {
        let group: Vec<&Probe> = rows
            .iter()
            .filter(|r| r.endpoint.access == access)
            .collect();
        if group.is_empty() {
            continue;
        }
        let down = probe::available(rows, access) == Some(false);
        lines.push(String::new());
        // The heading stays prominent either way; a path that is down says so after it.
        let strong = style::EMPHASIS;
        lines.push(if down {
            let warn = style::WARN;
            format!(
                "{strong}{}{strong:#} {warn}· {}{warn:#}",
                path_label(access),
                not_reachable(access)
            )
        } else {
            format!("{strong}{}{strong:#}", path_label(access))
        });
        if access.required() {
            lines.extend(
                group
                    .iter()
                    .map(|r| format!("{INDENT}{}", line(r, &widths, tick, down))),
            );
            continue;
        }
        lines.push(format!("{INDENT}{}", compact(&group, tick)));
    }
    lines
}

/// The Bestandsnetze on one line: production lists dozens and most practices book few, so a
/// row each would push the paths that matter off the screen. The names are grouped by result:
/// those still running, those that answered, by status, and those not routed; the JSON report
/// keeps each one's detail.
fn compact(group: &[&Probe], tick: usize) -> String {
    let names = |pick: &dyn Fn(&Outcome) -> bool| {
        group
            .iter()
            .filter(|r| r.outcome.as_ref().is_some_and(pick))
            .map(|r| r.endpoint.name.as_str())
            .collect::<Vec<_>>()
    };
    let (good, warn, bad, dim) = (style::GOOD, style::WARN, style::BAD, style::DIM);
    let mut parts = Vec::new();
    let running = group.iter().filter(|r| r.outcome.is_none()).count();
    if running > 0 {
        let frame = SPINNER[tick % SPINNER.len()];
        parts.push(format!("{dim}{frame} {running} probing{dim:#}"));
    }
    for (tone, symbol, status) in [
        (good, "✓", Status::Ok),
        (warn, "!", Status::Warn),
        (bad, "✗", Status::Fail),
    ] {
        let routed = names(&|o| o.answered && o.status == status);
        if !routed.is_empty() {
            parts.push(format!("{tone}{symbol} {}{tone:#}", routed.join(", ")));
        }
    }
    let silent = names(&|o| !o.answered);
    if !silent.is_empty() {
        parts.push(format!(
            "{warn}! {}{warn:#}",
            not_routed(silent.into_iter())
        ));
    }
    parts.join("  ")
}

/// The one line for the Bestandsnetze that did not answer.
fn not_routed<'a>(names: impl Iterator<Item = &'a str>) -> String {
    format!("not routed: {}", names.collect::<Vec<_>>().join(", "))
}

/// ` · TI-VPN not reachable` for each access path that is down.
fn paths_down(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut down = String::new();
    for path in report.access_paths.iter().filter(|p| !p.available) {
        let _ = write!(down, " · {} not reachable", path_label(path.access));
    }
    down
}

fn summary_plain(report: &Report, elapsed: Duration) -> String {
    let counts = &report.counts;
    format!(
        "{} ok · {} warn · {} failed{} · {:.1} s",
        counts.ok,
        counts.warn,
        counts.fail,
        paths_down(report),
        elapsed.as_secs_f64()
    )
}

fn summary(report: &Report, elapsed: Duration) -> String {
    let counts = &report.counts;
    let (good, warn, bad, dim) = (style::GOOD, style::WARN, style::BAD, style::DIM);
    let failed = if counts.fail > 0 {
        format!("{bad}{} failed{bad:#}", counts.fail)
    } else {
        "0 failed".to_owned()
    };
    let warned = if counts.warn > 0 {
        format!("{warn}{} warn{warn:#}", counts.warn)
    } else {
        "0 warn".to_owned()
    };
    format!(
        "{good}{} ok{good:#} · {warned} · {failed}{} {dim}· {:.1} s{dim:#}",
        counts.ok,
        paths_down(report),
        elapsed.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use ti_client::probe::Source;

    use super::*;

    /// An answer under -k stays green as judged; only its note that nobody checked the
    /// certificate is yellow.
    #[test]
    fn the_unchecked_note_alone_is_yellow() {
        let endpoint = probe::endpoints(None, Env::Prod).unwrap().remove(0);
        let row = Probe {
            endpoint,
            source: Source::Builtin,
            outcome: Some(Outcome {
                status: Status::Ok,
                answered: true,
                detail: format!("HTTP 200{UNCHECKED}"),
                http_status: Some(200),
                duration: Duration::ZERO,
                discovered: Vec::new(),
                verified: None,
            }),
        };
        let text = line(&row, &(10, 10), 0, false);
        let (good, warn) = (
            anstyle::Style::new().fg_color(style::GOOD.get_fg_color()),
            style::WARN,
        );
        assert!(
            text.contains(&format!("{good}HTTP 200{good:#}")),
            "{text:?}"
        );
        assert!(
            text.ends_with(&format!("{warn} · TLS unchecked{warn:#}")),
            "{text:?}"
        );
        assert_eq!(unchecked_note("HTTP 200"), ("HTTP 200", None));
    }

    /// Production lists 17 Bestandsnetze: they take one line, running or done, grouped by
    /// result, so the table keeps the paths every practice needs on the screen.
    #[test]
    fn the_bestandsnetze_take_one_line() {
        let mut rows: Vec<Probe> = probe::endpoints(None, Env::Prod)
            .unwrap()
            .into_iter()
            .map(|endpoint| Probe {
                endpoint,
                source: Source::Builtin,
                outcome: None,
            })
            .collect();
        let netze: Vec<usize> = (0..rows.len())
            .filter(|&i| rows[i].endpoint.access == Access::Bestandsnetz)
            .collect();
        assert!(netze.len() > 1);
        let group_lines = |rows: &[Probe]| {
            let lines = lines(rows, 0);
            let heading = lines
                .iter()
                .position(|l| l.contains("Bestandsnetze"))
                .unwrap();
            lines[heading + 1..].to_vec()
        };
        let running = group_lines(&rows);
        assert_eq!(running.len(), 1, "{running:?}");
        assert!(running[0].contains(&format!("{} probing", netze.len())));

        let outcome = |status, answered| Outcome {
            status,
            answered,
            detail: String::new(),
            http_status: None,
            duration: Duration::ZERO,
            discovered: Vec::new(),
            verified: None,
        };
        rows[netze[0]].outcome = Some(outcome(Status::Ok, true));
        for &i in &netze[1..] {
            rows[i].outcome = Some(outcome(Status::Warn, false));
        }
        let done = group_lines(&rows);
        assert_eq!(done.len(), 1, "{done:?}");
        assert!(done[0].contains(&rows[netze[0]].endpoint.name));
        assert!(done[0].contains("not routed:"));
        assert!(!done[0].contains("probing"));
    }
}
