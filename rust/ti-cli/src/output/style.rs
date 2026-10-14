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

//! The palette. Styles are written unconditionally; `anstream` strips them when stdout is
//! not a terminal, when `NO_COLOR` is set, or with `--color never`.

use anstyle::{AnsiColor, Style};

/// The document title in text output.
pub const TITLE: Style = Style::new().bold().underline();
/// Section headings.
pub const HEADING: Style = Style::new().bold();
/// Field labels: kept quiet, so color goes to the content.
pub const LABEL: Style = Style::new().dimmed();
/// The part of a value that matters most, e.g. a subject's common name.
pub const EMPHASIS: Style = Style::new().bold();
/// Secondary detail: descriptions, hex values, file names.
pub const DIM: Style = Style::new().dimmed();
/// URLs.
pub const URL: Style = AnsiColor::Blue.on_default().underline();
/// A positive verdict: valid, admissible.
pub const GOOD: Style = AnsiColor::Green.on_default().bold();
/// A negative verdict: invalid, expired, not admissible.
pub const BAD: Style = AnsiColor::Red.on_default().bold();
/// Warnings and phased-out states.
pub const WARN: Style = AnsiColor::Yellow.on_default().bold();
/// Identifiers: OIDs, type names, profile names.
pub const ID: Style = AnsiColor::Cyan.on_default();

pub(super) const JSON_KEY: Style = AnsiColor::Blue.on_default().bold();
pub(super) const JSON_STRING: Style = AnsiColor::Green.on_default();
pub(super) const JSON_NUMBER: Style = AnsiColor::Cyan.on_default();
pub(super) const JSON_LITERAL: Style = AnsiColor::Magenta.on_default();
