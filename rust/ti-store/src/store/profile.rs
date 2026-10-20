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

//! Section J: which profile is in effect and where its files are. Pure: the caller hands in
//! the environment and the active file's content, so that the rules are tested without
//! touching the real ones.

use super::StoreError;

/// How paths are written and which defaults apply (STORE-092).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// Linux, macOS and other Unix systems: the XDG layout.
    Unix,
    /// Windows: the local and roaming application data.
    Windows,
}

impl Platform {
    /// The platform this program runs on.
    pub fn current() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::Unix
        }
    }

    fn sep(self) -> &'static str {
        match self {
            Platform::Unix => "/",
            Platform::Windows => "\\",
        }
    }

    fn is_absolute(self, p: &str) -> bool {
        match self {
            Platform::Unix => p.starts_with('/'),
            Platform::Windows => {
                let b = p.as_bytes();
                p.starts_with("\\\\")
                    || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
            }
        }
    }

    fn join(self, parts: &[&str]) -> String {
        parts.join(self.sep())
    }
}

/// Where the profile name came from (STORE-091).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameSource {
    /// `--profile`.
    Flag,
    /// `TI_PROFILE`.
    Env,
    /// The active file.
    Active,
    /// Nothing given: `default`.
    Default,
}

impl NameSource {
    /// The name the corpus and `store doctor` use.
    pub fn as_str(self) -> &'static str {
        match self {
            NameSource::Flag => "flag",
            NameSource::Env => "env",
            NameSource::Active => "active",
            NameSource::Default => "default",
        }
    }
}

/// What resolution reads, handed in by the caller.
pub struct Inputs<'a> {
    /// The platform.
    pub platform: Platform,
    /// `--profile`, if given.
    pub flag: Option<&'a str>,
    /// An environment variable's value.
    pub env: &'a dyn Fn(&str) -> Option<String>,
    /// The content of the active file, if it exists (read from [`active_file`]).
    pub active: Option<&'a str>,
    /// The home directory.
    pub home: Option<&'a str>,
}

/// The profile in effect and its files (STORE-091 to STORE-094).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Its name.
    pub name: String,
    /// Where the name came from.
    pub from: NameSource,
    /// The active file, where `profile use` writes.
    pub active_file: Option<String>,
    /// The key file of the `key-file` wrapper.
    pub kek_file: String,
    /// `keyring.bin`.
    pub keyring: String,
    /// `state.db`.
    pub state_db: String,
    /// `cache.db`.
    pub cache_db: String,
    /// The files backend's root for state.
    pub state_root: String,
    /// The files backend's root for the cache.
    pub cache_root: String,
}

/// STORE-090.
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=32).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

struct Resolver<'a, 'i> {
    i: &'i Inputs<'a>,
}

impl Resolver<'_, '_> {
    fn var(&self, name: &str) -> Option<String> {
        (self.i.env)(name)
    }

    fn home(&self) -> Result<&str, StoreError> {
        self.i
            .home
            .filter(|h| self.i.platform.is_absolute(h))
            .ok_or(StoreError::InvalidArgument("home directory"))
    }

    /// An XDG base directory: the variable if absolute, else `home/fallback`.
    fn xdg(&self, var: &str, fallback: &[&str]) -> Result<String, StoreError> {
        if let Some(v) = self.var(var).filter(|v| self.i.platform.is_absolute(v)) {
            return Ok(v);
        }
        let home = self.home()?;
        let mut parts = vec![home];
        parts.extend_from_slice(fallback);
        Ok(self.i.platform.join(&parts))
    }

    fn windows(&self, var: &str) -> Result<String, StoreError> {
        self.var(var)
            .filter(|v| self.i.platform.is_absolute(v))
            .ok_or(StoreError::InvalidArgument("application data directory"))
    }

    /// `TI_STATE_DIR` and friends: absolute if set (STORE-092, STORE-094).
    fn explicit(&self, var: &'static str) -> Result<Option<String>, StoreError> {
        match self.var(var) {
            None => Ok(None),
            Some(v) if !v.is_empty() && self.i.platform.is_absolute(&v) => Ok(Some(v)),
            Some(_) => Err(StoreError::InvalidArgument(var)),
        }
    }

    fn config(&self) -> Result<String, StoreError> {
        match self.i.platform {
            Platform::Windows => self.windows("APPDATA"),
            Platform::Unix => self.xdg("XDG_CONFIG_HOME", &[".config"]),
        }
    }

    fn state(&self) -> Result<String, StoreError> {
        if let Some(dir) = self.explicit("TI_STATE_DIR")? {
            return Ok(dir);
        }
        let p = self.i.platform;
        Ok(match p {
            Platform::Windows => p.join(&[&self.windows("LOCALAPPDATA")?, "state", "telematik"]),
            Platform::Unix => p.join(&[
                &self.xdg("XDG_STATE_HOME", &[".local", "state"])?,
                "telematik",
            ]),
        })
    }

    fn cache(&self) -> Result<String, StoreError> {
        if let Some(dir) = self.explicit("TI_CACHE_DIR")? {
            return Ok(dir);
        }
        let p = self.i.platform;
        Ok(match p {
            Platform::Windows => p.join(&[&self.windows("LOCALAPPDATA")?, "telematik"]),
            Platform::Unix => p.join(&[&self.xdg("XDG_CACHE_HOME", &[".cache"])?, "telematik"]),
        })
    }
}

/// The active file (STORE-091), if the configuration directory is known. The caller reads
/// it and passes its content as [`Inputs::active`].
pub fn active_file(
    platform: Platform,
    env: &dyn Fn(&str) -> Option<String>,
    home: Option<&str>,
) -> Option<String> {
    let inputs = Inputs {
        platform,
        flag: None,
        env,
        active: None,
        home,
    };
    let r = Resolver { i: &inputs };
    r.config()
        .ok()
        .map(|c| platform.join(&[&c, "telematik", "profiles", "active"]))
}

/// STORE-091 to STORE-094.
///
/// # Errors
///
/// `invalid_argument` for a profile name outside STORE-090, a relative or empty
/// override, or a missing home or application data directory.
pub fn resolve(inputs: &Inputs<'_>) -> Result<Profile, StoreError> {
    let r = Resolver { i: inputs };
    let p = inputs.platform;
    let config = r.config();

    let (name, from) = if let Some(flag) = inputs.flag {
        (flag.to_owned(), NameSource::Flag)
    } else if let Some(env) = r.var("TI_PROFILE").filter(|v| !v.is_empty()) {
        (env, NameSource::Env)
    } else if let Some(line) = inputs.active.and_then(|a| {
        let line = a.split('\n').next().unwrap_or("");
        let line = line.strip_suffix('\r').unwrap_or(line);
        (!line.is_empty()).then(|| line.to_owned())
    }) {
        (line, NameSource::Active)
    } else {
        ("default".to_owned(), NameSource::Default)
    };
    // never a fall-through to the next source
    if !valid_name(&name) {
        return Err(StoreError::InvalidArgument("profile name"));
    }

    let state = r.state()?;
    let cache = r.cache()?;
    let kek_file = match r.explicit("TI_STORE_KEK_PATH")? {
        Some(path) => path,
        None => p.join(&[
            &config.clone()?,
            "telematik",
            "profiles",
            &name,
            "store.kek",
        ]),
    };
    let state_dir = p.join(&[&state, "profiles", &name]);
    let cache_dir = p.join(&[&cache, "profiles", &name]);
    Ok(Profile {
        active_file: config
            .ok()
            .map(|c| p.join(&[&c, "telematik", "profiles", "active"])),
        kek_file,
        keyring: p.join(&[&state_dir, "keyring.bin"]),
        state_db: p.join(&[&state_dir, "state.db"]),
        cache_db: p.join(&[&cache_dir, "cache.db"]),
        state_root: p.join(&[&state_dir, "state"]),
        cache_root: p.join(&[&cache_dir, "cache"]),
        name,
        from,
    })
}
