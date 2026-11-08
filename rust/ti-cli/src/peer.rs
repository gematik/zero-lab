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

//! `pki verify --connect` and `pki tsl bundle --connect`: the server to take the chain
//! from, which ti-client fetches.

/// `HOST[:PORT]`, the port 443 by default; IPv6 addresses in brackets.
pub fn target(value: &str) -> Result<(String, u16), String> {
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port))
            if !host.ends_with(':') && (!host.contains(':') || host.ends_with(']')) =>
        {
            let port = port
                .parse()
                .map_err(|_| format!("{port:?} is not a port"))?;
            (host, port)
        }
        _ => (value, 443),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("no host".into());
    }
    Ok((host.to_owned(), port))
}

/// The chain `host` presents on `port` ([`ti_client::peer::server_chain`]), over `net`'s
/// proxy and within its timeouts.
pub fn server_chain(
    host: &str,
    port: u16,
    net: &crate::net::NetArgs,
) -> Result<Vec<Vec<u8>>, crate::error::CliError> {
    Ok(ti_client::peer::server_chain(&net.net(), host, port)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(
            target("epa-as-1.ref.epa4all.de"),
            Ok(("epa-as-1.ref.epa4all.de".into(), 443))
        );
        assert_eq!(target("host:8443"), Ok(("host".into(), 8443)));
        assert_eq!(target("[::1]:8443"), Ok(("::1".into(), 8443)));
        assert_eq!(target("[::1]"), Ok(("::1".into(), 443)));
        assert!(target("host:http").is_err());
        assert!(target(":443").is_err());
    }
}
