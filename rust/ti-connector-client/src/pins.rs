//! CardService: PIN status, verification and change. Verification and change wait for
//! the user at the card terminal, so they use the long timeout.

use core::fmt;

use crate::api::gematik::conn::cardservice812::{
    ChangePin, ChangePinInput, GetPinStatus, GetPinStatusInput, VerifyPin, VerifyPinInput,
};
use crate::connector::Connector;
use crate::error::Error;
use crate::soap::Transport;
use crate::types::{CardType, PinResponse, PinStatus};

/// A card PIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PinType {
    /// `PIN.CH`, the cardholder PIN of an HBA or eGK.
    Ch,
    /// `PIN.QES`, the qualified-signature PIN of an HBA.
    Qes,
    /// `PIN.SMC`, the PIN of an SMC-B.
    Smc,
}

impl PinType {
    /// Every PIN type.
    pub const ALL: [PinType; 3] = [PinType::Ch, PinType::Qes, PinType::Smc];

    /// The name the Konnektor uses, e.g. `PIN.SMC`.
    pub const fn as_str(self) -> &'static str {
        match self {
            PinType::Ch => "PIN.CH",
            PinType::Qes => "PIN.QES",
            PinType::Smc => "PIN.SMC",
        }
    }

    /// The PINs a card type has; empty for cards without user PINs (SMC-KT).
    pub fn for_card(card_type: CardType) -> &'static [PinType] {
        match card_type {
            CardType::Hba => &[PinType::Ch, PinType::Qes],
            CardType::SmcB | CardType::HsmB | CardType::SmB => &[PinType::Smc],
            CardType::Egk => &[PinType::Ch],
            _ => &[],
        }
    }
}

impl fmt::Display for PinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for PinType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PinType::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| format!("unknown PIN type {s:?} (PIN.CH, PIN.QES, PIN.SMC)"))
    }
}

/// The PIN facade; see [`Connector::pins`].
#[derive(Debug)]
pub struct Pins<'a, T> {
    connector: &'a Connector<T>,
}

impl<T: Transport> Connector<T> {
    /// PIN status, verification and change (CardService).
    pub fn pins(&self) -> Pins<'_, T> {
        Pins { connector: self }
    }
}

impl<T: Transport> Pins<'_, T> {
    /// Whether `pin` of the card with `handle` is verified, verifiable, blocked or still
    /// a transport PIN, and the tries left.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn status(&self, handle: &str, pin: PinType) -> Result<PinStatus, Error> {
        self.connector
            .call::<GetPinStatusInput>(GetPinStatus {
                context: self.connector.context(),
                card_handle: handle.to_owned(),
                pin_typ: pin.as_str().to_owned(),
            })
            .await
    }

    /// Asks the user to enter `pin` at the card terminal.
    ///
    /// # Errors
    ///
    /// As [`Error`]. A wrong PIN is not an error: see the response's `pin_result`.
    pub async fn verify(&self, handle: &str, pin: PinType) -> Result<PinResponse, Error> {
        self.connector
            .call::<VerifyPinInput>(VerifyPin {
                context: self.connector.context(),
                card_handle: handle.to_owned(),
                pin_typ: pin.as_str().to_owned(),
            })
            .await
    }

    /// Asks the user to change `pin` at the card terminal.
    ///
    /// # Errors
    ///
    /// As [`Error`]. A rejected change is not an error: see the response's `pin_result`.
    pub async fn change(&self, handle: &str, pin: PinType) -> Result<PinResponse, Error> {
        self.connector
            .call::<ChangePinInput>(ChangePin {
                context: self.connector.context(),
                card_handle: handle.to_owned(),
                pin_typ: pin.as_str().to_owned(),
            })
            .await
    }
}
