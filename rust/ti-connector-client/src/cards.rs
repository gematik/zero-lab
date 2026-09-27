//! EventService: the cards in the Konnektor's terminals.

use crate::api::gematik::conn::eventservice72::{
    GetCards, GetCardsInput, GetResourceInformation, GetResourceInformationInput,
};
use crate::connector::Connector;
use crate::error::Error;
use crate::soap::Transport;
use crate::types::{Card, CardType, CertRef, Crypt, ResourceInformation};

/// The cards facade; see [`Connector::cards`].
#[derive(Debug)]
pub struct Cards<'a, T> {
    connector: &'a Connector<T>,
}

impl<T: Transport> Connector<T> {
    /// Cards in the Konnektor's terminals (EventService).
    pub fn cards(&self) -> Cards<'_, T> {
        Cards { connector: self }
    }
}

impl<T: Transport> Cards<'_, T> {
    /// The cards of `types`, or all cards when `types` is empty; each card once.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn list(&self, types: &[CardType]) -> Result<Vec<Card>, Error> {
        let mut cards: Vec<Card> = Vec::new();
        let filters: Vec<Option<CardType>> = if types.is_empty() {
            vec![None]
        } else {
            types.iter().copied().map(Some).collect()
        };
        for card_type in filters {
            let response = self
                .connector
                .call::<GetCardsInput>(GetCards {
                    mandant_wide: None,
                    context: self.connector.context(),
                    ct_id: None,
                    slot_id: None,
                    card_type,
                })
                .await?;
            for card in response.cards.card {
                if !cards.iter().any(|c| c.card_handle == card.card_handle) {
                    cards.push(card);
                }
            }
        }
        Ok(cards)
    }

    /// The card an identifier names: a card handle or ICCSN of a listed card, a
    /// Telematik-ID (`<1-2 digits>-…`, looked up in the C.AUT of the HBAs and SMC-Bs),
    /// or else a handle the Konnektor resolves itself. Listing first also finds cards
    /// the Konnektor answers no resource query for (SMC-KT).
    ///
    /// # Errors
    ///
    /// As [`Error`]; the error of the handle lookup when nothing matches.
    pub async fn find(&self, identifier: &str) -> Result<Card, Error> {
        let cards = self.list(&[]).await?;
        if let Some(card) = cards
            .iter()
            .find(|c| c.card_handle == identifier || c.iccsn.as_deref() == Some(identifier))
        {
            return Ok(card.clone());
        }
        let telematik_id = identifier.split_once('-').is_some_and(|(prefix, rest)| {
            (1..=2).contains(&prefix.len())
                && prefix.bytes().all(|b| b.is_ascii_digit())
                && !rest.is_empty()
        });
        if telematik_id {
            let holders = cards
                .into_iter()
                .filter(|c| matches!(c.card_type, CardType::Hba | CardType::SmcB));
            for card in holders {
                let certificates = self
                    .connector
                    .certificates()
                    .read(&card.card_handle, Crypt::Ecc, &[CertRef::CAut])
                    .await;
                if certificates
                    .is_ok_and(|c| c.iter().any(|c| c.telematik_id() == Some(identifier)))
                {
                    return Ok(card);
                }
            }
        }
        self.get(identifier).await
    }

    /// The card with `handle`.
    ///
    /// # Errors
    ///
    /// As [`Error`]; [`Error::Decode`] if the Konnektor answers without a card.
    pub async fn get(&self, handle: &str) -> Result<Card, Error> {
        let response = self
            .connector
            .call::<GetResourceInformationInput>(GetResourceInformation {
                context: self.connector.context(),
                ct_id: None,
                slot_id: None,
                iccsn: None,
                card_handle: Some(handle.to_owned()),
            })
            .await?;
        response
            .card
            .ok_or_else(|| Error::Decode(format!("GetResourceInformation: no card for {handle}")))
    }
}

impl<T: Transport> Connector<T> {
    /// The Konnektor's own state: VPN connections and operating errors
    /// (GetResourceInformation without a card or terminal).
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn status(&self) -> Result<ResourceInformation, Error> {
        self.call::<GetResourceInformationInput>(GetResourceInformation {
            context: self.context(),
            ct_id: None,
            slot_id: None,
            iccsn: None,
            card_handle: None,
        })
        .await
    }
}
