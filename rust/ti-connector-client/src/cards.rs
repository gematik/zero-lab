//! EventService: the cards in the Konnektor's terminals.

use crate::api::gematik::conn::eventservice72::{
    GetCards, GetCardsInput, GetResourceInformation, GetResourceInformationInput,
};
use crate::connector::Connector;
use crate::error::Error;
use crate::soap::Transport;
use crate::types::{Card, CardType};

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
