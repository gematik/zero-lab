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

//! STORE-001, STORE-005: length-prefixed fields and a reader that never reads or allocates
//! past its input.

use super::StoreError;

/// Appends `lp(x)`: a 32-bit big-endian length, then `x`.
pub(crate) fn put_lp(out: &mut Vec<u8>, x: &[u8]) {
    let len = u32::try_from(x.len()).expect("fields are bounded far below 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
}

/// Reads fields of one structure; every failure is `malformed` with the structure's name.
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8], what: &'static str) -> Self {
        Reader { rest: input, what }
    }

    pub(crate) fn malformed(&self) -> StoreError {
        StoreError::Malformed(self.what)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        if n > self.rest.len() {
            return Err(self.malformed());
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        let bytes = self.take(N)?;
        Ok(bytes.try_into().expect("take returned N bytes"))
    }

    pub(crate) fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A length-prefixed field; a length past the end is malformed before anything is
    /// allocated.
    pub(crate) fn lp(&mut self) -> Result<&'a [u8], StoreError> {
        let len = u32::from_be_bytes(self.array()?);
        let len = usize::try_from(len).map_err(|_| self.malformed())?;
        self.take(len)
    }

    pub(crate) fn rest(self) -> &'a [u8] {
        self.rest
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}
