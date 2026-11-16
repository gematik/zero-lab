// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package vau

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

// Why a CBOR message was refused. A decoding error wraps one of them and names at most a
// field of the message type, never a value of the input (servers.md rule 14): fxamacker's
// own errors quote a duplicate key, so they are not passed on.
var (
	ErrCBORMalformed    = errors.New("vau: CBOR not well-formed")
	ErrCBORDuplicateKey = errors.New("vau: CBOR map with a duplicate key")
	ErrCBORUnknownField = errors.New("vau: CBOR map with a key the message does not have")
	ErrCBORTag          = errors.New("vau: CBOR tag")
	ErrCBORTrailingData = errors.New("vau: bytes after the CBOR message")
	ErrCBORLimit        = errors.New("vau: CBOR nested or sized beyond its bound")
	ErrCBORSimpleValue  = errors.New("vau: CBOR null or undefined")
	ErrCBORType         = errors.New("vau: CBOR value of the wrong type")
	ErrCBORMissingField = errors.New("vau: CBOR message without a required field")
	ErrCBORMessageType  = errors.New("vau: CBOR message of another MessageType")
	ErrBodyTooLarge     = errors.New("vau: HTTP body larger than allowed")
)

// maxMessageSize bounds the body of every CBOR message the client reads: the handshake
// messages (lib-vau's Message2 is 2772 bytes), an error and the CertData (a brainpool
// certificate, its CA and the cross-certificates, about 1 KiB each). 64 KiB leaves room for
// long chains without letting a peer make the client buffer more.
const maxMessageSize = 64 << 10

// maxResponseSize bounds an encrypted response of the channel: it carries the inner HTTP
// response with ePA documents, which gemSpec_Aktensystem limits to 25 MB each, and a
// RetrieveDocumentSet may return several.
const maxResponseSize = 128 << 20

// The bounds a peer's message is held to: the deepest message is three levels (a key map
// inside a message inside nothing else); unknown attributes of the VAU keys (A_24425-01)
// get some room beyond that, and none of the messages has more than a handful of pairs or
// a long array.
const (
	maxNestedLevels  = 8
	maxArrayElements = 16
	maxMapPairs      = 32
)

func decOptions() cbor.DecOptions {
	return cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
		TagsMd:    cbor.TagsForbidden,
		// lib-vau (Jackson) writes every map with indefinite length.
		IndefLength:       cbor.IndefLengthAllowed,
		MaxNestedLevels:   maxNestedLevels,
		MaxArrayElements:  maxArrayElements,
		MaxMapPairs:       maxMapPairs,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
	}
}

// decMode decodes every message of the package: a map holds only the keys its type names,
// each once and exactly as written, without tags, null or undefined. Types whose
// specification lets the peer add keys ([PublicVAUKeys], [MessageError]) or send null
// ([SignedPublicVAUKeys]) split the map with pairsDecMode first.
var decMode = func() cbor.DecMode {
	options := decOptions()
	simple, err := cbor.NewSimpleValueRegistryFromDefaults(
		cbor.WithRejectedSimpleValue(cbor.SimpleValue(22)),
		cbor.WithRejectedSimpleValue(cbor.SimpleValue(23)),
	)
	if err != nil {
		panic(err)
	}
	options.SimpleValues = simple
	mode, err := options.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// maxSkippedNesting and maxSkippedItems bound the attributes of the VAU keys and the pairs
// of an error that the client ignores (A_24425-01, A_24635): whatever they hold is skipped,
// but not without limit.
const (
	maxSkippedNesting = 16
	maxSkippedItems   = 1024
)

// skipDecMode splits a map whose unknown keys are ignored: their values may hold anything
// well-formed within the bounds, tags and null included; only the known keys are then
// decoded with decMode.
var skipDecMode = func() cbor.DecMode {
	options := decOptions()
	options.TagsMd = cbor.TagsAllowed
	options.MaxNestedLevels = maxSkippedNesting
	options.MaxArrayElements = maxSkippedItems
	options.MaxMapPairs = maxSkippedItems
	mode, err := options.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// pairsDecMode is decMode that lets null through, for the one field where a peer sends it.
var pairsDecMode = func() cbor.DecMode {
	mode, err := decOptions().DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

var cborNull = []byte{0xf6}

// encMode writes an empty byte string or array where a field is nil, since decMode refuses
// null.
var encMode = func() cbor.EncMode {
	mode, err := cbor.EncOptions{NilContainers: cbor.NilContainerAsEmpty}.EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// decode decodes data, one complete CBOR item and nothing after it, into v with decMode.
func decode(data []byte, v any) error {
	return decodeError(decMode.Unmarshal(data, v))
}

// decodePairs decodes data, a map with text keys, into v: keys not in known are dropped
// when the specification tells the client to ignore them, and nullable keys whose value is
// null count as absent. The values left are decoded as strictly as decode does.
func decodePairs(data []byte, v any, known []string, ignoreUnknown bool, nullable ...string) error {
	split := pairsDecMode
	if ignoreUnknown {
		split = skipDecMode
	}
	var pairs map[string]cbor.RawMessage
	if err := split.Unmarshal(data, &pairs); err != nil {
		return decodeError(err)
	}
	for key, value := range pairs {
		switch {
		case slices.Contains(nullable, key) && slices.Equal(value, cborNull):
			delete(pairs, key)
		case ignoreUnknown && !slices.Contains(known, key):
			delete(pairs, key)
		}
	}
	kept, err := encMode.Marshal(pairs)
	if err != nil {
		return fmt.Errorf("%w: re-encoding", ErrCBORMalformed)
	}
	return decode(kept, v)
}

// refusals are the package's reasons, which a nested UnmarshalCBOR returns as they are.
var refusals = []error{
	ErrCBORMalformed, ErrCBORDuplicateKey, ErrCBORUnknownField, ErrCBORTag, ErrCBORTrailingData,
	ErrCBORLimit, ErrCBORSimpleValue, ErrCBORType, ErrCBORMissingField, ErrCBORMessageType,
}

// decodeError maps fxamacker's errors to the package's, which carry no input.
func decodeError(err error) error {
	if err == nil {
		return nil
	}
	if slices.ContainsFunc(refusals, func(target error) bool { return errors.Is(err, target) }) {
		return err
	}
	var (
		unknown   *cbor.UnknownFieldError
		wrongType *cbor.UnmarshalTypeError
	)
	switch {
	case errors.As(err, new(*cbor.DupMapKeyError)):
		return ErrCBORDuplicateKey
	case errors.As(err, &unknown):
		return fmt.Errorf("%w (pair %d)", ErrCBORUnknownField, unknown.Index)
	case errors.As(err, new(*cbor.TagsMdError)):
		return ErrCBORTag
	case errors.As(err, new(*cbor.ExtraneousDataError)):
		return ErrCBORTrailingData
	case errors.As(err, new(*cbor.MaxNestedLevelError)), errors.As(err, new(*cbor.MaxArrayElementsError)),
		errors.As(err, new(*cbor.MaxMapPairsError)):
		return ErrCBORLimit
	case errors.As(err, new(cbor.UnacceptableDataItemError)), errors.As(err, new(*cbor.UnacceptableDataItemError)):
		return ErrCBORSimpleValue
	case errors.As(err, &wrongType):
		if wrongType.StructFieldName != "" {
			return fmt.Errorf("%w: field %s", ErrCBORType, wrongType.StructFieldName)
		}
		return ErrCBORType
	}
	return ErrCBORMalformed
}

// checkMessageType refuses a message whose MessageType is not want; the value got is not
// quoted, as it is the peer's.
func checkMessageType(got, want string) error {
	if got != want {
		return fmt.Errorf("%w: want %s", ErrCBORMessageType, want)
	}
	return nil
}

// readBounded reads r to its end, refusing more than limit bytes before it buffers them.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrBodyTooLarge, limit)
	}
	return data, nil
}
