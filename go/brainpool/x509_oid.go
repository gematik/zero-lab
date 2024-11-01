// Modified version from Go standard library x509 package.
//
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package brainpool

import (
	"encoding/asn1"
)

func parseObjectIdentifier(der []byte) ([]uint64, bool) {
	out := make([]uint64, 0, len(der)+1)

	const (
		valSize         = 31 // amount of usable bits of val for OIDs.
		bitsPerByte     = 7
		maxValSafeShift = (1 << (valSize - bitsPerByte)) - 1
	)

	var val uint64 = 0

	for _, v := range der {
		if val > maxValSafeShift {
			return nil, false
		}

		val <<= bitsPerByte
		val |= uint64(v & 0x7F)

		if v&0x80 == 0 {
			if len(out) == 0 {
				if val < 80 {
					out = append(out, val/40)
					out = append(out, val%40)
				} else {
					out = append(out, 2)
					out = append(out, val-80)
				}
				val = 0
				continue
			}
			out = append(out, val)
			val = 0
		}
	}

	return out, true
}

func parseOIDString(oidStr string) (asn1.ObjectIdentifier, bool) {
	var (
		val int
		out []int
	)

	const (
		valSize         = 31 // amount of usable bits of val for OIDs.
		bitsPerByte     = 7
		maxValSafeShift = (1 << (valSize - bitsPerByte)) - 1
	)

	for i := 0; i < len(oidStr); i++ {
		curVal := int(oidStr[i] - '0')
		valEnd := i == len(oidStr)-1
		if curVal > 9 || curVal < 0 {
			return nil, false
		}
		if val > maxValSafeShift {
			return nil, false
		}
		val <<= bitsPerByte
		val |= curVal
		if valEnd {
			if len(out) == 0 {
				if val < 80 {
					out = append(out, val/40)
					out = append(out, val%40)
				} else {
					out = append(out, 2)
					out = append(out, val-80)
				}
			} else {
				out = append(out, val)
			}
			val = 0
		}
	}

	return asn1.ObjectIdentifier(out), true
}
