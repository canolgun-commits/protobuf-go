//go:build go1.18
// +build go1.18

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package protowire_test

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// FuzzConsumeTag tests protobuf wire-format tag parsing with arbitrary bytes.
// Every protobuf message uses this wire format. A parsing bug here affects
// EVERY Go service using protobuf.
func FuzzConsumeTag(f *testing.F) {
	f.Add([]byte{0x08, 0x01})
	f.Add([]byte{0x12, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g'})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		for len(data) > 0 {
			_, _, n := protowire.ConsumeTag(data)
			if n < 0 {
				break
			}
			data = data[n:]
		}

		data2 := make([]byte, len(data))
		copy(data2, data)
		for len(data2) > 0 {
			_, n := protowire.ConsumeVarint(data2)
			if n < 0 {
				break
			}
			data2 = data2[n:]
		}
	})
}

// FuzzWireRoundTrip tests protobuf wire encoding → decoding consistency.
func FuzzWireRoundTrip(f *testing.F) {
	f.Add(uint32(1), uint32(0))
	f.Add(uint32(2), uint32(2))
	f.Add(uint32(5), uint32(5))

	f.Fuzz(func(t *testing.T, fieldNum, wireType uint32) {
		num := protowire.Number(1 + (fieldNum % ((1 << 29) - 1)))
		typ := protowire.Type(wireType % 7)

		var buf []byte
		buf = protowire.AppendTag(buf, num, typ)

		decodedNum, decodedType, n := protowire.ConsumeTag(buf)
		if n < 0 {
			t.Errorf("failed to decode tag: num=%d typ=%d buf=%x", num, typ, buf)
			return
		}

		if decodedNum != num || decodedType != typ {
			t.Errorf("round-trip mismatch: (%d,%d) → (%d,%d)", num, typ, decodedNum, decodedType)
		}
	})
}

// FuzzVarintRoundTrip tests varint encoding → decoding.
func FuzzVarintRoundTrip(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(128))
	f.Add(uint64(1<<64 - 1))

	f.Fuzz(func(t *testing.T, val uint64) {
		buf := protowire.AppendVarint(nil, val)

		decoded, n := protowire.ConsumeVarint(buf)
		if n < 0 {
			t.Errorf("failed to decode varint: val=%d buf=%x", val, buf)
			return
		}

		if decoded != val {
			t.Errorf("varint round-trip mismatch: %d → %x → %d", val, buf, decoded)
		}
	})
}

// FuzzConsumeField tests field consumption combining tag + value parsing.
func FuzzConsumeField(f *testing.F) {
	f.Add([]byte{0x08, 0x2a})
	f.Add([]byte{0x12, 0x03, 0x61, 0x62, 0x63})
	f.Add([]byte{0x1a, 0x04, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		for len(data) > 0 {
			num, typ, tagLen := protowire.ConsumeTag(data)
			if tagLen < 0 {
				break
			}
			data = data[tagLen:]

			valLen := protowire.ConsumeFieldValue(num, typ, data)
			if valLen < 0 {
				break
			}
			data = data[valLen:]
		}
	})
}
