package gcid

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

var devKey = []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
var altKey = []byte("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY")

func TestSpecVectors(t *testing.T) {
	codec := newTestCodec(t)
	tests := []struct {
		prefix     string
		location   uint64
		sequence   uint64
		ciphertext string
		tag        string
		id         string
	}{
		{"prf", 0, 123, "619d1d6dc26f2d50845c51ee5b6f37", "f8015069da306ae7ee323ddcb428c45f", "prf_Cbds1yPUh73MNg2g2H3cdADCRuF7USjteUEdqeEAQPC7whQ"},
		{"asset", 0, 456, "be57802f7f0f0123077557a54ea928", "49ee9bd1fd58fd7476aef836e2d54ff8", "asset_Cbds3PQ1ZC2vzDFLB7qWod4hHnAuFwt4uqFH6NbKL1ZBCvT"},
		{"asset", 42, 123, "1c313f1a04c3c016de1298477fe0b8", "1f05d8b70283707ad41305890d03d7fe", "asset_CbdrzuzUWxA1FkCVjXXNP92ZT5cpu2DrP23ioGdJ5GPWj2M"},
		{"prf", 0, 0, "f3e6a0e5334c0076886a9dc80a9d4a", "b5fb28e63cede5a351e1e72f70b4f0fe", "prf_Cbds4CmMHP4273kXPwFQ8DQCPu3sd4CSAmhYDA7RzkTEGmb"},
		{"prf", 0, ^uint64(0), "0a4401ea838160882402e258cc8de4", "3f8c3ad5f654505d698dde38a96175e5", "prf_Cbdrze8v48sf8q2jPwrCf3TMB4Gs3YiHcnki91GDYsBwmxp"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			id, err := codec.EncodeWithLocation(tt.prefix, tt.sequence, tt.location)
			if err != nil {
				t.Fatal(err)
			}
			if id.String() != tt.id {
				t.Fatalf("EncodeWithLocation() = %q, want %q", id.String(), tt.id)
			}
			decoded, err := codec.Decode(tt.prefix, id.String())
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Sequence != tt.sequence {
				t.Fatalf("Sequence = %d, want %d", decoded.Sequence, tt.sequence)
			}
			if got := decoded.Location.Uint64(); got != tt.location {
				t.Fatalf("Location = %d, want %d", got, tt.location)
			}

			_, payload, err := decodeParts(id.String())
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(payload[HeaderLen : HeaderLen+PlaintextLen]); got != tt.ciphertext {
				t.Fatalf("ciphertext = %s, want %s", got, tt.ciphertext)
			}
			if got := hex.EncodeToString(payload[HeaderLen+PlaintextLen:]); got != tt.tag {
				t.Fatalf("tag = %s, want %s", got, tt.tag)
			}
		})
	}
}

func TestDecodeAnyAndID(t *testing.T) {
	codec := newTestCodec(t)
	id, err := codec.Encode("asset", 456)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Prefix() != "asset" {
		t.Fatalf("Prefix() = %q", parsed.Prefix())
	}
	decoded, err := codec.DecodeAnyID(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Prefix != "asset" || decoded.Sequence != 456 {
		t.Fatalf("decoded = %+v", decoded)
	}
	decoded, err = codec.DecodeID("asset", parsed)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sequence != 456 {
		t.Fatalf("DecodeID sequence = %d", decoded.Sequence)
	}
}

func TestRelabelingFailsAuthentication(t *testing.T) {
	codec := newTestCodec(t)
	id, err := codec.Encode("prf", 123)
	if err != nil {
		t.Fatal(err)
	}
	relabeled := "asset_" + id.String()[len("prf_"):]
	if _, err := codec.Decode("asset", relabeled); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Decode relabeled error = %v, want ErrAuthentication", err)
	}
}

func TestWrongExpectedPrefixFailsBeforeAuthentication(t *testing.T) {
	codec := newTestCodec(t)
	id, err := codec.Encode("prf", 123)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode("asset", id.String()); !errors.Is(err, ErrUnexpectedPrefix) {
		t.Fatalf("Decode wrong prefix error = %v, want ErrUnexpectedPrefix", err)
	}
}

func TestRejectsInvalidInputs(t *testing.T) {
	codec := newTestCodec(t)
	invalidPrefixes := []string{"", "bad_prefix", "bad prefix", "caf\u00e9"}
	for _, prefix := range invalidPrefixes {
		if _, err := codec.Encode(prefix, 1); !errors.Is(err, ErrInvalidPrefix) {
			t.Fatalf("Encode(%q) error = %v, want ErrInvalidPrefix", prefix, err)
		}
	}
	if _, err := codec.EncodeWithLocation("asset", 1, 1<<56); !errors.Is(err, ErrLocationOutOfRange) {
		t.Fatalf("EncodeWithLocation out of range error = %v", err)
	}
	if _, err := NewCodec(devKey[:31]); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("NewCodec short key error = %v", err)
	}
	if _, err := ParseID("prf_payload_extra"); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("ParseID extra separator error = %v", err)
	}
	if _, err := ParseID("prf_"); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("ParseID empty payload error = %v", err)
	}
	if _, err := codec.DecodeAny("prf_0"); !errors.Is(err, ErrInvalidBase58) {
		t.Fatalf("DecodeAny invalid base58 error = %v", err)
	}
	if _, err := codec.DecodeAny("prf_1"); !errors.Is(err, ErrInvalidPayloadLength) {
		t.Fatalf("DecodeAny short payload error = %v", err)
	}
	if _, err := codec.Decode("", "prf_1"); !errors.Is(err, ErrInvalidPrefix) {
		t.Fatalf("Decode invalid expected prefix error = %v", err)
	}
}

func TestHeaderAndPayloadTampering(t *testing.T) {
	codec := newTestCodec(t)
	id, err := codec.Encode("prf", 123)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		offset int
		value  byte
		err    error
	}{
		{0, 3, ErrUnsupportedVersion},
		{1, 2, ErrUnsupportedSuite},
		{2, 2, ErrUnsupportedSchema},
		{3, 1, ErrUnsupportedKeyID},
	} {
		mutated := mutatePayload(t, id.String(), tt.offset, tt.value, false)
		if _, err := codec.Decode("prf", mutated); !errors.Is(err, tt.err) {
			t.Fatalf("Decode mutated header offset %d error = %v, want %v", tt.offset, err, tt.err)
		}
	}
	for _, offset := range []int{4, PayloadLen - 1} {
		mutated := mutatePayload(t, id.String(), offset, 1, true)
		if _, err := codec.Decode("prf", mutated); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("Decode tampered payload offset %d error = %v", offset, err)
		}
	}
}

func TestKeyring(t *testing.T) {
	codec, err := NewCodecWithKeyID(devKey, 7)
	if err != nil {
		t.Fatal(err)
	}
	id, err := codec.Encode("prf", 99)
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyring()
	if _, err := ring.AddKey(1, altKey); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.AddKey(7, devKey); err != nil {
		t.Fatal(err)
	}
	decoded, err := ring.DecodeAny(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.KeyID != 7 || decoded.Sequence != 99 {
		t.Fatalf("decoded = %+v", decoded)
	}
	decoded, err = ring.Decode("prf", id.String())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sequence != 99 {
		t.Fatalf("Decode sequence = %d", decoded.Sequence)
	}
	otherRing, err := KeyringWithKey(altKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherRing.DecodeAny(id.String()); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("DecodeAny unknown key error = %v", err)
	}
	if _, err := NewKeyring().Encode("prf", 1); !errors.Is(err, ErrEmptyKeyring) {
		t.Fatalf("empty keyring Encode error = %v", err)
	}
	if _, err := NewKeyring().AddKey(1, devKey[:31]); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("AddKey short key error = %v", err)
	}
	if _, err := ring.Decode("asset", id.String()); !errors.Is(err, ErrUnexpectedPrefix) {
		t.Fatalf("Keyring Decode wrong prefix error = %v", err)
	}
	if _, err := ring.Decode("", id.String()); !errors.Is(err, ErrInvalidPrefix) {
		t.Fatalf("Keyring Decode invalid expected prefix error = %v", err)
	}
}

func TestLocationPartitionBytes(t *testing.T) {
	codec := newTestCodec(t)
	var location [LocationLen]byte
	location[6] = 42
	id, err := codec.EncodeWithLocationBytes("asset", 123, location)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := codec.DecodeID("asset", id)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Location.Uint64() != 42 {
		t.Fatalf("location = %d", decoded.Location.Uint64())
	}
}

func TestPolyvalRFCExample(t *testing.T) {
	h := mustHex16(t, "25629347589242761d31f826ba4b757b")
	x1 := mustHex(t, "4f4f95668c83dfb6401762bb2d01a262")
	x2 := mustHex(t, "d1a24ddd2721d006bbe45f20d3c9f362")
	got := polyvalBlocks(h, append(x1, x2...))
	want := mustHex(t, "f7a3b47b846119fae5b7866cf5e5b77e")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("polyval = %x, want %x", got, want)
	}
}

func BenchmarkEncode(b *testing.B) {
	codec := newTestCodec(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := codec.Encode("prf", uint64(i)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	codec := newTestCodec(b)
	ids := make([]ID, 1024)
	for i := range ids {
		id, err := codec.Encode("prf", uint64(i))
		if err != nil {
			b.Fatal(err)
		}
		ids[i] = id
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := codec.DecodeID("prf", ids[i%len(ids)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyringDecode(b *testing.B) {
	codec, err := NewCodecWithKeyID(devKey, 7)
	if err != nil {
		b.Fatal(err)
	}
	id, err := codec.Encode("prf", 123)
	if err != nil {
		b.Fatal(err)
	}
	ring := NewKeyring()
	if _, err := ring.AddKey(7, devKey); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ring.DecodeAny(id.String()); err != nil {
			b.Fatal(err)
		}
	}
}

func newTestCodec(tb testing.TB) *Codec {
	tb.Helper()
	codec, err := NewCodec(devKey)
	if err != nil {
		tb.Fatal(err)
	}
	return codec
}

func mutatePayload(t *testing.T, id string, offset int, value byte, xor bool) string {
	t.Helper()
	prefix, payload, err := decodeParts(id)
	if err != nil {
		t.Fatal(err)
	}
	if xor {
		payload[offset] ^= value
	} else {
		payload[offset] = value
	}
	return prefix + "_" + encodeBase58(payload)
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func mustHex16(t *testing.T, value string) [16]byte {
	t.Helper()
	decoded := mustHex(t, value)
	var out [16]byte
	copy(out[:], decoded)
	return out
}
