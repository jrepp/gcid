// Package gcid implements the GCIDv2 wire format.
//
// GCIDv2 identifiers have the shape "<prefix>_<base58-payload>". The
// Base58 payload contains a clear four-byte header followed by an
// AES-256-GCM-SIV ciphertext and authentication tag. The visible prefix and
// clear header are authenticated as associated data.
package gcid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	Version           byte = 0x02
	SuiteAES256GCMSIV byte = 0x01
	SchemaSeq64Loc56  byte = 0x01
	DefaultKeyID      byte = 0x00
	HeaderLen              = 4
	LocationLen            = 7
	SequenceLen            = 8
	PlaintextLen           = LocationLen + SequenceLen
	TagLen                 = 16
	PayloadLen             = HeaderLen + PlaintextLen + TagLen
)

var (
	ErrInvalidKeyLength      = errors.New("gcid: key must be exactly 32 bytes")
	ErrInvalidPrefix         = errors.New("gcid: invalid prefix")
	ErrLocationOutOfRange    = errors.New("gcid: location must fit in 56 bits")
	ErrInvalidFormat         = errors.New("gcid: invalid format")
	ErrUnexpectedPrefix      = errors.New("gcid: unexpected prefix")
	ErrInvalidBase58         = errors.New("gcid: invalid base58 payload")
	ErrInvalidPayloadLength  = errors.New("gcid: invalid payload length")
	ErrUnsupportedVersion    = errors.New("gcid: unsupported version")
	ErrUnsupportedSuite      = errors.New("gcid: unsupported crypto suite")
	ErrUnsupportedSchema     = errors.New("gcid: unsupported payload schema")
	ErrUnsupportedKeyID      = errors.New("gcid: unsupported key id")
	ErrUnknownKeyID          = errors.New("gcid: unknown key id")
	ErrEmptyKeyring          = errors.New("gcid: empty keyring")
	ErrAuthentication        = errors.New("gcid: authentication failed")
	ErrInvalidPlaintextBytes = errors.New("gcid: invalid plaintext length")
)

var (
	nonce     = [12]byte{}
	aadDomain = []byte("GCIDv2")
)

// ID is a validated GCID string.
type ID struct {
	value     string
	prefixLen int
}

// ParseID validates the visible GCID string shape and returns an ID wrapper.
// It does not authenticate the cryptographic payload; use Codec.Decode or
// Keyring.Decode for that.
func ParseID(value string) (ID, error) {
	prefix, _, err := split(value)
	if err != nil {
		return ID{}, err
	}
	return ID{value: value, prefixLen: len(prefix)}, nil
}

func newID(value string, prefixLen int) ID {
	return ID{value: value, prefixLen: prefixLen}
}

func (id ID) String() string {
	return id.value
}

func (id ID) Prefix() string {
	return id.value[:id.prefixLen]
}

// LocationPartition is the encrypted 56-bit location, shard, or tenant field.
type LocationPartition [LocationLen]byte

// LocationFromUint64 builds a LocationPartition from a 56-bit unsigned value.
func LocationFromUint64(value uint64) (LocationPartition, error) {
	if value >= 1<<56 {
		return LocationPartition{}, fmt.Errorf("%w: %d", ErrLocationOutOfRange, value)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	var location LocationPartition
	copy(location[:], buf[1:])
	return location, nil
}

func (location LocationPartition) Uint64() uint64 {
	var buf [8]byte
	copy(buf[1:], location[:])
	return binary.BigEndian.Uint64(buf[:])
}

// Decoded is the authenticated plaintext recovered from a GCIDv2 value.
type Decoded struct {
	Prefix   string
	Sequence uint64
	Location LocationPartition
	Header   [HeaderLen]byte
	KeyID    byte
}

// Codec encodes and decodes GCIDv2 strings for a single key ID.
type Codec struct {
	keyID   byte
	authKey [16]byte
	block   cipher.Block
}

// NewCodec creates a GCIDv2 codec for the default key ID.
func NewCodec(key []byte) (*Codec, error) {
	return NewCodecWithKeyID(key, DefaultKeyID)
}

// NewCodecWithKeyID creates a GCIDv2 codec for a specific cleartext key ID.
func NewCodecWithKeyID(key []byte, keyID byte) (*Codec, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidKeyLength, len(key))
	}
	authKey, encKey, err := deriveKeys(key, nonce[:])
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey[:])
	if err != nil {
		return nil, err
	}
	return &Codec{keyID: keyID, authKey: authKey, block: block}, nil
}

func (codec *Codec) Header() [HeaderLen]byte {
	return [HeaderLen]byte{Version, SuiteAES256GCMSIV, SchemaSeq64Loc56, codec.keyID}
}

func (codec *Codec) Encode(prefix string, sequence uint64) (ID, error) {
	return codec.EncodeWithLocation(prefix, sequence, 0)
}

func (codec *Codec) EncodeWithLocation(prefix string, sequence uint64, location uint64) (ID, error) {
	part, err := LocationFromUint64(location)
	if err != nil {
		return ID{}, err
	}
	return codec.EncodeWithLocationPartition(prefix, sequence, part)
}

func (codec *Codec) EncodeWithLocationBytes(prefix string, sequence uint64, location [LocationLen]byte) (ID, error) {
	return codec.EncodeWithLocationPartition(prefix, sequence, LocationPartition(location))
}

func (codec *Codec) EncodeWithLocationPartition(prefix string, sequence uint64, location LocationPartition) (ID, error) {
	if err := validatePrefix(prefix); err != nil {
		return ID{}, err
	}

	header := codec.Header()
	var plaintext [PlaintextLen]byte
	copy(plaintext[:LocationLen], location[:])
	binary.BigEndian.PutUint64(plaintext[LocationLen:], sequence)

	ciphertext := codec.seal(plaintext[:], associatedData(prefix, header))
	var payload [PayloadLen]byte
	copy(payload[:HeaderLen], header[:])
	copy(payload[HeaderLen:], ciphertext)

	encoded := encodeBase58(payload[:])
	var b strings.Builder
	b.Grow(len(prefix) + 1 + len(encoded))
	b.WriteString(prefix)
	b.WriteByte('_')
	b.WriteString(encoded)
	return newID(b.String(), len(prefix)), nil
}

func (codec *Codec) Decode(expectedPrefix string, value string) (Decoded, error) {
	if err := validatePrefix(expectedPrefix); err != nil {
		return Decoded{}, err
	}
	prefix, payload, err := decodeParts(value)
	if err != nil {
		return Decoded{}, err
	}
	if prefix != expectedPrefix {
		return Decoded{}, fmt.Errorf("%w: expected %q got %q", ErrUnexpectedPrefix, expectedPrefix, prefix)
	}
	return codec.decodePayload(prefix, payload)
}

func (codec *Codec) DecodeID(expectedPrefix string, id ID) (Decoded, error) {
	return codec.Decode(expectedPrefix, id.String())
}

func (codec *Codec) DecodeAny(value string) (Decoded, error) {
	prefix, payload, err := decodeParts(value)
	if err != nil {
		return Decoded{}, err
	}
	return codec.decodePayload(prefix, payload)
}

func (codec *Codec) DecodeAnyID(id ID) (Decoded, error) {
	return codec.DecodeAny(id.String())
}

func (codec *Codec) decodePayload(prefix string, payload []byte) (Decoded, error) {
	if len(payload) != PayloadLen {
		return Decoded{}, fmt.Errorf("%w: expected %d got %d", ErrInvalidPayloadLength, PayloadLen, len(payload))
	}
	var header [HeaderLen]byte
	copy(header[:], payload[:HeaderLen])
	if err := validateHeader(header, codec.keyID); err != nil {
		return Decoded{}, err
	}

	plaintext, err := codec.open(payload[HeaderLen:], associatedData(prefix, header))
	if err != nil {
		return Decoded{}, err
	}
	if len(plaintext) != PlaintextLen {
		return Decoded{}, fmt.Errorf("%w: got %d", ErrInvalidPlaintextBytes, len(plaintext))
	}

	var location LocationPartition
	copy(location[:], plaintext[:LocationLen])
	return Decoded{
		Prefix:   prefix,
		Sequence: binary.BigEndian.Uint64(plaintext[LocationLen:]),
		Location: location,
		Header:   header,
		KeyID:    header[3],
	}, nil
}

// Keyring decodes GCIDs for multiple key IDs and encodes with a default key.
type Keyring struct {
	codecs       [256]*Codec
	defaultKeyID byte
	hasDefault   bool
}

func NewKeyring() *Keyring {
	return &Keyring{}
}

func KeyringWithKey(key []byte) (*Keyring, error) {
	return NewKeyring().AddKey(DefaultKeyID, key)
}

func (ring *Keyring) AddKey(keyID byte, key []byte) (*Keyring, error) {
	codec, err := NewCodecWithKeyID(key, keyID)
	if err != nil {
		return nil, err
	}
	ring.codecs[keyID] = codec
	if !ring.hasDefault {
		ring.defaultKeyID = keyID
		ring.hasDefault = true
	}
	return ring, nil
}

func (ring *Keyring) Encode(prefix string, sequence uint64) (ID, error) {
	codec, err := ring.defaultCodec()
	if err != nil {
		return ID{}, err
	}
	return codec.Encode(prefix, sequence)
}

func (ring *Keyring) Decode(expectedPrefix string, value string) (Decoded, error) {
	if err := validatePrefix(expectedPrefix); err != nil {
		return Decoded{}, err
	}
	prefix, payload, err := decodeParts(value)
	if err != nil {
		return Decoded{}, err
	}
	if prefix != expectedPrefix {
		return Decoded{}, fmt.Errorf("%w: expected %q got %q", ErrUnexpectedPrefix, expectedPrefix, prefix)
	}
	return ring.decodePayload(prefix, payload)
}

func (ring *Keyring) DecodeAny(value string) (Decoded, error) {
	prefix, payload, err := decodeParts(value)
	if err != nil {
		return Decoded{}, err
	}
	return ring.decodePayload(prefix, payload)
}

func (ring *Keyring) decodePayload(prefix string, payload []byte) (Decoded, error) {
	if len(payload) < HeaderLen {
		return Decoded{}, fmt.Errorf("%w: expected %d got %d", ErrInvalidPayloadLength, PayloadLen, len(payload))
	}
	keyID := payload[3]
	codec := ring.codecs[keyID]
	if codec == nil {
		return Decoded{}, fmt.Errorf("%w: %d", ErrUnknownKeyID, keyID)
	}
	return codec.decodePayload(prefix, payload)
}

func (ring *Keyring) defaultCodec() (*Codec, error) {
	if !ring.hasDefault {
		return nil, ErrEmptyKeyring
	}
	codec := ring.codecs[ring.defaultKeyID]
	if codec == nil {
		return nil, ErrEmptyKeyring
	}
	return codec, nil
}

func split(value string) (string, string, error) {
	separator := strings.IndexByte(value, '_')
	if separator < 0 || strings.IndexByte(value[separator+1:], '_') >= 0 {
		return "", "", ErrInvalidFormat
	}
	prefix := value[:separator]
	payload := value[separator+1:]
	if err := validatePrefix(prefix); err != nil {
		return "", "", err
	}
	if payload == "" {
		return "", "", ErrInvalidFormat
	}
	return prefix, payload, nil
}

func decodeParts(value string) (string, []byte, error) {
	prefix, encoded, err := split(value)
	if err != nil {
		return "", nil, err
	}
	payload, err := decodeBase58(encoded)
	if err != nil {
		return "", nil, err
	}
	return prefix, payload, nil
}

func validatePrefix(prefix string) error {
	if prefix == "" {
		return ErrInvalidPrefix
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if c < 0x21 || c > 0x7e || c == '_' {
			return fmt.Errorf("%w: %q", ErrInvalidPrefix, prefix)
		}
	}
	return nil
}

func validateHeader(header [HeaderLen]byte, expectedKeyID byte) error {
	if header[0] != Version {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, header[0])
	}
	if header[1] != SuiteAES256GCMSIV {
		return fmt.Errorf("%w: %d", ErrUnsupportedSuite, header[1])
	}
	if header[2] != SchemaSeq64Loc56 {
		return fmt.Errorf("%w: %d", ErrUnsupportedSchema, header[2])
	}
	if header[3] != expectedKeyID {
		return fmt.Errorf("%w: expected %d got %d", ErrUnsupportedKeyID, expectedKeyID, header[3])
	}
	return nil
}

func associatedData(prefix string, header [HeaderLen]byte) []byte {
	aad := make([]byte, 0, len(aadDomain)+1+len(prefix)+1+HeaderLen)
	aad = append(aad, aadDomain...)
	aad = append(aad, 0)
	aad = append(aad, prefix...)
	aad = append(aad, 0)
	aad = append(aad, header[:]...)
	return aad
}

func deriveKeys(key []byte, nonce []byte) ([16]byte, [32]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return [16]byte{}, [32]byte{}, err
	}
	var authKey [16]byte
	var encKey [32]byte
	var input [16]byte
	copy(input[4:], nonce)
	var encrypted [16]byte
	for counter := uint32(0); counter < 6; counter++ {
		binary.LittleEndian.PutUint32(input[:4], counter)
		block.Encrypt(encrypted[:], input[:])
		if counter < 2 {
			copy(authKey[counter*8:], encrypted[:8])
		} else {
			copy(encKey[(counter-2)*8:], encrypted[:8])
		}
	}
	return authKey, encKey, nil
}

func (codec *Codec) seal(plaintext, aad []byte) []byte {
	tag := codec.tag(plaintext, aad)
	ciphertext := aesCTR(codec.block, tag[:], plaintext)
	return append(ciphertext, tag[:]...)
}

func (codec *Codec) open(ciphertextAndTag, aad []byte) ([]byte, error) {
	if len(ciphertextAndTag) < TagLen {
		return nil, ErrAuthentication
	}
	tagOffset := len(ciphertextAndTag) - TagLen
	tag := ciphertextAndTag[tagOffset:]
	plaintext := aesCTR(codec.block, tag, ciphertextAndTag[:tagOffset])
	expected := codec.tag(plaintext, aad)
	if subtle.ConstantTimeCompare(tag, expected[:]) != 1 {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func (codec *Codec) tag(plaintext, aad []byte) [TagLen]byte {
	s := polyval(codec.authKey, aad, plaintext)
	for i := range nonce {
		s[i] ^= nonce[i]
	}
	s[15] &= 0x7f
	var tag [TagLen]byte
	codec.block.Encrypt(tag[:], s[:])
	return tag
}

func aesCTR(block cipher.Block, tag []byte, input []byte) []byte {
	var counter [16]byte
	copy(counter[:], tag)
	counter[15] |= 0x80
	out := make([]byte, len(input))
	var stream [16]byte
	for offset := 0; offset < len(input); {
		block.Encrypt(stream[:], counter[:])
		n := min(len(input)-offset, len(stream))
		for i := 0; i < n; i++ {
			out[offset+i] = input[offset+i] ^ stream[i]
		}
		offset += n
		ctr := binary.LittleEndian.Uint32(counter[:4])
		binary.LittleEndian.PutUint32(counter[:4], ctr+1)
	}
	return out
}

func polyval(h [16]byte, aad, plaintext []byte) [16]byte {
	hPrime := mulXGHASH(reverse16(h))
	var state [16]byte
	updatePolyval(&state, hPrime, aad)
	updatePolyval(&state, hPrime, plaintext)
	var lengthBlock [16]byte
	binary.LittleEndian.PutUint64(lengthBlock[:8], uint64(len(aad))*8)
	binary.LittleEndian.PutUint64(lengthBlock[8:], uint64(len(plaintext))*8)
	updatePolyvalBlock(&state, hPrime, lengthBlock)
	return reverse16(state)
}

func polyvalBlocks(h [16]byte, input []byte) [16]byte {
	hPrime := mulXGHASH(reverse16(h))
	var state [16]byte
	updatePolyval(&state, hPrime, input)
	return reverse16(state)
}

func updatePolyval(state *[16]byte, h [16]byte, data []byte) {
	for len(data) >= 16 {
		var block [16]byte
		copy(block[:], data[:16])
		updatePolyvalBlock(state, h, block)
		data = data[16:]
	}
	if len(data) > 0 {
		var block [16]byte
		copy(block[:], data)
		updatePolyvalBlock(state, h, block)
	}
}

func updatePolyvalBlock(state *[16]byte, h [16]byte, block [16]byte) {
	reversed := reverse16(block)
	for i := range state {
		state[i] ^= reversed[i]
	}
	*state = ghashMul(*state, h)
}

func reverse16(in [16]byte) [16]byte {
	var out [16]byte
	for i := range in {
		out[i] = in[15-i]
	}
	return out
}

func mulXGHASH(in [16]byte) [16]byte {
	out := shiftRight(in)
	if in[15]&1 != 0 {
		out[0] ^= 0xe1
	}
	return out
}

func ghashMul(x, y [16]byte) [16]byte {
	var z [16]byte
	v := y
	for i := 0; i < 128; i++ {
		if bit(x, i) != 0 {
			xor16(&z, v)
		}
		lsb := v[15] & 1
		v = shiftRight(v)
		if lsb != 0 {
			v[0] ^= 0xe1
		}
	}
	return z
}

func bit(block [16]byte, i int) byte {
	return (block[i/8] >> (7 - uint(i%8))) & 1
}

func shiftRight(in [16]byte) [16]byte {
	var out [16]byte
	var carry byte
	for i := range in {
		out[i] = (in[i] >> 1) | carry
		carry = (in[i] & 1) << 7
	}
	return out
}

func xor16(dst *[16]byte, src [16]byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	bigRadix = big.NewInt(58)
	b58Index = func() [256]int {
		var table [256]int
		for i := range table {
			table[i] = -1
		}
		for i := 0; i < len(base58Alphabet); i++ {
			table[base58Alphabet[i]] = i
		}
		return table
	}()
)

func encodeBase58(input []byte) string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	x := new(big.Int).SetBytes(input)
	mod := new(big.Int)
	var encoded []byte
	for x.Sign() > 0 {
		x.DivMod(x, bigRadix, mod)
		encoded = append(encoded, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		encoded = append(encoded, base58Alphabet[0])
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return string(encoded)
}

func decodeBase58(input string) ([]byte, error) {
	x := new(big.Int)
	var digit big.Int
	for i := 0; i < len(input); i++ {
		index := b58Index[input[i]]
		if index < 0 {
			return nil, ErrInvalidBase58
		}
		x.Mul(x, bigRadix)
		digit.SetInt64(int64(index))
		x.Add(x, &digit)
	}
	decoded := x.Bytes()
	zeros := 0
	for zeros < len(input) && input[zeros] == base58Alphabet[0] {
		zeros++
	}
	if zeros == 0 {
		return decoded, nil
	}
	out := make([]byte, zeros+len(decoded))
	copy(out[zeros:], decoded)
	return out, nil
}
