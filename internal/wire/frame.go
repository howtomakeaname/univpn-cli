// Package wire encodes bounded UniVPN v1 frames and TLV fields.
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	FirstConnect byte = 0x00
	Auth         byte = 0x01
	SecondAuth   byte = 0x02
	RequestVIP   byte = 0x03
	Keepalive    byte = 0x06
	DataConnect  byte = 0x64
	DataAlive    byte = 0x65
	DataPacket   byte = 0x66
	MaxPayload        = 65535
)

var magic = [4]byte{0xc1, 0x92, 0xa4, 0xd6}

type Frame struct {
	Command byte
	Payload []byte
}

func Read(r io.Reader) (Frame, error) {
	var h [8]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	if !bytes.Equal(h[:4], magic[:]) || h[4] != 1 {
		return Frame{}, errors.New("unsupported VPN frame magic/version")
	}
	f := Frame{Command: h[5], Payload: make([]byte, int(binary.BigEndian.Uint16(h[6:])))}
	_, err := io.ReadFull(r, f.Payload)
	return f, err
}

func Write(w io.Writer, cmd byte, payload []byte) error {
	if len(payload) > MaxPayload {
		return errors.New("VPN frame too large")
	}
	b := make([]byte, 8+len(payload))
	defer clear(b)
	copy(b, magic[:])
	b[4], b[5] = 1, cmd
	binary.BigEndian.PutUint16(b[6:], uint16(len(payload)))
	copy(b[8:], payload)
	return WriteAll(w, b)
}

func WriteAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

type TLV struct {
	Type  uint16
	Value []byte
}

func ParseTLVs(b []byte) ([]TLV, error) {
	var out []TLV
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errors.New("truncated VPN TLV header")
		}
		t, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if n > len(b) {
			return nil, errors.New("truncated VPN TLV value")
		}
		out = append(out, TLV{t, b[:n]})
		b = b[n:]
	}
	return out, nil
}

func AppendTLV(dst []byte, kind uint16, value []byte) []byte {
	if len(value) > MaxPayload {
		panic("oversized TLV")
	}
	return append(append(dst, byte(kind>>8), byte(kind), byte(len(value)>>8), byte(len(value))), value...)
}

func Domain(s string) ([]byte, error) {
	if len(s) == 0 || len(s) > 255 || bytes.IndexByte([]byte(s), 0) >= 0 {
		return nil, errors.New("authentication domain must be 1..255 bytes without NUL")
	}
	b := make([]byte, 256)
	copy(b, s)
	return b, nil
}

func Hello(domain string) ([]byte, error) {
	d, err := Domain(domain)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 340)
	copy(b, []byte{0xfe, 0xfc, 0xef, 0xbe, 0xc1, 0x92, 0xa4, 0xd6, 0, 0, 0, 0, 0, 0x1d, 1, 0x44})
	copy(b[80:], d)
	b[337] = 1
	return b, nil
}

func Expect(r io.Reader, command byte) ([]byte, error) {
	f, err := Read(r)
	if err != nil {
		return nil, err
	}
	if f.Command != command {
		return nil, fmt.Errorf("unexpected VPN command 0x%02x (expected 0x%02x)", f.Command, command)
	}
	return f.Payload, nil
}
