package wire

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

type oneByte struct{ io.Reader }

func (r oneByte) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}

func TestFragmentedFrameGolden(t *testing.T) {
	golden, _ := hex.DecodeString("c192a4d60166000b0000000000000000616263")
	f, err := Read(oneByte{bytes.NewReader(golden)})
	if err != nil || f.Command != DataPacket || !bytes.Equal(f.Payload, append(make([]byte, 8), 'a', 'b', 'c')) {
		t.Fatalf("frame: %+v, %v", f, err)
	}
	var out bytes.Buffer
	if err = Write(&out, f.Command, f.Payload); err != nil || !bytes.Equal(out.Bytes(), golden) {
		t.Fatal("encoding differs from fixture", err)
	}
}

func TestRejectMalformed(t *testing.T) {
	for _, s := range []string{"c192a4d60101000300", "c192a4d602010000", "0092a4d601010000", "c192a4d601"} {
		b, _ := hex.DecodeString(s)
		if _, err := Read(bytes.NewReader(b)); err == nil {
			t.Fatal("accepted malformed frame", s)
		}
	}
	if _, err := ParseTLVs([]byte{0, 1, 0, 3, 1}); err == nil {
		t.Fatal("accepted oversized TLV")
	}
	if _, err := ParseTLVs([]byte{0, 1, 0}); err == nil {
		t.Fatal("accepted short TLV")
	}
	if err := Write(io.Discard, 0, make([]byte, 65536)); err == nil {
		t.Fatal("accepted oversized frame")
	}
}

func TestHelloLayout(t *testing.T) {
	b, err := Hello("vpn.example.com")
	if err != nil || len(b) != 340 {
		t.Fatal(len(b), err)
	}
	if hex.EncodeToString(b[:16]) != "fefcefbec192a4d600000000001d0144" || hex.EncodeToString(b[336:]) != "00010000" {
		t.Fatal("incorrect hello header/trailer")
	}
	if string(bytes.TrimRight(b[80:336], "\x00")) != "vpn.example.com" {
		t.Fatal("incorrect domain")
	}
	for _, s := range []string{"", strings.Repeat("a", 256), "bad\x00domain"} {
		if _, err := Hello(s); err == nil {
			t.Fatal("accepted invalid domain")
		}
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{0xc1, 0x92, 0xa4, 0xd6, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		frame, err := Read(bytes.NewReader(b))
		if err == nil && len(frame.Payload) > MaxPayload {
			t.Fatal("unbounded allocation")
		}
		ParseTLVs(b)
	})
}
