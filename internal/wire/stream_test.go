// SPDX-License-Identifier: GPL-2.0-only

package wire

import (
	"bytes"
	"io"
	"testing"
	"testing/iotest"

	"github.com/rm4n0s/errors"
)

func TestFrameRoundTrip(t *testing.T) {
	packets := [][]byte{
		{0x38, 1, 2, 3},
		{},
		bytes.Repeat([]byte{0xcd}, 1250),
		bytes.Repeat([]byte{0xef}, MaxFrame),
		{0x22},
	}
	var stream []byte
	for _, p := range packets {
		var err error
		stream, err = AppendFrame(stream, p)
		if err != nil {
			t.Fatal(err)
		}
	}
	readers := map[string]io.Reader{
		"whole":          bytes.NewReader(stream),
		"one byte":       iotest.OneByteReader(bytes.NewReader(stream)),
		"half reads":     iotest.HalfReader(bytes.NewReader(stream)),
		"data and error": iotest.DataErrReader(bytes.NewReader(stream)),
	}
	for name, r := range readers {
		t.Run(name, func(t *testing.T) {
			buf := make([]byte, MaxFrame)
			for i, want := range packets {
				got, err := ReadFrame(r, buf)
				if err != nil {
					t.Fatalf("frame %d: %v", i, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("frame %d: got %d bytes, want %d", i, len(got), len(want))
				}
			}
			// The stream ends between two frames.
			_, err := ReadFrame(r, buf)
			if !errors.Is(err, io.EOF) {
				t.Errorf("at the end of the stream: %v, want io.EOF as the cause", err)
			}
		})
	}
}

func TestAppendFrameBytes(t *testing.T) {
	got, err := AppendFrame([]byte{0xff}, []byte{0x38, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xff, 0x00, 0x02, 0x38, 0x01}; !bytes.Equal(got, want) {
		t.Errorf("made %x, want %x", got, want)
	}
	// 258 bytes: the length is big endian.
	got, err = AppendFrame(nil, make([]byte, 258))
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x01 || got[1] != 0x02 {
		t.Errorf("length bytes = %x, want 0102", got[:2])
	}
}

func TestReadFrameFailures(t *testing.T) {
	tests := []struct {
		name   string
		stream []byte
		buf    int
		route  string
		cause  error
		meta   map[string]any
	}{
		{"empty stream", nil, 100, "ReadFrame.FrameReadFailed", io.EOF, map[string]any{"part": "length"}},
		{"one byte of the length", []byte{0x00}, 100, "ReadFrame.FrameReadFailed", io.ErrUnexpectedEOF, map[string]any{"part": "length"}},
		{"packet cut short", []byte{0x00, 0x05, 1, 2, 3}, 100, "ReadFrame.FrameReadFailed", io.ErrUnexpectedEOF, map[string]any{"part": "packet", "length": 5}},
		{"stream ends after the length", []byte{0x00, 0x05}, 100, "ReadFrame.FrameReadFailed", io.ErrUnexpectedEOF, map[string]any{"part": "packet"}},
		{"frame larger than the buffer", []byte{0x0b, 0xb8}, 1500, "ReadFrame.FrameTooLarge", nil, map[string]any{"length": 3000, "buffer": 1500}},
		{"frame one byte larger than the buffer", append([]byte{0x00, 0x04}, 1, 2, 3, 4), 3, "ReadFrame.FrameTooLarge", nil, map[string]any{"length": 4, "buffer": 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(tt.stream), make([]byte, tt.buf))
			appErr, ok := errors.FromError(err)
			if !ok {
				t.Fatalf("expected *errors.Error, got %T: %v", err, err)
			}
			if !appErr.HasRoute(tt.route) {
				t.Errorf("unexpected failure path: %s, want %s", appErr.Route(), tt.route)
			}
			if tt.cause != nil && !errors.Is(err, tt.cause) {
				t.Errorf("cause is not %v: %v", tt.cause, err)
			}
			for k, v := range tt.meta {
				if appErr.Metadata[k] != v {
					t.Errorf("metadata %q = %v (%T), want %v (%T)", k, appErr.Metadata[k], appErr.Metadata[k], v, v)
				}
			}
		})
	}
}

func TestReadFrameDoesNotReadAnOversizedFrame(t *testing.T) {
	// The peer says 60000 bytes follow; the reader must refuse after the length.
	r := &countingReader{r: bytes.NewReader(append([]byte{0xea, 0x60}, make([]byte, 60000)...))}
	_, err := ReadFrame(r, make([]byte, 1500))
	if err == nil {
		t.Fatal("no error")
	}
	if r.n != 2 {
		t.Errorf("read %d bytes before refusing, want 2", r.n)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestAppendFrameFailure(t *testing.T) {
	_, err := AppendFrame(nil, make([]byte, MaxFrame+1))
	appErr, ok := errors.FromError(err)
	if !ok {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if !appErr.HasRoute("AppendFrame.PacketTooLarge") {
		t.Errorf("unexpected failure path: %s", appErr.Route())
	}
	if appErr.Metadata["length"] != MaxFrame+1 || appErr.Metadata["max"] != MaxFrame {
		t.Errorf("metadata = %v", appErr.Metadata)
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0x00, 0x03, 0x38, 0x01, 0x02})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, stream []byte) {
		buf := make([]byte, 1500)
		packet, err := ReadFrame(bytes.NewReader(stream), buf)
		if err != nil {
			return
		}
		if len(packet) > len(buf) {
			t.Fatalf("returned %d bytes with a buffer of %d", len(packet), len(buf))
		}
		again, err := AppendFrame(nil, packet)
		if err != nil {
			t.Fatalf("a frame that was read cannot be written: %v", err)
		}
		if !bytes.Equal(again, stream[:len(again)]) {
			t.Fatalf("read %x from %x and wrote %x", packet, stream, again)
		}
	})
}
