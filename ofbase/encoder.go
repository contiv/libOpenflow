package ofbase

import (
	"bytes"
	"encoding/binary"
)

type Encoder struct {
	buffer *bytes.Buffer
}

func NewEncoder() *Encoder {
	return &Encoder{
		buffer: new(bytes.Buffer),
	}
}

func (e *Encoder) PutChar(c byte) {
	e.buffer.WriteByte(c)
}

func (e *Encoder) PutUint8(i uint8) {
	e.buffer.WriteByte(i)
}

func (e *Encoder) PutUint16(i uint16) {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], i)
	e.buffer.Write(tmp[:])
}

func (e *Encoder) PutUint32(i uint32) {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[0:4], i)
	e.buffer.Write(tmp[:])
}

func (e *Encoder) PutUint64(i uint64) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[0:8], i)
	e.buffer.Write(tmp[:])
}

func (e *Encoder) PutUint128(i Uint128) {
	var tmp [16]byte
	binary.BigEndian.PutUint64(tmp[0:8], i.Hi)
	binary.BigEndian.PutUint64(tmp[8:16], i.Lo)
	e.buffer.Write(tmp[:])
}

func (e *Encoder) Write(b []byte) {
	e.buffer.Write(b)
}

func (e *Encoder) Bytes() []byte {
	return e.buffer.Bytes()
}

func (e *Encoder) SkipAlign() {
	length := len(e.buffer.Bytes())
	e.Write(bytes.Repeat([]byte{0}, (length+7)/8*8-length))
}
