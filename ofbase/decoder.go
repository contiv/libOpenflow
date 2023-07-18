package ofbase

import (
	"encoding/binary"
)

type Decoder struct {
	buffer     []byte
	offset     int
	baseOffset int
}

func NewDecoder(data []byte) *Decoder {
	return &Decoder{
		buffer: data,
	}
}

func (d *Decoder) ReadByte() byte {
	c := d.buffer[d.offset]
	d.offset++
	return c
}

func (d *Decoder) ReadUint8() uint8 {
	i := uint8(d.buffer[d.offset])
	d.offset++
	return i
}

func (d *Decoder) ReadUint16() uint16 {
	i := binary.BigEndian.Uint16(d.buffer[d.offset : d.offset+2])
	d.offset += 2
	return i
}

func (d *Decoder) ReadUint32() uint32 {
	i := binary.BigEndian.Uint32(d.buffer[d.offset : d.offset+4])
	d.offset += 4
	return i
}

func (d *Decoder) ReadUint64() uint64 {
	i := binary.BigEndian.Uint64(d.buffer[d.offset : d.offset+8])
	d.offset += 8
	return i
}

func (d *Decoder) ReadUint128() Uint128 {
	hi := binary.BigEndian.Uint64(d.buffer[d.offset : d.offset+8])
	lo := binary.BigEndian.Uint64(d.buffer[d.offset+8 : d.offset+16])
	d.offset += 16
	return Uint128{
		Hi: hi,
		Lo: lo,
	}
}

func (d *Decoder) Skip(n int) {
	d.offset += n
}

func (d *Decoder) SkipAlign() {
	d.offset += (d.baseOffset+d.offset+7)/8*8 - d.baseOffset - d.offset
}

func (d *Decoder) Read(n int) []byte {
	data := d.buffer[d.offset : d.offset+n]
	d.offset += n
	return data
}

func (d *Decoder) Length() int {
	return len(d.buffer) - d.offset
}

func (d *Decoder) Bytes() []byte {
	return d.buffer[d.offset:]
}

func (d *Decoder) Offset() int {
	return d.offset
}

func (d *Decoder) BaseOffset() int {
	return d.baseOffset
}

func (d *Decoder) SliceDecoder(length, rewind int) *Decoder {
	newDecoder := NewDecoder(d.buffer[d.offset : d.offset+length-rewind])
	newDecoder.baseOffset = d.offset + d.baseOffset
	d.offset += length - rewind
	return newDecoder
}
