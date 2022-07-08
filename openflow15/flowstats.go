package openflow15

import (
	"encoding/binary"
	"errors"

	"antrea.io/libOpenflow/util"

	"github.com/sirupsen/logrus"
)

// ofp_stats
type Stats struct {
	Reserved uint16 /* Reserved for future use, currently zeroed. */
	Length   uint16 /* Length of ofp_stats (excluding padding) */
	/* Followed by:
	 * - Exactly (length - 4) (possibly 0) bytes containing OXS TLVs, then
	 * - Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of
	 * all-zero bytes
	 * In summary, ofp_stats is padded as needed, to make its overall size
	 * a multiple of 8, to preserve alignement in structures using it.
	 */
	Fields []util.Message
	Pad    uint32 /* Zero bytes - see above for sizing */
}

func (s *Stats) Len() (n uint16) {
	n = 4
	for _, f := range s.Fields {
		n += f.Len()
	}
	n += 4
	return n
}

func (s *Stats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	n := 2
	s.Length = s.Len() - 4 // 'Pad' not part of Length
	binary.BigEndian.PutUint16(data[n:], s.Length)
	n += 2

	for _, f := range s.Fields {
		var b []byte
		b, err = f.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += len(b)
	}
	return
}

func (s *Stats) UnmarshalBinary(data []byte) (err error) {
	logrus.Debugf("Stats Data: %x", data)
	n := 2 // 2 bytes Reserved
	s.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	logrus.Debugf("Stats Length: %d", s.Length)
	for n < int(s.Length) {
		var f util.Message
		logrus.Debugf("Stats Field: %d", data[n+2]>>1)
		switch data[n+2] >> 1 {
		case XST_OFB_DURATION:
			fallthrough
		case XST_OFB_IDLE_TIME:
			logrus.Debugf("Received TimeStatField n:%d", n)
			f = new(TimeStatField)
		case XST_OFB_FLOW_COUNT:
			logrus.Debugf("Received FlowCountStatField n:%d", n)
			f = new(FlowCountStatField)
		case XST_OFB_PACKET_COUNT:
			fallthrough
		case XST_OFB_BYTE_COUNT:
			logrus.Debugf("Received PBCountStatField n:%d", n)
			f = new(PBCountStatField)
		default:
			logrus.Debugf("Received Unknown field: %d", data[n+2])
			err = errors.New("Unknown type received for the Stats Field")
			return
		}
		err = f.UnmarshalBinary(data[n:])
		if err != nil {
			return
		}
		n += int(f.Len())
		s.Fields = append(s.Fields, f)
	}
	return
}

func NewStats() *Stats {
	s := new(Stats)

	return s
}

func (s *Stats) AddField(f util.Message) {
	s.Fields = append(s.Fields, f)
}

// ofp_oxs_class
const (
	XSC_OPENFLOW_BASIC = 0x8002
	XSC_EXPERIMENTER   = 0xFFFF
)

// oxs_ofb_stat_fields
const (
	XST_OFB_DURATION     = 0 /* Time flow entry has been alive. */
	XST_OFB_IDLE_TIME    = 1 /* Time flow entry has been idle. */
	XST_OFB_FLOW_COUNT   = 3 /* Number of aggregated flow entries. */
	XST_OFB_PACKET_COUNT = 4 /* Number of packets in flow entry. */
	XST_OFB_BYTE_COUNT   = 5 /* Number of bytes in flow entry. */
)

type OXSStatHeader struct {
	Class  uint16
	Field  uint8
	Length uint8
}

func (f *OXSStatHeader) Len() (n uint16) {
	n = 4
	return
}

func (h *OXSStatHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(h.Len()))
	n := 0

	binary.BigEndian.PutUint16(data[n:], h.Class)
	n += 2

	data[n] = h.Field << 1
	n++

	data[n] = h.Length
	n++
	return
}

func (h *OXSStatHeader) UnmarshalBinary(data []byte) (err error) {
	h.Class = binary.BigEndian.Uint16(data[0:])
	h.Field = data[2] >> 1
	h.Length = data[3]
	return
}

// type XST_OFB_DURATION or XST_OFB_IDLE_TIME
type TimeStatField struct {
	Header OXSStatHeader
	Sec    uint32
	NSec   uint32
}

func (f *TimeStatField) Len() (n uint16) {
	n = f.Header.Len()
	n += 8
	return
}

func (f *TimeStatField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(f.Len()))
	n := 0
	var b []byte
	f.Header.Length = 8
	b, err = f.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)

	binary.BigEndian.PutUint32(data[n:], f.Sec)
	n += 4
	binary.BigEndian.PutUint32(data[n:], f.NSec)
	n += 4
	return
}

func (f *TimeStatField) UnmarshalBinary(data []byte) (err error) {
	err = f.Header.UnmarshalBinary(data)
	if err != nil {
		return
	}
	n := f.Header.Len()
	logrus.Debugf("Header Len: %d", n)
	f.Sec = binary.BigEndian.Uint32(data[n:])
	n += 4
	f.NSec = binary.BigEndian.Uint32(data[n:])
	n += 4
	return
}

type DurationStatField = TimeStatField
type IdleTimeStatField = TimeStatField

func NewDurationStatField() *DurationStatField {
	f := new(DurationStatField)
	f.Header.Class = XSC_OPENFLOW_BASIC
	f.Header.Field = XST_OFB_DURATION
	return f
}

func NewIdleTimeStatField() *IdleTimeStatField {
	f := new(IdleTimeStatField)
	f.Header.Class = XSC_OPENFLOW_BASIC
	f.Header.Field = XST_OFB_IDLE_TIME
	return f
}

// type XST_OFB_FLOW_COUNT
type FlowCountStatField struct {
	Header OXSStatHeader
	Count  uint32
}

func (f *FlowCountStatField) Len() (n uint16) {
	n = f.Header.Len()
	n += 4
	return
}

func (f *FlowCountStatField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(f.Len()))
	n := 0
	var b []byte
	f.Header.Length = 4
	b, err = f.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint32(data[n:], f.Count)
	n += 4
	return
}

func (f *FlowCountStatField) UnmarshalBinary(data []byte) (err error) {
	err = f.Header.UnmarshalBinary(data)
	if err != nil {
		return
	}
	n := f.Header.Len()

	f.Count = binary.BigEndian.Uint32(data[n:])
	n += 4
	return
}

func NewFlowCountStatField() *FlowCountStatField {
	f := new(FlowCountStatField)
	f.Header.Class = XSC_OPENFLOW_BASIC
	f.Header.Field = XST_OFB_FLOW_COUNT
	return f
}

// type XST_OFB_PACKET_COUNT or XST_OFB_BYTE_COUNT
type PBCountStatField struct {
	Header OXSStatHeader
	Count  uint64
}

func (f *PBCountStatField) Len() (n uint16) {
	n = f.Header.Len()
	n += 8
	return
}

func (f *PBCountStatField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(f.Len()))
	n := 0
	var b []byte
	f.Header.Length = 8
	b, err = f.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint64(data[n:], f.Count)
	n += 8
	return
}

func (f *PBCountStatField) UnmarshalBinary(data []byte) (err error) {
	err = f.Header.UnmarshalBinary(data)
	if err != nil {
		return
	}
	n := f.Header.Len()

	f.Count = binary.BigEndian.Uint64(data[n:])
	n += 8
	return
}

type PacketCountStatField = PBCountStatField
type ByteCountStatField = PBCountStatField

func NewPacketCountStatField() *PacketCountStatField {
	f := new(PacketCountStatField)
	f.Header.Class = XSC_OPENFLOW_BASIC
	f.Header.Field = XST_OFB_PACKET_COUNT
	return f
}

func NewByteCountStatField() *ByteCountStatField {
	f := new(ByteCountStatField)
	f.Header.Class = XSC_OPENFLOW_BASIC
	f.Header.Field = XST_OFB_BYTE_COUNT
	return f
}
