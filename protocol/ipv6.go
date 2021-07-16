package protocol

import (
	"encoding/binary"
	"errors"
	"net"

	"antrea.io/libOpenflow/util"
)

const (
	Type_HBH      = 0x0
	Type_Routing  = 0x2b
	Type_Fragment = 0x2c
)

type IPv6 struct {
	Version        uint8 //4-bits
	TrafficClass   uint8
	FlowLabel      uint32 //20-bits
	Length         uint16
	NextHeader     uint8
	HopLimit       uint8
	NWSrc          net.IP
	NWDst          net.IP
	HbhHeader      *HopByHopHeader
	RoutingHeader  *RoutingHeader
	FragmentHeader *FragmentHeader
	Data           util.Message
}

func (i *IPv6) Len() (n uint16) {
	length := uint16(40)
	if i.HbhHeader != nil {
		length += i.HbhHeader.Len()
	}
	if i.RoutingHeader != nil {
		length += i.RoutingHeader.Len()
	}
	if i.FragmentHeader != nil {
		length += i.FragmentHeader.Len()
	}
	length += i.Data.Len()
	return length
}

func (i *IPv6) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(i.Len()))
	var b []byte
	n := 0

	ihl := (i.Version << 4) | (i.TrafficClass>>4)&0x0f
	data[n] = ihl
	n += 1
	data[n] = (i.TrafficClass<<4)&0xf0 | uint8(i.FlowLabel>>16)
	n += 1
	binary.BigEndian.PutUint16(data[n:], uint16(i.FlowLabel))
	n += 2
	binary.BigEndian.PutUint16(data[n:], i.Length)
	n += 2
	data[n] = i.NextHeader
	n += 1
	data[n] = i.HopLimit
	n += 1
	copy(data[n:], i.NWSrc)
	n += 16
	copy(data[n:], i.NWDst)
	n += 16

	checkExtHeader := true
	nxtHeader := i.NextHeader
	for checkExtHeader {
		var err error
		var hBytes []byte
		switch nxtHeader {
		case Type_HBH:
			checkExtHeader = true
			nxtHeader = i.HbhHeader.NextHeader
			hBytes, err = i.HbhHeader.MarshalBinary()
		case Type_Routing:
			checkExtHeader = true
			nxtHeader = i.RoutingHeader.NextHeader
			hBytes, err = i.RoutingHeader.MarshalBinary()
		case Type_Fragment:
			checkExtHeader = true
			nxtHeader = i.FragmentHeader.NextHeader
			hBytes, err = i.FragmentHeader.MarshalBinary()
		default:
			checkExtHeader = false
			break
		}
		if err != nil {
			return nil, err
		}
		copy(data[n:], hBytes)
		n += len(hBytes)
	}

	if i.Data != nil {
		if b, err = i.Data.MarshalBinary(); err != nil {
			return
		}
		copy(data[n:], b)
		n += len(b)
	}
	return
}

func (i *IPv6) UnmarshalBinary(data []byte) error {
	if len(data) < 40 {
		return errors.New("The []byte is too short to unmarshal a full IPv6 message.")
	}
	n := 0

	var ihl uint8
	ihl = data[n]
	i.Version = ihl >> 4
	tcLeft := (ihl & 0x0f) << 4
	n += 1
	tc := data[n]
	i.TrafficClass = tcLeft | (tc >> 4)
	n += 1
	i.FlowLabel = binary.BigEndian.Uint32(data[0:4]) & 0x000FFFFF
	n += 2
	i.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	i.NextHeader = data[n]
	n += 1
	i.HopLimit = data[n]
	n += 1
	i.NWSrc = data[n : n+16]
	n += 16
	i.NWDst = data[n : n+16]
	n += 16

	checkExtHeader := true
	nxtHeader := i.NextHeader
checkXHeader:
	for checkExtHeader {
		switch nxtHeader {
		case Type_HBH:
			checkExtHeader = true
			i.HbhHeader = NewHopByHopHeader()
			err := i.HbhHeader.UnmarshalBinary(data[n:])
			if err != nil {
				return err
			}
			nxtHeader = i.HbhHeader.NextHeader
			n += int(i.HbhHeader.Len())
		case Type_Routing:
			checkExtHeader = true
			i.RoutingHeader = NewRoutingHeader()
			err := i.RoutingHeader.UnmarshalBinary(data[n:])
			if err != nil {
				return err
			}
			nxtHeader = i.RoutingHeader.NextHeader
			n += int(i.RoutingHeader.Len())
		case Type_Fragment:
			checkExtHeader = true
			i.FragmentHeader = NewFragmentHeader()
			err := i.FragmentHeader.UnmarshalBinary(data[n:])
			if err != nil {
				return err
			}
			nxtHeader = i.FragmentHeader.NextHeader
			n += int(i.FragmentHeader.Len())
		case Type_IPv6ICMP:
			i.Data = NewICMP()
			break checkXHeader
		case Type_UDP:
			i.Data = NewUDP()
			break checkXHeader
		default:
			i.Data = new(util.Buffer)
			break checkXHeader
		}
	}
	return i.Data.UnmarshalBinary(data[n:])
}

type Option struct {
	Type   uint8
	Length uint8
	Data   []byte
}

func (o *Option) Len() uint16 {
	return uint16(o.Length + 2)
}

func (o *Option) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(o.Len()))
	n := 0
	data[n] = o.Type
	n += 1
	data[n] = o.Length
	n += 1
	copy(data[n:], o.Data)
	return data, nil
}

func (o *Option) UnmarshalBinary(data []byte) error {
	n := 0
	o.Type = data[n]
	n += 1
	o.Length = data[n]
	n += 1
	if (len(data) - 2) < int(o.Length) {
		return errors.New("The []byte is too short to unmarshal a full Option message.")
	}
	o.Data = make([]byte, o.Length)
	copy(o.Data, data[n:n+int(o.Length)])
	return nil
}

type HopByHopHeader struct {
	NextHeader uint8
	HEL        uint8
	Options    []*Option
}

func (h *HopByHopHeader) Len() uint16 {
	return 8 * uint16(h.HEL+1)
}

func (h *HopByHopHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(h.Len()))
	n := 0
	data[n] = h.NextHeader
	n += 1
	data[n] = h.HEL
	n += 1
	for _, o := range h.Options {
		ob, err := o.MarshalBinary()
		if err != nil {
			return data, err
		}
		copy(data[n:], ob)
		n += int(o.Len())
	}
	return data, nil
}

func (h *HopByHopHeader) UnmarshalBinary(data []byte) error {
	n := 0
	h.NextHeader = data[n]
	n += 1
	h.HEL = data[n]
	if len(data) < 8*int(h.HEL+1) {
		return errors.New("The []byte is too short to unmarshal a full HopByHopHeader message.")
	}
	n += 1
	for n < int(h.Len()) {
		o := new(Option)
		err := o.UnmarshalBinary(data[n:])
		if err != nil {
			return err
		}
		n += int(o.Len())
		h.Options = append(h.Options, o)
	}
	return nil
}

func NewHopByHopHeader() *HopByHopHeader {
	return new(HopByHopHeader)
}

type RoutingHeader struct {
	NextHeader   uint8
	HEL          uint8
	RoutingType  uint8
	SegmentsLeft uint8
	Data         *util.Buffer
}

func (h *RoutingHeader) Len() uint16 {
	return 8 * uint16(h.HEL+1)
}

func (h *RoutingHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(h.Len()))
	n := 0
	data[n] = h.NextHeader
	n += 1
	data[n] = h.HEL
	n += 1
	data[n] = h.RoutingType
	n += 1
	data[n] = h.SegmentsLeft
	n += 1
	copy(data[n:], h.Data.Bytes())
	return data, nil
}

func (h *RoutingHeader) UnmarshalBinary(data []byte) error {
	n := 0
	h.NextHeader = data[n]
	n += 1
	h.HEL = data[n]
	if len(data) < 8*int(h.HEL+1) {
		return errors.New("The []byte is too short to unmarshal a full RoutingHeader message.")
	}
	n += 1
	h.RoutingType = data[n]
	n += 1
	h.SegmentsLeft = data[n]
	n += 1
	h.Data = new(util.Buffer)
	err := h.Data.UnmarshalBinary(data[n:h.Len()])
	if err != nil {
		return err
	}
	return nil
}

func NewRoutingHeader() *RoutingHeader {
	return new(RoutingHeader)
}

type FragmentHeader struct {
	NextHeader     uint8
	Reserved       uint8
	FragmentOffset uint16
	MoreFragments  bool
	Identification uint32
}

func (h *FragmentHeader) Len() uint16 {
	return uint16(8)
}

func (h *FragmentHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(h.Len()))
	n := 0
	data[n] = h.NextHeader
	n += 1
	data[n] = h.Reserved
	n += 1
	fragment := h.FragmentOffset << 3
	if h.MoreFragments {
		fragment |= uint16(1)
	}
	binary.BigEndian.PutUint16(data[n:], fragment)
	n += 2
	binary.BigEndian.PutUint32(data[n:], h.Identification)
	return data, nil
}

func (h *FragmentHeader) UnmarshalBinary(data []byte) error {
	if len(data) < int(h.Len()) {
		return errors.New("The []byte is too short to unmarshal a full FragmentHeader message.")
	}
	n := 0
	h.NextHeader = data[n]
	n += 1
	h.Reserved = data[n]
	n += 1
	fragment := binary.BigEndian.Uint16(data[n:])
	n += 2
	h.FragmentOffset = fragment >> 3
	h.MoreFragments = (fragment & uint16(1)) == uint16(1)
	h.Identification = binary.BigEndian.Uint32(data[n:])
	n += 4
	return nil
}

func NewFragmentHeader() *FragmentHeader {
	return new(FragmentHeader)
}
