package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	IGMPQuery        = 0x11
	IGMPv1Report     = 0x12
	IGMPv2Report     = 0x16
	IGMPv2LeaveGroup = 0x17
	IGMPv3Report     = 0x22

	IGMPIsIn  = 0x01 // Type MODE_IS_INCLUDE, source addresses x
	IGMPIsEx  = 0x02 // Type MODE_IS_EXCLUDE, source addresses x
	IGMPToIn  = 0x03 // Type CHANGE_TO_INCLUDE_MODE, source addresses x
	IGMPToEx  = 0x04 // Type CHANGE_TO_EXCLUDE_MODE, source addresses x
	IGMPAllow = 0x05 // Type ALLOW_NEW_SOURCES, source addresses x
	IGMPBlock = 0x06 // Type BLOCK_OLD_SOURCES, source addresses x
)

type IGMPMessage interface {
	GetMessageType() uint8
}

// IGMPv1:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version| Type  |    Unused     |           Checksum            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Group Address                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// IGMPv2:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      Type     | Max Resp Time |           Checksum            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Group Address                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IGMPv1or2 struct {
	Type            uint8
	MaxResponseTime uint8 // It is 0 for IGMPv1 message.
	Checksum        uint16
	GroupAddress    net.IP
}

func (p *IGMPv1or2) Len() uint16 {
	return 8
}

func (p *IGMPv1or2) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	n := 0
	data[n] = p.Type
	n += 1
	data[n] = p.MaxResponseTime
	n += 1
	binary.BigEndian.PutUint16(data[n:], p.Checksum)
	n += 2
	copy(data[n:n+4], p.GroupAddress.To4())
	return
}

func (p *IGMPv1or2) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.New("The []byte is too short to unmarshal a full IGMPv1or2 message.")
	}
	p.Type = data[0]
	p.MaxResponseTime = data[1]
	p.Checksum = binary.BigEndian.Uint16(data[2:4])
	p.GroupAddress = data[4:8]
	return nil
}

func (p *IGMPv1or2) GetMessageType() uint8 {
	return p.Type
}

func NewIGMPv1Query(group net.IP) *IGMPv1or2 {
	return &IGMPv1or2{Type: IGMPQuery, GroupAddress: group}
}

func NewIGMPv1Report(group net.IP) *IGMPv1or2 {
	return &IGMPv1or2{Type: IGMPv1Report, GroupAddress: group}
}

func NewIGMPv2Query(group net.IP, maxResponseTime uint8) *IGMPv1or2 {
	return &IGMPv1or2{
		Type:            IGMPQuery,
		MaxResponseTime: maxResponseTime,
		GroupAddress:    group,
	}
}

func NewIGMPv2Report(group net.IP) *IGMPv1or2 {
	return &IGMPv1or2{
		Type:         IGMPv2Report,
		GroupAddress: group,
	}
}

func NewIGMPv2Leave(group net.IP) *IGMPv1or2 {
	return &IGMPv1or2{
		Type:         IGMPv2LeaveGroup,
		GroupAddress: group,
	}
}

// IGMPv3Query:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Type = 0x11  | Max Resp Code |           Checksum            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Group Address                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address [1]                      |
//   +-                                                             -+
//   |                       Source Address [2]                      |
//   +-                              .                              -+
//   .                               .                               .
//   .                               .                               .
//   +-                                                             -+
//   |                       Source Address [N]                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IGMPv3Query struct {
	Type                     uint8
	MaxResponseTime          uint8
	Checksum                 uint16
	GroupAddress             net.IP
	Reserved                 uint8
	SuppressRouterProcessing bool
	RobustnessValue          uint8
	IntervalTime             uint8
	NumberOfSources          uint16
	SourceAddresses          []net.IP
}

func (p *IGMPv3Query) Len() uint16 {
	return 12 + p.NumberOfSources*4
}

func (p *IGMPv3Query) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	n := 0
	data[n] = p.Type
	n += 1
	data[n] = p.MaxResponseTime
	n += 1
	binary.BigEndian.PutUint16(data[n:], p.Checksum)
	n += 2
	copy(data[n:n+4], p.GroupAddress[12:16])
	n += 4
	sBit := uint8(0x0)
	if p.SuppressRouterProcessing {
		sBit = 0x8
	}
	data[n] = sBit | p.RobustnessValue&0x7
	n += 1
	data[n] = p.IntervalTime
	n += 1
	binary.BigEndian.PutUint16(data[n:], p.NumberOfSources)
	n += 2
	for _, src := range p.SourceAddresses {
		copy(data[n:n+4], src.To4())
		n += 4
	}
	return
}

func (p *IGMPv3Query) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return errors.New("The []byte is too short to unmarshal a full IGMPv3Query message.")
	}
	n := 0
	p.Type = data[n]
	n += 1
	p.MaxResponseTime = data[n]
	n += 1
	p.Checksum = binary.BigEndian.Uint16(data[n:])
	n += 2
	p.GroupAddress = data[n : n+4]
	n += 4
	p.SuppressRouterProcessing = data[n]&0x8 != 0
	p.RobustnessValue = data[n] & 0x7
	n += 1
	p.IntervalTime = data[n]
	n += 1
	p.NumberOfSources = binary.BigEndian.Uint16(data[n:])
	n += 2
	if len(data) < int(p.Len()) {
		return fmt.Errorf("The []byte is too short to unmarshal a full IGMPv3Query message.")
	}
	for j := 0; j < int(p.NumberOfSources); j++ {
		p.SourceAddresses = append(p.SourceAddresses, data[n:n+4])
		n += 4
	}
	return nil
}

func (p *IGMPv3Query) GetMessageType() uint8 {
	return IGMPQuery
}

func NewIGMPv3Query(group net.IP, maxResponseTime uint8, queryInterval uint8, sources []net.IP) *IGMPv3Query {
	return &IGMPv3Query{
		Type:            IGMPQuery,
		MaxResponseTime: maxResponseTime,
		GroupAddress:    group,
		IntervalTime:    queryInterval,
		NumberOfSources: uint16(len(sources)),
		SourceAddresses: sources,
	}
}

// IGMPv3GroupRecord:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Multicast Address                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address [1]                      |
//   +-                                                             -+
//   |                       Source Address [2]                      |
//   +-                                                             -+
//   .                               .                               .
//   .                               .                               .
//   .                               .                               .
//   +-                                                             -+
//   |                       Source Address [N]                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   .                                                               .
//   .                         Auxiliary Data                        .
//   .                                                               .
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IGMPv3GroupRecord struct {
	Type             uint8
	AuxDataLen       uint8 // this should always be 0 as per IGMPv3 spec.
	NumberOfSources  uint16
	MulticastAddress net.IP
	SourceAddresses  []net.IP
	AuxData          []uint32 // NOT USED
}

func (p *IGMPv3GroupRecord) Len() uint16 {
	return 8 + uint16(p.AuxDataLen)*4 + p.NumberOfSources*4
}

func (p *IGMPv3GroupRecord) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	n := 0
	data[n] = p.Type
	n += 1
	data[n] = p.AuxDataLen
	n += 1
	binary.BigEndian.PutUint16(data[n:], p.NumberOfSources)
	n += 2
	copy(data[n:n+4], p.MulticastAddress.To4())
	n += 4
	for _, src := range p.SourceAddresses {
		copy(data[n:n+4], src.To4())
		n += 4
	}
	for _, d := range p.AuxData {
		binary.BigEndian.PutUint32(data[n:], d)
		n += 4
	}
	return
}

func (p *IGMPv3GroupRecord) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.New("The []byte is too short to unmarshal a full IGMPv3GroupRecord message.")
	}
	n := 0
	p.Type = data[n]
	n += 1
	p.AuxDataLen = data[n]
	n += 1
	p.NumberOfSources = binary.BigEndian.Uint16(data[n:])
	n += 2
	p.MulticastAddress = data[n : n+4]
	n += 4
	if len(data) < int(p.Len()) {
		return fmt.Errorf("The []byte is too short to unmarshal a full IGMPv3GroupRecord message.")
	}
	for i := uint16(0); i < p.NumberOfSources; i++ {
		p.SourceAddresses = append(p.SourceAddresses, data[n:n+4])
		n += 4
	}
	for i := uint8(0); i < p.AuxDataLen; i++ {
		p.AuxData = append(p.AuxData, binary.BigEndian.Uint32(data[n:]))
		n += 4
	}
	return nil
}

func NewGroupRecord(recordType uint8, group net.IP, sources []net.IP) IGMPv3GroupRecord {
	return IGMPv3GroupRecord{
		Type:             recordType,
		MulticastAddress: group,
		NumberOfSources:  uint16(len(sources)),
		SourceAddresses:  sources,
	}
}

// IGMPv3MembershipReport:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Type = 0x22  |    Reserved   |           Checksum            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |           Reserved            |  Number of Group Records (M)  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   .                                                               .
//   .                        Group Record [1]                       .
//   .                                                               .
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   .                                                               .
//   .                        Group Record [2]                       .
//   .                                                               .
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                               .                               |
//   .                               .                               .
//   |                               .                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   .                                                               .
//   .                        Group Record [M]                       .
//   .                                                               .
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IGMPv3MembershipReport struct {
	Type           uint8
	Reserved       uint8
	Checksum       uint16
	Reserved2      uint16
	NumberOfGroups uint16
	GroupRecords   []IGMPv3GroupRecord
}

func (p *IGMPv3MembershipReport) Len() uint16 {
	length := uint16(8)
	for _, r := range p.GroupRecords {
		length += r.Len()
	}
	return length
}

func (p *IGMPv3MembershipReport) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	n := 0
	data[n] = p.Type
	n += 1
	// Length for field "Reserved"
	n += 1
	binary.BigEndian.PutUint16(data[n:], p.Checksum)
	n += 2
	// Length for field "Reserved2".
	n += 2
	binary.BigEndian.PutUint16(data[n:], p.NumberOfGroups)
	n += 2
	for _, r := range p.GroupRecords {
		b, err := r.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(r.Len())
	}
	return
}

func (p *IGMPv3MembershipReport) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.New("The []byte is too short to unmarshal a full IGMPv3MembershipReport message.")
	}
	n := 0
	p.Type = data[n]
	n += 1
	// Length for field "Reserved"
	n += 1
	p.Checksum = binary.BigEndian.Uint16(data[n:])
	n += 2
	// Length for field "Reserved2".
	n += 2
	p.NumberOfGroups = binary.BigEndian.Uint16(data[n:])
	n += 2
	for i := uint16(0); i < p.NumberOfGroups; i++ {
		gr := new(IGMPv3GroupRecord)
		if err := gr.UnmarshalBinary(data[n:]); err != nil {
			return err
		}
		p.GroupRecords = append(p.GroupRecords, *gr)
		n += int(gr.Len())
	}
	return nil
}

func (p *IGMPv3MembershipReport) GetMessageType() uint8 {
	return IGMPv3Report
}

func NewIGMPv3Report(groups []IGMPv3GroupRecord) *IGMPv3MembershipReport {
	return &IGMPv3MembershipReport{
		Type:           IGMPv3Report,
		NumberOfGroups: uint16(len(groups)),
		GroupRecords:   groups,
	}
}
