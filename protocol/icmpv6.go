package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"antrea.io/libOpenflow/util"
)

const (
	ICMPv6_Type_EchoRequest  = 128
	ICMPv6_Type_EchoReply    = 129
	ICMPv6_Type_MLD_Query    = 130
	ICMPv6_Type_MLDv2_Report = 143
	ICMPv6_Type_MLD_Report   = 131
	ICMPv6_Type_MLD_Done     = 132

	ICMPv6_ErrType_Destination_Unreachable = 1
	ICMPv6_ErrType_Packet_Large            = 2
	ICMPv6_ErrType_Timeout                 = 3
	ICMPv6_ErrType_Parameter               = 4

	// Code for ICMPv6 Error: Destination Unreachable
	ICMPv6_ErrCode_NoRoute         = 0
	ICMPv6_ErrCode_AdminProhibited = 1
	ICMPv6_ErrCode_BeyondOfSource  = 2
	ICMPv6_ErrCode_AddrUnreachable = 3
	ICMPv6_ErrCode_PortUnreachable = 4
	ICMPv6_ErrCode_SourcePolicy    = 5
	ICMPv6_ErrCode_Reject          = 6

	// Code for ICMPv6 Error: Timeout
	ICMPv6_ErrCode_TTL              = 0
	ICMPv6_ErrCode_Fragment_Timeout = 1

	// Code for ICMPv6 Error: Parameter
	ICMPv6_ErrCode_Err_Header     = 0
	ICMPv6_ErrCode_Unknown_Header = 1
	ICMPv6_ErrCode_Unknown_Option = 2
)

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |     Type      |     Code      |          Checksum             |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                         Message Body                          +
//      |                                                               |
type ICMPv6Header struct {
	Type     uint8
	Code     uint8
	Checksum uint16
}

func (i *ICMPv6Header) Len() uint16 {
	return 4
}

func (i *ICMPv6Header) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(i.Len()))
	data[0] = i.Type
	data[1] = i.Code
	binary.BigEndian.PutUint16(data[2:4], i.Checksum)
	return
}

func (i *ICMPv6Header) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("The []byte is too short to unmarshal a full ICMPv6Header message.")
	}
	i.Type = data[0]
	i.Code = data[1]
	i.Checksum = binary.BigEndian.Uint16(data[2:4])
	return nil
}

type ICMPv6EchoReqRpl struct {
	ICMPv6Header
	Identifier uint16
	SeqNum     uint16
	Data       util.Message
}

func (i *ICMPv6EchoReqRpl) Len() (n uint16) {
	n = uint16(8)
	if i.Data != nil {
		n += i.Data.Len()
	}
	return
}

func (i *ICMPv6EchoReqRpl) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(i.Len()))
	n := 0
	b, err := i.ICMPv6Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], i.Identifier)
	n += 2
	binary.BigEndian.PutUint16(data[n:], i.SeqNum)
	n += 2
	dataBytes, err := i.Data.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], dataBytes)
	return data, nil
}

func (i *ICMPv6EchoReqRpl) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("The []byte is too short to unmarshal a full ICMPv6Header message.")
	}
	err := i.ICMPv6Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	if len(data) < 8 {
		return errors.New("The []byte is too short to unmarshal a full ICMPv6EchoReqRpl message.")
	}
	n := i.ICMPv6Header.Len()
	i.Identifier = binary.BigEndian.Uint16(data[n:])
	n += 2
	i.SeqNum = binary.BigEndian.Uint16(data[n:])
	n += 2
	i.Data = new(util.Buffer)
	err = i.Data.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	return nil
}

func NewICMPv6EchoRequest(identifier, sequenceNumber uint16) *ICMPv6EchoReqRpl {
	return &ICMPv6EchoReqRpl{
		ICMPv6Header: ICMPv6Header{
			Type: ICMPv6_Type_EchoRequest,
			Code: 0,
		},
		Identifier: identifier,
		SeqNum:     sequenceNumber,
	}
}

func NewICMPv6EchoReply(identifier, sequenceNumber uint16) *ICMPv6EchoReqRpl {
	return &ICMPv6EchoReqRpl{
		ICMPv6Header: ICMPv6Header{
			Type: ICMPv6_Type_EchoReply,
			Code: 0,
		},
		Identifier: identifier,
		SeqNum:     sequenceNumber,
	}
}

type ICMPv6Error ICMPv6Header

//     0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Type      |     Code      |          Checksum             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Maximum Response Delay    |          Reserved             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                       Multicast Address                       +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLD struct {
	ICMPv6Header
	MaxResponse      uint16
	Reserved         uint16
	MulticastAddress net.IP
}

func (m *MLD) Len() uint16 {
	return 24
}

func (m *MLD) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(m.Len()))
	n := 0
	b, err := m.ICMPv6Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], m.MaxResponse)
	n += 2
	n += 2
	copy(data[n:], m.MulticastAddress)
	return data, nil
}

func (m *MLD) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("The []byte is too short to unmarshal a full ICMPv6Header message.")
	}
	err := m.ICMPv6Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	if len(data) < int(m.Len()) {
		return errors.New("The []byte is too short to unmarshal a full MLD message.")
	}
	n := m.ICMPv6Header.Len()
	m.MaxResponse = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2
	m.MulticastAddress = data[n : n+16]
	return nil
}

func NewMLDReport(multicastIP net.IP) *MLD {
	return &MLD{
		ICMPv6Header: ICMPv6Header{
			Type: ICMPv6_Type_MLD_Report,
			Code: 0,
		},
		MulticastAddress: multicastIP,
	}
}

func NewMLDDone(multicastIP net.IP) *MLD {
	return &MLD{
		ICMPv6Header: ICMPv6Header{
			Type: ICMPv6_Type_MLD_Done,
			Code: 0,
		},
		MulticastAddress: multicastIP,
	}
}

//      0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Type = 130   |      Code     |           Checksum            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |    Maximum Response Code      |           Reserved            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    *                       Multicast Address                       *
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    *                       Source Address [1]                      *
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    +-                                                             -+
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    *                       Source Address [2]                      *
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    +-                              .                              -+
//    .                               .                               .
//    .                               .                               .
//    +-                                                             -+
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    *                       Source Address [N]                      *
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLDQuery struct {
	ICMPv6Header
	MaxResponse              uint16
	Reserved                 uint16
	MulticastAddress         net.IP
	Version2                 bool
	Reserved2                uint8
	SuppressRouterProcessing bool
	RobustnessValue          uint8
	IntervalTime             uint8
	NumberOfSources          uint16
	SourceAddresses          []net.IP
}

func (q *MLDQuery) Len() uint16 {
	if !q.Version2 {
		return 28
	}
	return 28 + q.NumberOfSources*16
}

func (q *MLDQuery) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(q.Len()))
	n := 0
	b, err := q.ICMPv6Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], q.MaxResponse)
	n += 2
	n += 2
	copy(data[n:], q.MulticastAddress)
	n += 16
	if q.Version2 {
		sBit := uint8(0x0)
		if q.SuppressRouterProcessing {
			sBit = 0x8
		}
		data[n] = sBit | q.RobustnessValue&0x7
		n += 1
		data[n] = q.IntervalTime
		n += 1
		binary.BigEndian.PutUint16(data[n:], q.NumberOfSources)
		n += 2
		for _, src := range q.SourceAddresses {
			copy(data[n:], src.To16())
			n += 16
		}
	}
	return data, nil
}

func (q *MLDQuery) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("The []byte is too short to unmarshal a full ICMPv6Header message.")
	}
	err := q.ICMPv6Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	n := q.ICMPv6Header.Len()
	if len(data) < 28 {
		return fmt.Errorf("The []byte is too short to unmarshal a full MLDQuery message.")
	}
	q.MaxResponse = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2
	q.MulticastAddress = data[n : n+16]
	n += 16
	q.Version2 = len(data) > 28
	if q.Version2 {
		q.SuppressRouterProcessing = data[n]&0x8 != 0
		q.RobustnessValue = data[n] & 0x7
		n += 1
		q.IntervalTime = data[n]
		n += 1
		q.NumberOfSources = binary.BigEndian.Uint16(data[n:])
		n += 2
		if len(data) < int(q.Len()) {
			return fmt.Errorf("The []byte is too short to unmarshal a full MLDv2 Query message.")
		}
		for j := 0; j < int(q.NumberOfSources); j++ {
			q.SourceAddresses = append(q.SourceAddresses, data[n:n+16])
			n += 16
		}
	}
	return nil
}

func NewMLDQuery(maxResponse uint16, multicastIP net.IP) *MLDQuery {
	return &MLDQuery{
		ICMPv6Header: ICMPv6Header{
			Type: ICMPv6_Type_MLD_Query,
			Code: 0,
		},
		MaxResponse:      maxResponse,
		MulticastAddress: multicastIP,
		Version2:         false,
	}
}

func NewMLDv2Query(maxResponse uint16, multicastIP net.IP, queryInterval uint8, sources []net.IP) *MLDQuery {
	return &MLDQuery{
		ICMPv6Header: ICMPv6Header{
			Type: ICMPv6_Type_MLD_Query,
			Code: 0,
		},
		MaxResponse:      maxResponse,
		MulticastAddress: multicastIP,
		Version2:         true,
		IntervalTime:     queryInterval,
		NumberOfSources:  uint16(len(sources)),
		SourceAddresses:  sources,
	}
}

//      0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Type = 143   |    Reserved   |           Checksum            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |           Reserved            |Nr of Mcast Address Records (M)|
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    .                                                               .
//    .                  Multicast Address Record [1]                 .
//    .                                                               .
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    .                                                               .
//    .                  Multicast Address Record [2]                 .
//    .                                                               .
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                               .                               |
//    .                               .                               .
//    |                               .                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    .                                                               .
//    .                  Multicast Address Record [M]                 .
//    .                                                               .
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLDv2Report struct {
	ICMPv6Header
	Reserved2       uint16
	NumberOfRecords uint16
	GroupRecords    []MLDv2Record
}

func (r *MLDv2Report) Len() (n uint16) {
	n = uint16(8)
	for _, gr := range r.GroupRecords {
		n += gr.Len()
	}
	return
}

func (r *MLDv2Report) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(r.Len()))
	n := 0
	b, err := r.ICMPv6Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += len(b)
	// Length for field "Reserved2"
	n += 2
	binary.BigEndian.PutUint16(data[n:], r.NumberOfRecords)
	n += 2
	for _, gr := range r.GroupRecords {
		b, err := gr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(gr.Len())
	}
	return
}

func (r *MLDv2Report) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("The []byte is too short to unmarshal a full ICMPv6Header message.")
	}
	err := r.ICMPv6Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	n := r.ICMPv6Header.Len()
	// Length for field "Reserved2".
	n += 2
	r.NumberOfRecords = binary.BigEndian.Uint16(data[n:])
	n += 2
	for i := uint16(0); i < r.NumberOfRecords; i++ {
		record := new(MLDv2Record)
		if err := record.UnmarshalBinary(data[n:]); err != nil {
			return err
		}
		r.GroupRecords = append(r.GroupRecords, *record)
		n += record.Len()
	}
	return nil
}

func NewMLDv2Report(records []MLDv2Record) *MLDv2Report {
	return &MLDv2Report{
		ICMPv6Header: ICMPv6Header{
			Type: ICMPv6_Type_MLDv2_Report,
			Code: 0,
		},
		NumberOfRecords: uint16(len(records)),
		GroupRecords:    records,
	}
}

//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    *                       Multicast Address                       *
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    *                       Source Address [1]                      *
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    +-                                                             -+
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    *                       Source Address [2]                      *
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    +-                                                             -+
//    .                               .                               .
//    .                               .                               .
//    .                               .                               .
//    +-                                                             -+
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    *                       Source Address [N]                      *
//    |                                                               |
//    *                                                               *
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                                                               |
//    .                                                               .
//    .                         Auxiliary Data                        .
//    .                                                               .
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLDv2Record struct {
	Type             uint8
	AuxDataLen       uint8 // this may be 0 to indicate the absence of any auxiliary data.
	NumberOfSources  uint16
	MulticastAddress net.IP
	SourceAddresses  []net.IP
	AuxData          []uint32 // NOT USED
}

func (r *MLDv2Record) Len() uint16 {
	return 20 + uint16(r.AuxDataLen)*4 + r.NumberOfSources*16
}

func (r *MLDv2Record) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(r.Len()))
	n := 0
	data[n] = r.Type
	n += 1
	data[n] = r.AuxDataLen
	n += 1
	binary.BigEndian.PutUint16(data[n:], r.NumberOfSources)
	n += 2
	copy(data[n:], r.MulticastAddress.To16())
	n += 16
	for _, src := range r.SourceAddresses {
		copy(data[n:], src.To16())
		n += 16
	}
	for _, d := range r.AuxData {
		binary.BigEndian.PutUint32(data[n:], d)
		n += 4
	}
	return
}

func (r *MLDv2Record) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.New("The []byte is too short to unmarshal a full MLDv2Record message.")
	}
	n := 0
	r.Type = data[n]
	n += 1
	r.AuxDataLen = data[n]
	n += 1
	r.NumberOfSources = binary.BigEndian.Uint16(data[n:])
	n += 2
	r.MulticastAddress = data[n : n+16]
	n += 16
	if len(data) < int(r.Len()) {
		return fmt.Errorf("The []byte is too short to unmarshal a full MLDv2Record message.")
	}
	for i := uint16(0); i < r.NumberOfSources; i++ {
		r.SourceAddresses = append(r.SourceAddresses, data[n:n+16])
		n += 16
	}
	for i := uint8(0); i < r.AuxDataLen; i++ {
		r.AuxData = append(r.AuxData, binary.BigEndian.Uint32(data[n:]))
		n += 4
	}
	return nil
}

func NewMLDv2Record(recordType uint8, group net.IP, sources []net.IP) *MLDv2Record {
	return &MLDv2Record{
		Type:             recordType,
		MulticastAddress: group,
		NumberOfSources:  uint16(len(sources)),
		SourceAddresses:  sources,
	}
}

func NewICMPv6ByHeaderType(packetType uint8) util.Message {
	switch packetType {
	case ICMPv6_Type_EchoRequest:
		fallthrough
	case ICMPv6_Type_EchoReply:
		return new(ICMPv6EchoReqRpl)
	case ICMPv6_Type_MLD_Query:
		return new(MLDQuery)
	// MLD Report and MLD Done are using the same message struct.
	case ICMPv6_Type_MLD_Report:
		fallthrough
	case ICMPv6_Type_MLD_Done:
		return new(MLD)
	case ICMPv6_Type_MLDv2_Report:
		return new(MLDv2Report)
	}
	return new(util.Buffer)
}
