package openflow13

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
)

const (
	NxExperimenterID     = 0x00002320 // Experimenter_ID for Nicira extension messages
	NxActionHeaderLength = 10         // Length of Nicira extension message header

	NXAST_RESUBMIT         = 1  // Nicira extended action: resubmit(port)
	NXAST_SET_TUNNEL       = 2  // Nicira extended action: set_tunnel
	NXAST_DROP_SPOOFED_ARP = 3  // Nicira extended action: drop spoofed arp packets
	NXAST_SET_QUEUE        = 4  // Nicira extended action: set_queue
	NXAST_POP_QUEUE        = 5  // Nicira extended action: pop_tunnel
	NXAST_REG_MOVE         = 6  // Nicira extended action: move:srcField[m1..n1]->dstField[m2..n2]
	NXAST_REG_LOAD         = 7  // Nicira extended action: load:data->dstField[m..n]
	NXAST_NOTE             = 8  // Nicira extended action: note
	NXAST_SET_TUNNEL_V6    = 9  // Nicira extended action: set_tunnel64
	NXAST_MULTIPATH        = 10 // Nicira extended action: set_tunnel
	NXAST_AUTOPATH         = 11 // Nicira extended action: multipath
	NXAST_BUNDLE           = 12 // Nicira extended action: bundle
	NXAST_BUNDLE_LOAD      = 13 // Nicira extended action: bundle_load
	NXAST_RESUBMIT_TABLE   = 14 // Nicira extended action: resubmit(port, table)
	NXAST_OUTPUT_REG       = 15 // Nicira extended action: output:field
	NXAST_LEARN            = 16 // Nicira extended action: learn
	NXAST_EXIT             = 17 // Nicira extended action: exit
	NXAST_DEC_TTL          = 18 // Nicira extended action: dec_ttl
	NXAST_FIN_TIMEOUT      = 19 // Nicira extended action: output:field
	NXAST_CONTROLLER       = 20 // Nicira extended action: fin_timeout
	NXAST_DEC_TTL_CNT_IDS  = 21 // Nicira extended action: dec_ttl(id1,[id2]...)
	NXAST_PUSH_MPLS        = 23 // Nicira extended action: push_mpls
	NXAST_POP_MPLS         = 24 // Nicira extended action: pop_mpls
	NXAST_SET_MPLS_TTL     = 25 // Nicira extended action: set_mpls_ttl
	NXAST_DEC_MPLS_TTL     = 26 // Nicira extended action: set_mpls_ttl
	NXAST_STACK_PUSH       = 27 // Nicira extended action: push:src
	NXAST_STACK_POP        = 28 // Nicira extended action: pop:dst
	NXAST_SAMPLE           = 29 // Nicira extended action: sample
	NXAST_SET_MPLS_LABEL   = 30 // Nicira extended action: set_mpls_label
	NXAST_SET_MPLS_TC      = 31 // Nicira extended action: set_mpls_tc
	NXAST_OUTPUT_REG2      = 32 // Nicira extended action: output(port=port,max_len)
	NXAST_REG_LOAD2        = 33 // Nicira extended action: load
	NXAST_CNJUNCTION       = 34 // Nicira extended action: conjunction
	NXAST_CT               = 35 // Nicira extended action: ct
	NXAST_NAT              = 36 // Nicira extended action: nat, need to be along with ct action
	NXAST_CONTROLLER2      = 37 // Nicira extended action: controller(userdata=xxx,pause)
	NXAST_SAMPLE2          = 38 // Nicira extended action: sample, support for exporting egress tunnel
	NXAST_OUTPUT_TRUNC     = 39 // Nicira extended action: truncate output action
	NXAST_CT_CLEAR         = 43 // Nicira extended action: ct_clear
	NXAST_CT_RESUBMIT      = 44 // Nicira extended action: resubmit to table in ct
	NXAST_RAW_ENCAP        = 46 // Nicira extended action: encap
	NXAST_RAW_DECAP        = 47 // Nicira extended action: decap
	NXAST_DEC_NSH_TTL      = 48 // Nicira extended action: dec_nsh_ttl
)

type NXActionHeader struct {
	*ActionHeader
	Vendor  uint32
	Subtype uint16
}

func (a *NXActionHeader) Header() *ActionHeader {
	return a.ActionHeader
}

func (a *NXActionHeader) NXHeader() *NXActionHeader {
	return a
}

func (a *NXActionHeader) Len() (n uint16) {
	return NxActionHeaderLength
}

func (a *NXActionHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	b := make([]byte, 0)
	n := 0

	b, err = a.ActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint32(data[n:], a.Vendor)
	n += 4
	binary.BigEndian.PutUint16(data[n:], a.Subtype)
	return
}

func (a *NXActionHeader) UnmarshalBinary(data []byte) error {
	if len(data) < int(NxActionHeaderLength) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionHeader message.")
	}
	a.ActionHeader = new(ActionHeader)
	n := 0
	err := a.ActionHeader.UnmarshalBinary(data[:4])
	n += 4
	a.Vendor = binary.BigEndian.Uint32(data[n:])
	n += 4
	a.Subtype = binary.BigEndian.Uint16(data[n:])
	return err
}

func NewNxActionHeader(subtype uint16) *NXActionHeader {
	actionHeader := &ActionHeader{Type: ActionType_Experimenter, Length: NxActionHeaderLength}
	return &NXActionHeader{ActionHeader: actionHeader, Vendor: NxExperimenterID, Subtype: subtype}
}

// nxast_conjunction
type NXActionConjunction struct {
	*NXActionHeader
	Clause  uint8
	NClause uint8
	ID      uint32
}

// conjunction(ID, Clause/nclause)
func NewNXActionConjunction(clause uint8, nclause uint8, id uint32) *NXActionConjunction {
	a := new(NXActionConjunction)
	a.NXActionHeader = NewNxActionHeader(NXAST_CNJUNCTION)
	a.Length = a.NXActionHeader.Len() + 6
	a.Clause = clause
	a.NClause = nclause
	a.ID = id
	return a
}

func (a *NXActionConjunction) Len() (n uint16) {
	return a.Length
}

func (a *NXActionConjunction) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	data[n] = a.Clause
	n += 1
	data[n] = a.NClause
	n += 1
	binary.BigEndian.PutUint32(data[n:], a.ID)
	n += 4

	return
}

func (a *NXActionConjunction) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionConjunction message")
	}
	a.Clause = uint8(data[n])
	n += 1
	a.NClause = uint8(data[n])
	n += 1
	a.ID = binary.BigEndian.Uint32(data[n:])

	return err
}

// nx_action_conntrack
type NXActionConnTrack struct {
	*NXActionHeader
	Flags        uint16
	ZoneSrc      uint32
	ZoneOfsNbits uint16
	RecircTable  uint8
	pad          []byte // 3bytes
	Alg          uint16
	actions      []Action
}

func (a *NXActionConnTrack) Len() (n uint16) {
	return a.Length
}

func (a *NXActionConnTrack) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Length))
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.Flags)
	n += 2
	binary.BigEndian.PutUint32(data[n:], a.ZoneSrc)
	n += 4
	binary.BigEndian.PutUint16(data[n:], a.ZoneOfsNbits)
	n += 2
	data[n] = a.RecircTable
	n += 1
	copy(data[n:], a.pad)
	n += 3
	binary.BigEndian.PutUint16(data[n:], a.Alg)
	n += 2
	// Marshal ct actions
	for _, action := range a.actions {
		actionBytes, err := action.MarshalBinary()
		if err != nil {
			return data, errors.New("failed to Marshal ct subActions")
		}
		copy(data[n:], actionBytes)
		n += len(actionBytes)
	}
	return
}

func (a *NXActionConnTrack) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionConnTrack message")
	}
	a.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.ZoneSrc = binary.BigEndian.Uint32(data[n:])
	n += 4
	a.ZoneOfsNbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.RecircTable = data[n]
	n += 1
	copy(a.pad, data[n:n+3])
	n += 3
	a.Alg = binary.BigEndian.Uint16(data[n:])
	n += 2

	for n < int(a.Len()) {
		act, err := DecodeAction(data[n:])
		if err != nil {
			return errors.New("failed to decode actions")
		}
		a.actions = append(a.actions, act)
		n += int(act.Len())
	}
	a.Length = uint16(n)
	return err
}

func (a *NXActionConnTrack) Commit() *NXActionConnTrack {
	a.Flags |= NX_CT_F_COMMIT
	return a
}

func (a *NXActionConnTrack) Force() *NXActionConnTrack {
	a.Flags |= NX_CT_F_FORCE
	return a
}

func (a *NXActionConnTrack) Table(tableID uint8) *NXActionConnTrack {
	a.RecircTable = tableID
	return a
}

func (a *NXActionConnTrack) ZoneImm(zoneID uint16) *NXActionConnTrack {
	a.ZoneSrc = 0
	a.ZoneOfsNbits = zoneID
	return a
}

func (a *NXActionConnTrack) ZoneRange(field *MatchField, rng *NXRange) *NXActionConnTrack {
	a.ZoneSrc = field.MarshalHeader()
	a.ZoneOfsNbits = rng.ToOfsBits()
	return a
}

func (a *NXActionConnTrack) AddAction(actions ...Action) *NXActionConnTrack {
	for _, act := range actions {
		a.actions = append(a.actions, act)
		a.Length += act.Len()
	}
	return a
}

func NewNXActionConnTrack() *NXActionConnTrack {
	a := new(NXActionConnTrack)
	a.NXActionHeader = NewNxActionHeader(NXAST_CT)
	a.Length = a.NXActionHeader.Len() + 14
	a.RecircTable = NX_CT_RECIRC_NONE
	return a
}

// nx_action_reg_load
type NXActionRegLoad struct {
	*NXActionHeader
	OfsNbits uint16
	DstReg   *MatchField
	Value    uint64
}

func NewNXActionRegLoad(ofsNbits uint16, dstField *MatchField, value uint64) *NXActionRegLoad {
	a := new(NXActionRegLoad)
	a.NXActionHeader = NewNxActionHeader(NXAST_REG_LOAD)
	a.Length = a.NXActionHeader.Len() + 14
	a.OfsNbits = ofsNbits
	a.DstReg = dstField
	a.Value = value
	return a
}

func (a *NXActionRegLoad) Len() (n uint16) {
	return a.Length
}

func (a *NXActionRegLoad) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.OfsNbits)
	n += 2
	fieldHeaderData := a.DstReg.MarshalHeader()
	binary.BigEndian.PutUint32(data[n:], fieldHeaderData)
	n += 4
	binary.BigEndian.PutUint64(data[n:], a.Value)
	n += 8

	return
}

func (a *NXActionRegLoad) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionRegLoad message")
	}
	a.OfsNbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.DstReg = new(MatchField)
	err = a.DstReg.UnmarshalHeader(data[n : n+4])
	n += 4
	a.Value = binary.BigEndian.Uint64(data[n:])
	return err
}

// nx_action_reg_move
type NXActionRegMove struct {
	*NXActionHeader
	Nbits    uint16
	SrcOfs   uint16
	DstOfs   uint16
	SrcField *MatchField
	DstField *MatchField
}

func NewNXActionRegMove(nBits uint16, srcOfs uint16, dstOfs uint16, srcField *MatchField, dstField *MatchField) *NXActionRegMove {
	a := new(NXActionRegMove)
	a.NXActionHeader = NewNxActionHeader(NXAST_REG_MOVE)
	a.Length = a.NXActionHeader.Len() + 14
	a.Nbits = nBits
	a.SrcOfs = srcOfs
	a.DstOfs = dstOfs
	a.SrcField = srcField
	a.DstField = dstField
	return a
}

func (a *NXActionRegMove) Len() (n uint16) {
	return a.Length
}

func (a *NXActionRegMove) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Length)
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.Nbits)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.SrcOfs)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.DstOfs)
	n += 2

	srcFieldHeaderData := a.SrcField.MarshalHeader()
	binary.BigEndian.PutUint32(data[n:], srcFieldHeaderData)
	n += 4

	dstFieldHeaderData := a.DstField.MarshalHeader()
	binary.BigEndian.PutUint32(data[n:], dstFieldHeaderData)
	n += 4
	return
}

func (a *NXActionRegMove) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionRegLoad message")
	}
	a.Nbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.SrcOfs = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.DstOfs = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.SrcField = new(MatchField)
	err = a.SrcField.UnmarshalHeader(data[n:])
	n += 4
	a.DstField = new(MatchField)
	err = a.DstField.UnmarshalHeader(data[n:])
	return err
}

type NXActionResubmit struct {
	*NXActionHeader
	InPort  uint16
	TableID uint8
	pad     [3]byte // 3 bytes
}

func NewNXActionResubmit(inPort uint16) *NXActionResubmit {
	a := new(NXActionResubmit)
	a.NXActionHeader = NewNxActionHeader(NXAST_RESUBMIT)
	a.Type = Type_Experimenter
	a.Length = a.NXActionHeader.Len() + 6
	a.InPort = inPort
	a.pad = [3]byte{}
	return a
}

func (a *NXActionResubmit) Len() (n uint16) {
	return a.Length
}

func (a *NXActionResubmit) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.InPort)
	n += 2
	a.TableID = OFPTT_ALL
	n += 1
	n += 3

	return
}

func (a *NXActionResubmit) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionConjunction message")
	}
	a.InPort = binary.BigEndian.Uint16(data[n:])

	return err
}

// nxast_resubmit_table
type NXActionResubmitTable struct {
	*NXActionHeader
	InPort  uint16
	TableID uint8
	pad     [3]byte // 3 bytes
	withCT  bool
}

func newNXActionResubmitTable() *NXActionResubmitTable {
	a := &NXActionResubmitTable{
		NXActionHeader: NewNxActionHeader(NXAST_RESUBMIT_TABLE),
		withCT:         false,
		pad:            [3]byte{},
	}
	a.Length = 16
	return a
}

func newNXActionResubmitTableCT() *NXActionResubmitTable {
	a := &NXActionResubmitTable{
		NXActionHeader: NewNxActionHeader(NXAST_RESUBMIT_TABLE),
		withCT:         true,
		pad:            [3]byte{},
	}
	a.Length = 16
	return a
}

func NewNXActionResubmitTableAction(inPort uint16, tableId uint8) *NXActionResubmitTable {
	a := newNXActionResubmitTable()
	a.InPort = inPort
	a.TableID = tableId
	return a
}

func (a *NXActionResubmitTable) IsCT() bool {
	return a.withCT
}

func (a *NXActionResubmitTable) Len() (n uint16) {
	return a.Length
}

func (a *NXActionResubmitTable) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.InPort)
	n += 2
	data[n] = a.TableID
	n += 1
	n += 3

	return
}

func (a *NXActionResubmitTable) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionResubmitTable message")
	}
	a.InPort = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.TableID = data[n]
	n += 1

	return err
}

func NewNXActionResubmitTableCT(inPort uint16, tableId uint8) *NXActionResubmitTable {
	a := newNXActionResubmitTableCT()
	a.InPort = inPort
	a.TableID = tableId
	return a
}

func NewNXActionResubmitTableCTNoInPort(tableId uint8) *NXActionResubmitTable {
	a := newNXActionResubmitTableCT()
	a.InPort = OFPP_IN_PORT
	a.TableID = tableId
	return a
}

// nxast_resubmit_table
type NXActionCTNAT struct {
	*NXActionHeader
	pad          []byte // 2 bytes
	Flags        uint16 // nat Flags to identify snat/dnat, and nat algorithms: random/protocolHash, connection persistent
	rangePresent uint16 // mark if has set nat range, including ipv4/ipv6 range, port range

	rangeIPv4Min  net.IP
	rangeIPv4Max  net.IP
	rangeIPv6Min  net.IP
	rangeIPv6Max  net.IP
	rangeProtoMin *uint16
	rangeProtoMax *uint16
}

func NewNXActionCTNAT() *NXActionCTNAT {
	a := new(NXActionCTNAT)
	a.NXActionHeader = NewNxActionHeader(NXAST_NAT)
	a.Length = 16
	a.pad = make([]byte, 2, 2)
	return a
}

func (a *NXActionCTNAT) Len() (n uint16) {
	a.Length = uint16(math.Ceil(float64(a.Length)/float64(8))) * 8
	return a.Length
}

func (a *NXActionCTNAT) MarshalBinary() (data []byte, err error) {
	optData := make([]byte, 0)
	optN := 0
	if a.rangeIPv4Min != nil {
		optData = append(optData[optN:], a.rangeIPv4Min.To4()...)
		optN += 4
	}
	if a.rangeIPv4Max != nil {
		optData = append(optData[optN:], a.rangeIPv4Max.To4()...)
		optN += 4
	}
	if a.rangeIPv6Min != nil {
		optData = append(optData[optN:], a.rangeIPv6Min.To16()...)
		optN += 16
	}
	if a.rangeIPv6Max != nil {
		optData = append(optData[optN:], a.rangeIPv6Max.To16()...)
		optN += 16
	}
	if a.rangeProtoMin != nil {
		binary.BigEndian.PutUint16(optData[optN:], *a.rangeProtoMin)
		optN += 2
	}
	if a.rangeProtoMin != nil {
		binary.BigEndian.PutUint16(optData[optN:], *a.rangeProtoMax)
		optN += 2
	}

	data = make([]byte, a.Len())
	b := make([]byte, a.NXActionHeader.Len())
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	copy(data[n:], a.pad)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.Flags)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.rangePresent)
	n += 2
	copy(data[n:], optData)
	n += optN

	// padding the message if the length is not an integer multiple of 8 bytes
	if n < int(a.Length) {
		var padN = int(a.Length) - n
		pad := make([]byte, padN, padN)
		copy(optData, pad)
		a.Length = a.Len()
	}
	return
}

func (a *NXActionCTNAT) SetSNAT() error {
	if a.Flags&(^uint16(NX_NAT_F_MASK)) != 0 || a.Flags&NX_NAT_F_DST != 0 {
		return errors.New("SNAT action should be exclusively with DNAT")
	}
	a.Flags |= NX_NAT_F_SRC
	return nil
}

func (a *NXActionCTNAT) SetDNAT() error {
	if a.Flags&NX_NAT_F_SRC != 0 {
		return errors.New("DNAT action should be exclusively with SNAT")
	}
	a.Flags |= NX_NAT_F_DST
	return nil
}

func (a *NXActionCTNAT) SetProtoHash() error {
	if a.Flags&NX_NAT_F_PROTO_RANDOM != 0 {
		return errors.New("protocol hash should be exclusively with random")
	}
	a.Flags |= NX_NAT_F_PROTO_HASH
	return nil
}

func (a *NXActionCTNAT) SetRandom() error {
	if a.Flags&NX_NAT_F_PROTO_HASH != 0 {
		return errors.New("random should be exclusively with protocol hash")
	}
	a.Flags |= NX_NAT_F_PROTO_RANDOM
	return nil
}

func (a *NXActionCTNAT) SetPersistent() error {
	a.Flags |= NX_NAT_F_PERSISTENT
	return nil
}

func (a *NXActionCTNAT) SetRangeIPv4Min(ipMin net.IP) {
	a.rangeIPv4Min = ipMin
	a.rangePresent |= NX_NAT_RANGE_IPV4_MIN
	a.Length += 4
}
func (a *NXActionCTNAT) SetRangeIPv4Max(ipMax net.IP) {
	a.rangeIPv4Max = ipMax
	a.rangePresent |= NX_NAT_RANGE_IPV4_MAX
	a.Length += 4
}
func (a *NXActionCTNAT) SetRangeIPv6Min(ipMin net.IP) {
	a.rangeIPv6Min = ipMin
	a.rangePresent |= NX_NAT_RANGE_IPV6_MIN
	a.Length += 16
}
func (a *NXActionCTNAT) SetRangeIPv6Max(ipMax net.IP) {
	a.rangeIPv6Max = ipMax
	a.rangePresent |= NX_NAT_RANGE_IPV6_MAX
	a.Length += 16
}
func (a *NXActionCTNAT) SetRangeProtoMin(protoMin *uint16) {
	a.rangeProtoMin = protoMin
	a.rangePresent |= NX_NAT_RANGE_PROTO_MIN
	a.Length += 2
}
func (a *NXActionCTNAT) SetRangeProtoMax(protoMax *uint16) {
	a.rangeProtoMax = protoMax
	a.rangePresent |= NX_NAT_RANGE_PROTO_MAX
	a.Length += 2
}

func (a *NXActionCTNAT) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionCTNAT message")
	}
	copy(a.pad, data[n:n+2])
	n += 2
	a.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.rangePresent = binary.BigEndian.Uint16(data[n:])
	n += 2
	if a.rangePresent&NX_NAT_RANGE_IPV4_MIN != 0 {
		a.rangeIPv4Min = net.IPv4(data[n], data[n+1], data[n+2], data[n+3])
		n += 4
	}
	if a.rangePresent&NX_NAT_RANGE_IPV4_MAX != 0 {
		a.rangeIPv4Max = net.IPv4(data[n], data[n+1], data[n+2], data[n+3])
		n += 4
	}
	if a.rangePresent&NX_NAT_RANGE_IPV6_MIN != 0 {
		a.rangeIPv6Min = make([]byte, 16)
		copy(a.rangeIPv6Min, data[n:n+16])
		n += 16
	}
	if a.rangePresent&NX_NAT_RANGE_IPV6_MAX != 0 {
		a.rangeIPv6Max = make([]byte, 16)
		copy(a.rangeIPv6Max, data[n:n+16])
		n += 16
	}
	if a.rangePresent&NX_NAT_RANGE_PROTO_MIN != 0 {
		portMin := binary.BigEndian.Uint16(data[n:])
		a.rangeProtoMin = &portMin
		n += 2
	}
	if a.rangePresent&NX_NAT_RANGE_PROTO_MAX != 0 {
		portMax := binary.BigEndian.Uint16(data[n:])
		a.rangeProtoMin = &portMax
		n += 2
	}

	return err
}

// nx_action_output_reg
type NXActionOutputReg struct {
	*NXActionHeader
	OfsNbits uint16      // (ofs << 6 | (Nbits -1)
	SrcField *MatchField // source nxm_nx_reg
	MaxLen   uint16      // Max length to send to controller if chosen port is OFPP_CONTROLLER
	zero     []uint8     // 6 uint8 with all Value as 0, reserved
}

func (a *NXActionOutputReg) Len() (n uint16) {
	return a.Length
}

func (a *NXActionOutputReg) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.OfsNbits)
	n += 2
	fieldHeaderData := a.SrcField.MarshalHeader()
	binary.BigEndian.PutUint32(data[n:], fieldHeaderData)
	n += 4
	binary.BigEndian.PutUint16(data[n:], a.MaxLen)
	n += 2
	copy(data[n:], a.zero)
	n += 6

	return
}

func (a *NXActionOutputReg) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionOutputReg message")
	}
	a.OfsNbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.SrcField = new(MatchField)
	err = a.SrcField.UnmarshalHeader(data[n : n+4])
	n += 4
	a.MaxLen = binary.BigEndian.Uint16(data[n:])
	return err
}

func newNXActionOutputReg() *NXActionOutputReg {
	a := &NXActionOutputReg{
		NXActionHeader: NewNxActionHeader(NXAST_OUTPUT_REG),
		zero:           make([]uint8, 6, 6),
	}
	a.Length = 24
	return a
}

func NewOutputFromField(srcField *MatchField, ofsNbits uint16) *NXActionOutputReg {
	a := newNXActionOutputReg()
	a.SrcField = srcField
	a.OfsNbits = ofsNbits
	a.MaxLen = uint16(0xffff)
	return a
}

func NewOutputFromFieldWithMaxLen(srcField *MatchField, ofsNbits uint16, maxLen uint16) *NXActionOutputReg {
	a := newNXActionOutputReg()
	a.SrcField = srcField
	a.OfsNbits = ofsNbits
	a.MaxLen = maxLen
	return a
}

type NXActionDecTTL struct {
	*NXActionHeader
	controllers uint16   // number of controller
	zeros       [4]uint8 // 4 byte with zeros
}

func (a *NXActionDecTTL) Len() (n uint16) {
	return a.Length
}

func (a *NXActionDecTTL) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.controllers)
	n += 2
	copy(data[n:], a.zeros[0:])
	return
}

func (a *NXActionDecTTL) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the byte array has wrong size to unmarshal an NXActionRegLoad2 message")
	}
	a.controllers = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.zeros = [4]uint8{}
	return err
}

func NewNXActionDecTTL() *NXActionDecTTL {
	a := &NXActionDecTTL{
		NXActionHeader: NewNxActionHeader(NXAST_DEC_TTL),
		zeros:          [4]uint8{},
	}
	a.Length = 16
	return a
}

type NXActionDecTTLCntIDs struct {
	*NXActionHeader
	controllers uint16   // number of controller
	zeros       [4]uint8 // 4 byte with zeros
	cntIDs      []uint16 // controller IDs
}

func (a *NXActionDecTTLCntIDs) Len() (n uint16) {
	return a.Length
}

func (a *NXActionDecTTLCntIDs) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	b := make([]byte, 0)
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.controllers)
	n += 2
	copy(data[n:], a.zeros[0:])
	n += 4
	for _, id := range a.cntIDs {
		binary.BigEndian.PutUint16(data[n:], id)
		n += 2
	}
	return
}

func (a *NXActionDecTTLCntIDs) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the []byte is too short to unmarshal a full NXActionDecTTLCntIDs message")
	}
	a.controllers = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.zeros = [4]uint8{}
	n += 4
	for i := 0; i < int(a.controllers); i++ {
		id := binary.BigEndian.Uint16(data[n:])
		a.cntIDs = append(a.cntIDs, id)
		n += 2
	}
	return err
}

func NewNXActionDecTTLCntIDs(controllers uint16, ids ...uint16) *NXActionDecTTLCntIDs {
	a := &NXActionDecTTLCntIDs{
		NXActionHeader: NewNxActionHeader(NXAST_DEC_TTL_CNT_IDS),
		controllers:    controllers,
		zeros:          [4]uint8{},
		cntIDs:         ids,
	}
	a.Length = 16 + uint16(2*len(ids))
	return a
}
