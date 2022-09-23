package openflow15

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"k8s.io/klog/v2"
)

// NX Action constants
const (
	NxExperimenterID     = 0x00002320 // Vendor ID for Nicira extension messages
	NxActionHeaderLength = 10         // Length of Nicira extension message header
)

// NX Action subtypes
const (
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
	NXAST_FIN_TIMEOUT      = 19 // Nicira extended action: fin_timeout
	NXAST_CONTROLLER       = 20 // Nicira extended action: controller(reason=xx,max_len=xx,id=xx)
	NXAST_DEC_TTL_CNT_IDS  = 21 // Nicira extended action: dec_ttl(id1,[id2]...)
	NXAST_PUSH_MPLS        = 23 // Nicira extended action: push_mpls
	NXAST_POP_MPLS         = 24 // Nicira extended action: pop_mpls
	NXAST_SET_MPLS_TTL     = 25 // Nicira extended action: set_mpls_ttl
	NXAST_DEC_MPLS_TTL     = 26 // Nicira extended action: dec_mpls_ttl
	NXAST_STACK_PUSH       = 27 // Nicira extended action: push:src
	NXAST_STACK_POP        = 28 // Nicira extended action: pop:dst
	NXAST_SAMPLE           = 29 // Nicira extended action: sample
	NXAST_SET_MPLS_LABEL   = 30 // Nicira extended action: set_mpls_label
	NXAST_SET_MPLS_TC      = 31 // Nicira extended action: set_mpls_tc
	NXAST_OUTPUT_REG2      = 32 // Nicira extended action: output(port=port,max_len)
	NXAST_REG_LOAD2        = 33 // Nicira extended action: load
	NXAST_CONJUNCTION      = 34 // Nicira extended action: conjunction
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
	var b []byte
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
		return errors.New("the []byte is too short to unmarshal a full NXActionHeader message")
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

func DecodeNxAction(data []byte) (Action, error) {
	var a Action
	if len(data) < 10 {
		return nil, errors.New("data too short to decode NxAction")
	}
	// Previous 8 bytes in the data includes type(2 byte), length(2 byte), and vendor(4 byte)
	subtype := binary.BigEndian.Uint16(data[8:])
	switch subtype {
	case NXAST_RESUBMIT:
		a = new(NXActionResubmit)
	case NXAST_SET_TUNNEL:
	case NXAST_DROP_SPOOFED_ARP:
	case NXAST_SET_QUEUE:
	case NXAST_POP_QUEUE:
	case NXAST_REG_MOVE:
		a = new(NXActionRegMove)
	case NXAST_REG_LOAD:
		a = new(NXActionRegLoad)
	case NXAST_NOTE:
		a = new(NXActionNote)
	case NXAST_SET_TUNNEL_V6:
	case NXAST_MULTIPATH:
	case NXAST_AUTOPATH:
	case NXAST_BUNDLE:
	case NXAST_BUNDLE_LOAD:
	case NXAST_RESUBMIT_TABLE:
		a = new(NXActionResubmitTable)
	case NXAST_OUTPUT_REG:
		a = new(NXActionOutputReg)
	case NXAST_LEARN:
		a = new(NXActionLearn)
	case NXAST_EXIT:
	case NXAST_DEC_TTL:
		a = new(NXActionDecTTL)
	case NXAST_FIN_TIMEOUT:
	case NXAST_CONTROLLER:
		a = new(NXActionController)
	case NXAST_DEC_TTL_CNT_IDS:
		a = new(NXActionDecTTLCntIDs)
	case NXAST_PUSH_MPLS:
	case NXAST_POP_MPLS:
	case NXAST_SET_MPLS_TTL:
	case NXAST_DEC_MPLS_TTL:
	case NXAST_STACK_PUSH:
	case NXAST_STACK_POP:
	case NXAST_SAMPLE:
	case NXAST_SET_MPLS_LABEL:
	case NXAST_SET_MPLS_TC:
	case NXAST_OUTPUT_REG2:
		a = new(NXActionOutputReg)
	case NXAST_REG_LOAD2:
		a = new(NXActionRegLoad2)
	case NXAST_CONJUNCTION:
		a = new(NXActionConjunction)
	case NXAST_CT:
		a = new(NXActionConnTrack)
	case NXAST_NAT:
		a = new(NXActionCTNAT)
	case NXAST_CONTROLLER2:
		a = new(NXActionController2)
	case NXAST_SAMPLE2:
	case NXAST_OUTPUT_TRUNC:
	case NXAST_CT_CLEAR:
	case NXAST_CT_RESUBMIT:
		a = new(NXActionResubmitTable)
		a.(*NXActionResubmitTable).withCT = true
	case NXAST_RAW_ENCAP:
	case NXAST_RAW_DECAP:
	case NXAST_DEC_NSH_TTL:
	default:
		err := fmt.Errorf("unknown NXActionHeader subtype: %v", subtype)
		klog.ErrorS(err, "Received invalid NXActionHeader", "data", data)
		return nil, err
	}
	return a, nil
}

// NXActionConjunction is NX action to configure conjunctive match flows.
type NXActionConjunction struct {
	*NXActionHeader
	Clause  uint8
	NClause uint8
	ID      uint32
}

// NewNXActionConjunction creates NXActionConjunction, the action in flow entry is like conjunction(ID, Clause/nclause).
func NewNXActionConjunction(clause uint8, nclause uint8, id uint32) *NXActionConjunction {
	a := new(NXActionConjunction)
	a.NXActionHeader = NewNxActionHeader(NXAST_CONJUNCTION)
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
	var b []byte
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	data[n] = a.Clause
	n++
	data[n] = a.NClause
	n++
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
		return errors.New("the []byte is too short to unmarshal a full NXActionConjunction message")
	}
	a.Clause = uint8(data[n])
	n++
	a.NClause = uint8(data[n])
	n++
	a.ID = binary.BigEndian.Uint32(data[n:])

	return err
}

// NXActionConnTrack is NX action for conntrack.
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
	var b []byte
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
	n++
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
		return errors.New("the []byte is too short to unmarshal a full NXActionConnTrack message")
	}
	a.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.ZoneSrc = binary.BigEndian.Uint32(data[n:])
	n += 4
	a.ZoneOfsNbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.RecircTable = data[n]
	n++
	copy(a.pad, data[n:n+3])
	n += 3
	a.Alg = binary.BigEndian.Uint16(data[n:])
	n += 2

	for n < int(a.Len()) {
		act, err := DecodeAction(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to decode NXActionConnTrack Actions", "data", data[n:])
			return err
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

// NXActionRegLoad is NX action to load data to a specified field.
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
	var b []byte
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
	if err := a.NXActionHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the []byte is too short to unmarshal a full NXActionRegLoad message")
	}
	a.OfsNbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.DstReg = new(MatchField)
	if err := a.DstReg.UnmarshalHeader(data[n : n+4]); err != nil {
		klog.ErrorS(err, "Failed to unmarshal NXActionRegLoad's DstReg", "data", data[n:n+4])
		return err
	}
	n += 4
	a.Value = binary.BigEndian.Uint64(data[n:])
	return nil
}

// NXActionRegMove is NX action to move data from srcField to dstField.
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
	var b []byte
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
	if err := a.NXActionHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionRegMove message")
	}
	a.Nbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.SrcOfs = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.DstOfs = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.SrcField = new(MatchField)
	if err := a.SrcField.UnmarshalHeader(data[n:]); err != nil {
		klog.ErrorS(err, "Failed to unmarshal NXActionRegMove's SrcField", "data", data[n:])
		return err
	}
	n += 4
	a.DstField = new(MatchField)
	if err := a.DstField.UnmarshalHeader(data[n:]); err != nil {
		klog.ErrorS(err, "Failed to unmarshal NXActionRegMove's DstField", "data", data[n:])
		return err
	}
	return nil
}

// NXActionResubmit is NX action to resubmit packet to a specified in_port.
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
	var b []byte
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.InPort)
	n += 2
	a.TableID = OFPTT_ALL
	n++
	// Skip padding copy, move the index.
	n += 3

	return
}

func (a *NXActionResubmit) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the []byte is too short to unmarshal a full NXActionConjunction message")
	}
	a.InPort = binary.BigEndian.Uint16(data[n:])

	return err
}

// NXActionResubmitTable is NX action to resubmit packet to a specified table and in_port.
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
		NXActionHeader: NewNxActionHeader(NXAST_CT_RESUBMIT),
		withCT:         true,
		pad:            [3]byte{},
	}
	a.Length = 16
	return a
}

func NewNXActionResubmitTableAction(inPort uint16, tableID uint8) *NXActionResubmitTable {
	a := newNXActionResubmitTable()
	a.InPort = inPort
	a.TableID = tableID
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
	var b []byte
	n := 0

	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.InPort)
	n += 2
	data[n] = a.TableID
	n++
	// Skip padding copy, move the index.
	n += 3

	return
}

func (a *NXActionResubmitTable) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the []byte is too short to unmarshal a full NXActionResubmitTable message")
	}
	a.InPort = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.TableID = data[n]
	n++
	// Skip padding copy, move the index.
	n += 3

	return err
}

func NewNXActionResubmitTableCT(inPort uint16, tableID uint8) *NXActionResubmitTable {
	a := newNXActionResubmitTableCT()
	a.InPort = inPort
	a.TableID = tableID
	return a
}

func NewNXActionResubmitTableCTNoInPort(tableID uint8) *NXActionResubmitTable {
	a := newNXActionResubmitTableCT()
	a.InPort = OFPP_IN_PORT
	a.TableID = tableID
	return a
}

// NXActionCTNAT is NX action to set NAT in conntrack.
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
	a.pad = make([]byte, 2)
	return a
}

func (a *NXActionCTNAT) Len() (n uint16) {
	a.Length = ((a.Length + 7) / 8) * 8
	return a.Length
}

func (a *NXActionCTNAT) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0

	if b, err = a.NXActionHeader.MarshalBinary(); err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)
	// Skip padding bytes
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.Flags)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.rangePresent)
	n += 2

	if a.rangeIPv4Min != nil {
		copy(data[n:], a.rangeIPv4Min.To4())
		n += 4
	}
	if a.rangeIPv4Max != nil {
		copy(data[n:], a.rangeIPv4Max.To4())
		n += 4
	}
	if a.rangeIPv6Min != nil {
		copy(data[n:], a.rangeIPv6Min.To16())
		n += 16
	}
	if a.rangeIPv6Max != nil {
		copy(data[n:], a.rangeIPv6Max.To16())
		n += 16
	}
	if a.rangeProtoMin != nil {
		binary.BigEndian.PutUint16(data[n:], *a.rangeProtoMin)
		n += 2
	}
	if a.rangeProtoMin != nil {
		binary.BigEndian.PutUint16(data[n:], *a.rangeProtoMax)
		n += 2
	}

	return
}

func (a *NXActionCTNAT) SetSNAT() error {
	if a.Flags&NX_NAT_F_DST != 0 {
		return errors.New("the SNAT and DNAT actions should be mutually exclusive")
	}
	a.Flags |= NX_NAT_F_SRC
	return nil
}

func (a *NXActionCTNAT) SetDNAT() error {
	if a.Flags&NX_NAT_F_SRC != 0 {
		return errors.New("the DNAT and SNAT actions should be mutually exclusive")
	}
	a.Flags |= NX_NAT_F_DST
	return nil
}

func (a *NXActionCTNAT) SetProtoHash() error {
	if a.Flags&NX_NAT_F_PROTO_RANDOM != 0 {
		return errors.New("protocol hash and random should be mutually exclusive")
	}
	a.Flags |= NX_NAT_F_PROTO_HASH
	return nil
}

func (a *NXActionCTNAT) SetRandom() error {
	if a.Flags&NX_NAT_F_PROTO_HASH != 0 {
		return errors.New("random and protocol hash should be mutually exclusive")
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
		return errors.New("the []byte is too short to unmarshal a full NXActionCTNAT message")
	}
	// Skip padding bytes
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
		a.rangeProtoMax = &portMax
		n += 2
	}

	return err
}

// NXActionOutputReg is NX action to output to a field with a specified range.
type NXActionOutputReg struct {
	*NXActionHeader
	OfsNbits uint16      // (ofs << 6 | (Nbits -1)
	SrcField *MatchField // source nxm_nx_reg
	MaxLen   uint16      // Max length to send to controller if chosen port is OFPP_CONTROLLER
	zero     [6]uint8    // 6 uint8 with all Value as 0, reserved
}

func (a *NXActionOutputReg) Len() (n uint16) {
	return a.Length
}

func (a *NXActionOutputReg) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	var b []byte
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
	copy(data[n:], a.zero[0:])
	n += 6

	return
}

func (a *NXActionOutputReg) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	if err := a.NXActionHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Len()) {
		return errors.New("the []byte is too short to unmarshal a full NXActionOutputReg message")
	}
	a.OfsNbits = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.SrcField = new(MatchField)
	if err := a.SrcField.UnmarshalHeader(data[n : n+4]); err != nil {
		klog.ErrorS(err, "Failed to unmarshal NXActionOutputReg's SrcField", "data", data[n:n+4])
		return err
	}
	n += 4
	a.MaxLen = binary.BigEndian.Uint16(data[n:])
	return nil
}

func newNXActionOutputReg() *NXActionOutputReg {
	a := &NXActionOutputReg{
		NXActionHeader: NewNxActionHeader(NXAST_OUTPUT_REG),
		zero:           [6]uint8{},
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
	var b []byte
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
		return errors.New("the []byte is too short to unmarshal a full NXActionDecTTL message")
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
	var b []byte
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

type NXLearnSpecHeader struct {
	src    bool
	dst    bool
	output bool
	nBits  uint16
	length uint16
}

func (h *NXLearnSpecHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, h.length)
	value := h.nBits
	if h.src {
		value |= 1 << LEARN_SPEC_HEADER_MATCH
	} else {
		value &^= 1 << LEARN_SPEC_HEADER_MATCH
	}
	if h.dst {
		value |= 1 << LEARN_SPEC_HEADER_LOAD
	} else {
		value &^= 1 << LEARN_SPEC_HEADER_LOAD
	}
	if h.output {
		value &^= 1 << LEARN_SPEC_HEADER_MATCH
		value |= 2 << LEARN_SPEC_HEADER_LOAD
	}
	binary.BigEndian.PutUint16(data[0:], value)
	return
}

func (h *NXLearnSpecHeader) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("the []byte is too short to unmarshal a full NXLearnSpecHeader message")
	}
	value := binary.BigEndian.Uint16(data)
	h.length = 2
	h.nBits = (0xffff >> 5) & value
	h.src = ((1 << LEARN_SPEC_HEADER_MATCH) & value) != 0
	h.dst = ((1 << LEARN_SPEC_HEADER_LOAD) & value) != 0
	h.output = ((2 << LEARN_SPEC_HEADER_LOAD) & value) != 0
	return nil
}

func (h *NXLearnSpecHeader) Len() (n uint16) {
	return h.length
}

func NewLearnHeaderMatchFromValue(nBits uint16) *NXLearnSpecHeader {
	return &NXLearnSpecHeader{src: true, dst: false, nBits: nBits, length: 2}
}

func NewLearnHeaderMatchFromField(nBits uint16) *NXLearnSpecHeader {
	return &NXLearnSpecHeader{src: false, dst: false, nBits: nBits, length: 2}
}

func NewLearnHeaderLoadFromValue(nBits uint16) *NXLearnSpecHeader {
	return &NXLearnSpecHeader{src: true, dst: true, nBits: nBits, length: 2}
}

func NewLearnHeaderLoadFromField(nBits uint16) *NXLearnSpecHeader {
	return &NXLearnSpecHeader{src: false, dst: true, nBits: nBits, length: 2}
}

func NewLearnHeaderOutputFromField(nBits uint16) *NXLearnSpecHeader {
	return &NXLearnSpecHeader{src: false, dst: false, output: true, nBits: nBits, length: 2}
}

type NXLearnSpecField struct {
	Field *MatchField
	Ofs   uint16
}

func (f *NXLearnSpecField) Len() uint16 {
	return uint16(6)
}

func (f *NXLearnSpecField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, f.Len())
	n := 0
	fieldValue := f.Field.MarshalHeader()
	binary.BigEndian.PutUint32(data[n:], fieldValue)
	n += 4
	binary.BigEndian.PutUint16(data[n:], f.Ofs)
	return
}

func (f *NXLearnSpecField) UnmarshalBinary(data []byte) error {
	if len(data) < int(f.Len()) {
		return errors.New("the []byte is too short to unmarshal a full NXLearnSpecField message")
	}
	f.Field = new(MatchField)
	n := 0
	err := f.Field.UnmarshalHeader(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal NXLearnSpecField's Field", "data", data[n:])
		return err
	}
	n += 4
	f.Ofs = binary.BigEndian.Uint16(data[n:])
	return nil
}

type NXLearnSpec struct {
	Header   *NXLearnSpecHeader
	SrcField *NXLearnSpecField
	DstField *NXLearnSpecField
	SrcValue []byte
}

func (s *NXLearnSpec) Len() uint16 {
	length := s.Header.Len()
	if s.Header.src {
		length += 2 * ((s.Header.nBits + 15) / 16)
	} else {
		length += 6
	}

	// Add the length of DstField if it is not to "output" to a port.
	if !s.Header.output {
		length += 6
	}
	return length
}

func (s *NXLearnSpec) MarshalBinary() (data []byte, err error) {
	data = make([]byte, s.Len())
	n := 0
	b, err := s.Header.MarshalBinary()
	if err != nil {
		return data, err
	}
	copy(data[n:], b)
	n += len(b)
	var srcData []byte
	var srcDataLength int
	if s.Header.src {
		srcDataLength = int(2 * ((s.Header.nBits + 15) / 16))
		srcData = append(srcData, s.SrcValue[:srcDataLength]...)
	} else {
		srcData, err = s.SrcField.MarshalBinary()
		if err != nil {
			return data, err
		}
		srcDataLength = 6
	}
	copy(data[n:], srcData)
	n += srcDataLength
	if !s.Header.output {
		var dstData []byte
		dstData, err = s.DstField.MarshalBinary()
		if err != nil {
			return data, err
		}
		copy(data[n:], dstData)
	}
	return data, err
}

func (s *NXLearnSpec) UnmarshalBinary(data []byte) error {
	var err error
	s.Header = new(NXLearnSpecHeader)
	err = s.Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	n := s.Header.Len()
	if s.Header.src {
		srcDataLength := 2 * ((s.Header.nBits + 15) / 16)
		s.SrcValue = data[n : n+srcDataLength]
		n += srcDataLength
	} else {
		s.SrcField = new(NXLearnSpecField)
		err = s.SrcField.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal NXLearnSpec's SrcField", "data", data[n:])
			return err
		}
		n += s.SrcField.Len()
	}
	if !s.Header.output {
		s.DstField = new(NXLearnSpecField)
		err = s.DstField.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal NXLearnSpec's DstField", "data", data[n:])
			return err
		}
		n += s.DstField.Len()
	}

	return err
}

type NXActionLearn struct {
	*NXActionHeader
	IdleTimeout    uint16
	HardTimeout    uint16
	Priority       uint16
	Cookie         uint64
	Flags          uint16
	TableID        uint8
	pad            uint8
	FinIdleTimeout uint16
	FinHardTimeout uint16
	LearnSpecs     []*NXLearnSpec
	pad2           []byte
}

func (a *NXActionLearn) Len() uint16 {
	length := a.NXActionHeader.Len() + 22
	for _, s := range a.LearnSpecs {
		length += s.Len()
	}
	return 8 * ((length + 7) / 8)
}

func (a *NXActionLearn) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0
	a.Length = a.Len()
	b, err = a.NXActionHeader.MarshalBinary()
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.IdleTimeout)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.HardTimeout)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.Priority)
	n += 2
	binary.BigEndian.PutUint64(data[n:], a.Cookie)
	n += 8
	binary.BigEndian.PutUint16(data[n:], a.Flags)
	n += 2
	data[n] = a.TableID
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.FinIdleTimeout)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.FinHardTimeout)
	n += 2
	for _, s := range a.LearnSpecs {
		b, err = s.MarshalBinary()
		if err != nil {
			return data, err
		}
		copy(data[n:], b)
		n += len(b)
	}
	return
}

func (a *NXActionLearn) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionLearn message")
	}
	n += int(a.NXActionHeader.Len())
	a.IdleTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.HardTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.Priority = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8
	a.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.TableID = data[n]
	n += 2
	a.FinIdleTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.FinHardTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	for n < int(a.Length) {
		if int(a.Length)-n < 8 {
			break
		}
		spec := new(NXLearnSpec)
		err = spec.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal NXActionLearn's LearnSpecs", "data", data[n:])
			return err
		}
		a.LearnSpecs = append(a.LearnSpecs, spec)
		n += int(spec.Len())
	}
	return nil
}

func NewNXActionLearn() *NXActionLearn {
	return &NXActionLearn{
		NXActionHeader: NewNxActionHeader(NXAST_LEARN),
	}
}

type NXActionNote struct {
	*NXActionHeader
	Note []byte
}

func (a *NXActionNote) Len() uint16 {
	length := a.NXActionHeader.Len() + uint16(len(a.Note))
	return 8 * ((length + 7) / 8)
}

func (a *NXActionNote) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	n := 0
	a.Length = a.Len()
	b, err := a.NXActionHeader.MarshalBinary()
	if err != nil {
		return data, err
	}
	copy(data[n:], b)
	n += len(b)
	copy(data[n:], a.Note)
	return
}

func (a *NXActionNote) UnmarshalBinary(data []byte) error {
	a.NXActionHeader = new(NXActionHeader)
	err := a.NXActionHeader.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionNote message")
	}
	n := a.NXActionHeader.Len()
	a.Note = data[n:a.Length]
	return nil
}

func NewNXActionNote() *NXActionNote {
	return &NXActionNote{
		NXActionHeader: NewNxActionHeader(NXAST_NOTE),
	}
}

// NXActionRegLoad2 is NX action to load data to a specified field.
type NXActionRegLoad2 struct {
	*NXActionHeader
	DstField *MatchField
	pad      []byte
}

func NewNXActionRegLoad2(dstField *MatchField) *NXActionRegLoad2 {
	a := new(NXActionRegLoad2)
	a.NXActionHeader = NewNxActionHeader(NXAST_REG_LOAD2)
	a.DstField = dstField
	return a
}

func (a *NXActionRegLoad2) Len() (n uint16) {
	return 8 * ((a.NXActionHeader.Len() + a.DstField.Len() + 7) / 8)
}

func (a *NXActionRegLoad2) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(a.Len()))
	var b []byte
	n := 0
	a.Length = a.Len()
	if b, err = a.NXActionHeader.MarshalBinary(); err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)
	fieldData, err := a.DstField.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], fieldData)
	n += len(fieldData)
	return
}

func (a *NXActionRegLoad2) UnmarshalBinary(data []byte) error {
	n := 0
	a.NXActionHeader = new(NXActionHeader)
	if err := a.NXActionHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	n += int(a.NXActionHeader.Len())
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionRegLoad2 message")
	}
	a.DstField = new(MatchField)
	err := a.DstField.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal NXActionRegLoad2's DstField", "data", data[n:])
		return err
	}
	return nil
}

// NXActionController is NX action to output packet to the Controller set with a specified ID.
type NXActionController struct {
	*NXActionHeader
	MaxLen       uint16
	ControllerID uint16
	Reason       uint8
	pad          uint8
}

func (a *NXActionController) Len() uint16 {
	return a.NXActionHeader.Len() + 6
}

func (a *NXActionController) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0
	a.Length = a.Len()
	b, err = a.NXActionHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint16(data[n:], a.MaxLen)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.ControllerID)
	n += 2
	data[n] = a.Reason
	n += 1

	return data, nil
}

func (a *NXActionController) UnmarshalBinary(data []byte) error {
	a.NXActionHeader = new(NXActionHeader)
	n := 0
	err := a.NXActionHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionController message")
	}
	n += int(a.NXActionHeader.Len())
	a.MaxLen = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.ControllerID = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.Reason = data[n]
	n += 1
	return nil
}

func NewNXActionController(controllerID uint16) *NXActionController {
	a := new(NXActionController)
	a.NXActionHeader = NewNxActionHeader(NXAST_CONTROLLER)
	a.ControllerID = controllerID
	a.Length = a.NXActionHeader.Len() + 6
	return a
}

const (
	NXAC2PT_MAX_LEN       = iota /* ovs_be16 max bytes to send (default all). */
	NXAC2PT_CONTROLLER_ID        /* ovs_be16 dest controller ID (default 0). */
	NXAC2PT_REASON               /* uint8_t reason (OFPR_*), default 0. */
	NXAC2PT_USERDATA             /* Data to copy into NXPINT_USERDATA. */
	NXAC2PT_PAUSE                /* Flag to pause pipeline to resume later. */
	NXAC2PT_METER_ID             /* ovs_b32 meter (default NX_CTLR_NO_METER). */

	NX_CTLR_NO_METER = 0
)

type NXActionController2PropMaxLen struct {
	*PropHeader /* Type: NXAC2PT_MAX_LEN */
	MaxLen      uint16
	pad         [2]uint8
}

func (a *NXActionController2PropMaxLen) Len() uint16 {
	return a.PropHeader.Len() + 4
}

func (a *NXActionController2PropMaxLen) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0

	a.Length = a.PropHeader.Len() + 2
	b, err = a.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(a.PropHeader.Len())

	binary.BigEndian.PutUint16(data[n:], a.MaxLen)
	return
}

func (a *NXActionController2PropMaxLen) UnmarshalBinary(data []byte) error {
	a.PropHeader = new(PropHeader)
	n := 0

	if err := a.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionController2PropMaxLen message")
	}
	n += int(a.PropHeader.Len())

	a.MaxLen = binary.BigEndian.Uint16(data[n:])
	return nil
}

func NewMaxLen(maxLen uint16) *NXActionController2PropMaxLen {
	a := new(NXActionController2PropMaxLen)
	a.PropHeader = new(PropHeader)
	a.Type = NXAC2PT_MAX_LEN
	a.Length = a.PropHeader.Len() + 2
	a.MaxLen = maxLen
	return a
}

type NXActionController2PropControllerID struct {
	*PropHeader  /* Type: NXAC2PT_CONTROLLER_ID */
	ControllerID uint16
	pad          [2]uint8
}

func (a *NXActionController2PropControllerID) Len() uint16 {
	return a.PropHeader.Len() + 4
}

func (a *NXActionController2PropControllerID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0

	a.Length = a.PropHeader.Len() + 2
	b, err = a.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(a.PropHeader.Len())

	binary.BigEndian.PutUint16(data[n:], a.ControllerID)
	return
}

func (a *NXActionController2PropControllerID) UnmarshalBinary(data []byte) error {
	a.PropHeader = new(PropHeader)
	n := 0

	if err := a.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionController2PropControllerID message")
	}
	n += int(a.PropHeader.Len())

	a.ControllerID = binary.BigEndian.Uint16(data[n:])
	return nil
}

func NewControllerID(controllerID uint16) *NXActionController2PropControllerID {
	a := new(NXActionController2PropControllerID)
	a.PropHeader = new(PropHeader)
	a.Type = NXAC2PT_CONTROLLER_ID
	a.Length = a.PropHeader.Len() + 2
	a.ControllerID = controllerID
	return a
}

type NXActionController2PropReason struct {
	*PropHeader /* Type: NXAC2PT_REASON */
	Reason      uint8
	pad         [3]uint8
}

func (a *NXActionController2PropReason) Len() uint16 {
	return a.PropHeader.Len() + 4
}

func (a *NXActionController2PropReason) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0

	a.Length = a.PropHeader.Len() + 1
	b, err = a.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(a.PropHeader.Len())

	data[n] = a.Reason
	return
}

func (a *NXActionController2PropReason) UnmarshalBinary(data []byte) error {
	a.PropHeader = new(PropHeader)
	n := 0

	if err := a.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionController2PropReason message")
	}
	n += int(a.PropHeader.Len())

	a.Reason = data[n]
	return nil
}

func NewReason(reason uint8) *NXActionController2PropReason {
	a := new(NXActionController2PropReason)
	a.PropHeader = new(PropHeader)
	a.Type = NXAC2PT_REASON
	a.Length = a.PropHeader.Len() + 1
	a.Reason = reason
	return a
}

type NXActionController2PropUserdata struct {
	*PropHeader /* Type: NXAC2PT_USERDATA */
	Userdata    []byte
	pad         []uint8
}

func (a *NXActionController2PropUserdata) Len() uint16 {
	length := a.PropHeader.Len() + uint16(len(a.Userdata))
	return 8 * ((length + 7) / 8)
}

func (a *NXActionController2PropUserdata) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0

	a.Length = a.PropHeader.Len() + uint16(len(a.Userdata))
	b, err = a.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(a.PropHeader.Len())

	copy(data[n:], a.Userdata)
	return
}

func (a *NXActionController2PropUserdata) UnmarshalBinary(data []byte) error {
	a.PropHeader = new(PropHeader)
	n := 0

	if err := a.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionController2PropUserdata message")
	}
	n += int(a.PropHeader.Len())

	a.Userdata = data[n:a.Length]
	return nil
}

func NewUserdata(userdata []byte) *NXActionController2PropUserdata {
	a := new(NXActionController2PropUserdata)
	a.PropHeader = new(PropHeader)
	a.Type = NXAC2PT_USERDATA
	a.Length = a.PropHeader.Len() + uint16(len(a.Userdata))
	a.Userdata = userdata
	return a
}

type NXActionController2PropPause struct {
	*PropHeader /* Type: NXAC2PT_PAUSE */
	pad         [4]uint8
}

func (a *NXActionController2PropPause) Len() uint16 {
	return a.PropHeader.Len() + 4
}

func (a *NXActionController2PropPause) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0

	a.Length = a.PropHeader.Len()
	b, err = a.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(a.PropHeader.Len())
	return
}

func (a *NXActionController2PropPause) UnmarshalBinary(data []byte) error {
	a.PropHeader = new(PropHeader)
	n := 0

	if err := a.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionController2PropPause message")
	}
	n += int(a.PropHeader.Len())
	return nil
}

func NewPause() *NXActionController2PropPause {
	a := new(NXActionController2PropPause)
	a.PropHeader = new(PropHeader)
	a.Type = NXAC2PT_PAUSE
	a.Length = a.PropHeader.Len()
	return a
}

type NXActionController2PropMeterId struct {
	*PropHeader /* Type: NXAC2PT_METER_ID */
	MeterId     uint32
}

func (a *NXActionController2PropMeterId) Len() uint16 {
	return a.PropHeader.Len() + 4
}

func (a *NXActionController2PropMeterId) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0

	a.Length = a.PropHeader.Len() + 4
	b, err = a.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(a.PropHeader.Len())

	binary.BigEndian.PutUint32(data[n:], a.MeterId)
	return
}

func (a *NXActionController2PropMeterId) UnmarshalBinary(data []byte) error {
	a.PropHeader = new(PropHeader)
	n := 0

	if err := a.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionController2PropMeterId message")
	}
	n += int(a.PropHeader.Len())

	a.MeterId = binary.BigEndian.Uint32(data[n:])
	return nil
}

func NewMeterId(meterId uint32) *NXActionController2PropMeterId {
	a := new(NXActionController2PropMeterId)
	a.PropHeader = new(PropHeader)
	a.Type = NXAC2PT_METER_ID
	a.Length = a.PropHeader.Len() + 4
	a.MeterId = meterId
	return a
}

// Decode Controller2 Property types.
func DecodeController2Prop(data []byte) (Property, error) {
	t := binary.BigEndian.Uint16(data[:2])
	var p Property
	switch t {
	case NXAC2PT_MAX_LEN:
		p = new(NXActionController2PropMaxLen)
	case NXAC2PT_CONTROLLER_ID:
		p = new(NXActionController2PropControllerID)
	case NXAC2PT_REASON:
		p = new(NXActionController2PropReason)
	case NXAC2PT_USERDATA:
		p = new(NXActionController2PropUserdata)
	case NXAC2PT_PAUSE:
		p = new(NXActionController2PropPause)
	case NXAC2PT_METER_ID:
		p = new(NXActionController2PropMeterId)
	}
	err := p.UnmarshalBinary(data)
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal NXActionController2Prop", "data", data)
		return p, err
	}
	return p, nil
}

// NXActionController2 is NX action to output packet to the Controller set with a specified ID.
type NXActionController2 struct {
	*NXActionHeader
	pad [6]uint8

	props []Property
}

func (a *NXActionController2) Len() uint16 {
	n := a.NXActionHeader.Len() + 6
	for _, prop := range a.props {
		n += prop.Len()
	}
	return n
}

func (a *NXActionController2) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	var b []byte
	n := 0

	a.Length = a.Len()
	b, err = a.NXActionHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(a.NXActionHeader.Len())
	n += 6

	for _, prop := range a.props {
		b, err = prop.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(prop.Len())
	}

	return
}

func (a *NXActionController2) UnmarshalBinary(data []byte) error {
	a.NXActionHeader = new(NXActionHeader)
	n := 0

	if err := a.NXActionHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(a.Length) {
		return errors.New("the []byte is too short to unmarshal a full NXActionController2 message")
	}
	n += int(a.NXActionHeader.Len())
	n += 6

	for n < int(a.Length) {
		prop, err := DecodeController2Prop(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to decode Controller2Prop", "data", data[n:])
			return err
		}
		a.props = append(a.props, prop)
		n += int(prop.Len())
	}

	return nil
}

func (a *NXActionController2) AddMaxLen(maxLen uint16) {
	a.props = append(a.props, NewMaxLen(maxLen))
	a.Length = a.Len()
}

func (a *NXActionController2) AddControllerID(controllerID uint16) {
	a.props = append(a.props, NewControllerID(controllerID))
	a.Length = a.Len()
}

func (a *NXActionController2) AddReason(reason uint8) {
	a.props = append(a.props, NewReason(reason))
	a.Length = a.Len()
}

func (a *NXActionController2) AddUserdata(userdata []byte) {
	a.props = append(a.props, NewUserdata(userdata))
	a.Length = a.Len()
}

func (a *NXActionController2) AddPause(pause bool) {
	if pause {
		a.props = append(a.props, NewPause())
		a.Length = a.Len()
	}
}

func (a *NXActionController2) AddMeterID(meterID uint32) {
	if meterID != NX_CTLR_NO_METER {
		a.props = append(a.props, NewMeterId(meterID))
		a.Length = a.Len()
	}
}

func NewNXActionController2() *NXActionController2 {
	a := new(NXActionController2)
	a.NXActionHeader = NewNxActionHeader(NXAST_CONTROLLER2)
	return a
}
