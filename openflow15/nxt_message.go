package openflow15

import (
	"encoding/binary"
	"errors"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
)

// Nicira extension messages.
const (
	Type_SetFlowFormat     = 12
	Type_FlowModTableId    = 15
	Type_SetPacketInFormat = 16
	Type_SetControllerId   = 20
	Type_TlvTableMod       = 24
	Type_TlvTableRequest   = 25
	Type_TlvTableReply     = 26
	Type_Resume            = 28
	Type_CtFlushZone       = 29
	Type_PacketIn2         = 30
)

// ofpet_tlv_table_mod_failed_code 1.3
const (
	OFPERR_NXTTMFC_BAD_COMMAND     = 16
	OFPERR_NXTTMFC_BAD_OPT_LEN     = 17
	ERR_NXTTMFC_BAD_FIELD_IDX      = 18
	OFPERR_NXTTMFC_TABLE_FULL      = 19
	OFPERR_NXTTMFC_ALREADY_MAPPED  = 20
	OFPERR_NXTTMFC_DUP_ENTRY       = 21
	OFPERR_NXTTMFC_INVALID_TLV_DEL = 38
)

func NewNXTVendorHeader(msgType uint32) *VendorHeader {
	h := NewOfp15Header()
	h.Type = Type_Experimenter
	return &VendorHeader{
		Header:           h,
		Vendor:           NxExperimenterID,
		ExperimenterType: msgType,
	}
}

// ofputil_packet_in_format
const (
	OFPUTIL_PACKET_IN_STD  = iota /* OFPT_PACKET_IN for this OpenFlow version. */
	OFPUTIL_PACKET_IN_NXT         /* NXT_PACKET_IN (since OVS v1.1). */
	OFPUTIL_PACKET_IN_NXT2        /* NXT_PACKET_IN2 (since OVS v2.6). */
)

type PacketInFormat struct {
	Spif uint32
}

func (p *PacketInFormat) Len() (n uint16) {
	return 4
}

func (p *PacketInFormat) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0
	binary.BigEndian.PutUint32(data[n:], p.Spif)
	return
}

func (p *PacketInFormat) UnmarshalBinary(data []byte) error {
	n := 0
	p.Spif = binary.BigEndian.Uint32(data[n:])
	return nil
}

func NewSetPacketInFormet(format uint32) *VendorHeader {
	msg := NewNXTVendorHeader(Type_SetPacketInFormat)
	msg.VendorData = &PacketInFormat{
		Spif: format,
	}
	return msg
}

type ControllerID struct {
	pad [6]byte
	ID  uint16
}

func (c *ControllerID) Len() uint16 {
	return uint16(len(c.pad) + 2)
}

func (c *ControllerID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(c.Len()))
	n := 6
	binary.BigEndian.PutUint16(data[n:], c.ID)
	return data, nil
}

func (c *ControllerID) UnmarshalBinary(data []byte) error {
	if len(data) < int(c.Len()) {
		return errors.New("the []byte is too short to unmarshal a full ControllerID message")
	}
	n := 6
	c.ID = binary.BigEndian.Uint16(data[n:])
	return nil
}

func NewSetControllerID(id uint16) *VendorHeader {
	msg := NewNXTVendorHeader(Type_SetControllerId)
	msg.VendorData = &ControllerID{
		ID: id,
	}
	return msg
}

type TLVTableMap struct {
	OptClass  uint16
	OptType   uint8
	OptLength uint8
	Index     uint16
	pad       [2]byte
}

func (t *TLVTableMap) Len() uint16 {
	return uint16(len(t.pad) + 6)
}

func (t *TLVTableMap) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(t.Len()))
	n := 0
	binary.BigEndian.PutUint16(data[n:], t.OptClass)
	n += 2
	data[n] = t.OptType
	n += 1
	data[n] = t.OptLength
	n += 1
	binary.BigEndian.PutUint16(data[n:], t.Index)
	return data, nil
}

func (t *TLVTableMap) UnmarshalBinary(data []byte) error {
	if len(data) < int(t.Len()) {
		return errors.New("the []byte is too short to unmarshal a full TLVTableMap message")
	}
	n := 0
	t.OptClass = binary.BigEndian.Uint16(data[n:])
	n += 2
	t.OptType = data[n]
	n += 1
	t.OptLength = data[n]
	n += 1
	t.Index = binary.BigEndian.Uint16(data[n:])
	return nil
}

type TLVTableMod struct {
	Command uint16
	pad     [6]byte
	TlvMaps []*TLVTableMap
}

func (t *TLVTableMod) Len() uint16 {
	length := uint16(8)
	for _, tlvMap := range t.TlvMaps {
		length += tlvMap.Len()
	}
	return length
}

func (t *TLVTableMod) MarshalBinary() (data []byte, err error) {
	data = make([]byte, t.Len())
	n := 0
	binary.BigEndian.PutUint16(data[n:], t.Command)
	n += 2
	n += 6
	for _, tlvMap := range t.TlvMaps {
		tlvData, err := tlvMap.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], tlvData)
		n += len(tlvData)
	}
	return data, nil
}

func (t *TLVTableMod) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return errors.New("the []byte is too short to unmarshal a full TLVTableMod message")
	}
	n := 0
	t.Command = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 6

	for n < len(data) {
		tlvMap := new(TLVTableMap)
		err := tlvMap.UnmarshalBinary(data[n:])
		if err != nil {
			return err
		}
		n += int(tlvMap.Len())
		t.TlvMaps = append(t.TlvMaps, tlvMap)
	}
	return nil
}

func NewTLVTableMod(command uint16, tlvMaps []*TLVTableMap) *TLVTableMod {
	return &TLVTableMod{
		Command: command,
		TlvMaps: tlvMaps,
	}
}

func NewTLVTableModMessage(tlvMod *TLVTableMod) *VendorHeader {
	msg := NewNXTVendorHeader(Type_TlvTableMod)
	msg.VendorData = tlvMod
	return msg
}

type TLVTableReply struct {
	MaxSpace  uint32
	MaxFields uint16
	reserved  [10]byte
	TlvMaps   []*TLVTableMap
}

func (t *TLVTableReply) Len() uint16 {
	length := uint16(16)
	for _, tlvMap := range t.TlvMaps {
		length += tlvMap.Len()
	}
	return length
}

func (t *TLVTableReply) MarshalBinary() (data []byte, err error) {
	data = make([]byte, t.Len())
	n := 0
	binary.BigEndian.PutUint32(data[n:], t.MaxSpace)
	n += 4
	binary.BigEndian.PutUint16(data[n:], t.MaxFields)
	n += 2
	n += 10
	for _, tlvMap := range t.TlvMaps {
		tlvData, err := tlvMap.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], tlvData)
		n += len(tlvData)
	}
	return data, nil
}

func (t *TLVTableReply) UnmarshalBinary(data []byte) error {
	n := 0
	t.MaxSpace = binary.BigEndian.Uint32(data[n:])
	n += 4
	t.MaxFields = binary.BigEndian.Uint16(data[n:])
	n += 2
	t.reserved = [10]byte{}
	copy(t.reserved[0:], data[n:n+10])
	n += 10
	for n < len(data) {
		tlvMap := new(TLVTableMap)
		err := tlvMap.UnmarshalBinary(data[n:])
		if err != nil {
			return err
		}
		n += int(tlvMap.Len())
		t.TlvMaps = append(t.TlvMaps, tlvMap)
	}
	return nil
}

func NewTLVTableRequest() *VendorHeader {
	return NewNXTVendorHeader(Type_TlvTableRequest)
}

// nx_continuation_prop_type
const (
	NXCPT_BRIDGE      = 0x8000
	NXCPT_STACK       = 0x8001
	NXCPT_MIRRORS     = 0x8002
	NXCPT_CONNTRACKED = 0x8003
	NXCPT_TABLE_ID    = 0x8004
	NXCPT_COOKIE      = 0x8005
	NXCPT_ACTIONS     = 0x8006
	NXCPT_ACTION_SET  = 0x8007
	NXCPT_ODP_PORT    = 0x8008
)

type ContinuationPropBridge struct {
	*PropHeader /* Type: NXCPT_BRIDGE */
	Bridge      [4]uint32
	pad         [4]uint8
}

func (p *ContinuationPropBridge) Len() (n uint16) {
	return p.PropHeader.Len() + 20
}

func (p *ContinuationPropBridge) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + 16
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(data[n:], p.Bridge[i])
		n += 4
	}
	return
}

func (p *ContinuationPropBridge) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropBridge message")
	}
	n += int(p.PropHeader.Len())

	for i := 0; i < 4; i++ {
		p.Bridge[i] = binary.BigEndian.Uint32(data[n:])
		n += 4
	}
	return nil
}

type ContinuationPropStack struct {
	*PropHeader /* Type: NXCPT_STACK */
	Stack       []uint8
	pad         []uint8
}

func (p *ContinuationPropStack) Len() (n uint16) {
	n = p.PropHeader.Len() + uint16(len(p.Stack))

	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *ContinuationPropStack) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + uint16(len(p.Stack))
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	copy(data[n:], p.Stack)
	return
}

func (p *ContinuationPropStack) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropStack message")
	}
	n += int(p.PropHeader.Len())
	for _, eachStack := range p.Stack {
		data[n] = eachStack
		n++
	}
	return nil
}

type ContinuationPropMirrors struct {
	*PropHeader /* Type: NXCPT_MIRRORS */
	Mirrors     uint32
}

func (p *ContinuationPropMirrors) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *ContinuationPropMirrors) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + 4
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	binary.BigEndian.PutUint32(data[n:], p.Mirrors)
	return
}

func (p *ContinuationPropMirrors) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropMirrors message")
	}
	n += int(p.PropHeader.Len())

	p.Mirrors = binary.BigEndian.Uint32(data[n:])
	return nil
}

type ContinuationPropConntracked struct {
	*PropHeader /* Type: NXCPT_CONNTRACKED */
	pad         [4]uint8
}

func (p *ContinuationPropConntracked) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *ContinuationPropConntracked) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len()
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	return
}

func (p *ContinuationPropConntracked) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropConntracked message")
	}
	n += int(p.PropHeader.Len())
	return nil
}

type ContinuationPropTableID struct {
	*PropHeader /* Type: NXCPT_TABLE_ID */
	TableID     uint8
	pad         [3]uint8
}

func (p *ContinuationPropTableID) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *ContinuationPropTableID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + 1
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	data[n] = p.TableID
	return
}

func (p *ContinuationPropTableID) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropTableID message")
	}
	n += int(p.PropHeader.Len())

	p.TableID = data[n]
	return nil
}

type ContinuationPropCookie struct {
	*PropHeader /* Type: NXCPT_COOKIE */
	pad         [4]uint8
	Cookie      uint64
}

func (p *ContinuationPropCookie) Len() (n uint16) {
	return p.PropHeader.Len() + 12
}

func (p *ContinuationPropCookie) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.Len()
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	binary.BigEndian.PutUint64(data[n:], p.Cookie)
	return
}

func (p *ContinuationPropCookie) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropCookie message")
	}
	n += int(p.PropHeader.Len())

	p.Cookie = binary.BigEndian.Uint64(data[n:])
	return nil
}

type ContinuationPropActions struct {
	*PropHeader /* Type: NXCPT_ACTIONS */
	pad         [4]uint8
	Actions     []Action
}

func (p *ContinuationPropActions) Len() (n uint16) {
	n = p.PropHeader.Len() + 4
	for _, action := range p.Actions {
		n += action.Len()
	}
	return n
}

func (p *ContinuationPropActions) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.Len()
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	n += 4

	for _, action := range p.Actions {
		b, err = action.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(action.Len())
	}
	return
}

func (p *ContinuationPropActions) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropActions message")
	}
	n += int(p.PropHeader.Len())
	n += 4

	for n < int(p.Length) {
		act, err := DecodeAction(data[n:])
		if err != nil {
			return errors.New("failed to decode actions")
		}
		p.Actions = append(p.Actions, act)
		n += int(act.Len())
	}
	return nil
}

type ContinuationPropActionSet struct {
	*PropHeader /* Type: NXCPT_ACTION_SET */
	pad         [4]uint8
	ActionSet   []Action
}

func (p *ContinuationPropActionSet) Len() (n uint16) {
	n = p.PropHeader.Len() + 4
	for _, action := range p.ActionSet {
		n += action.Len()
	}
	return n
}

func (p *ContinuationPropActionSet) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.Len()
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	n += 4

	for _, action := range p.ActionSet {
		b, err = action.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(action.Len())
	}
	return
}

func (p *ContinuationPropActionSet) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropActionSet message")
	}
	n += int(p.PropHeader.Len())
	n += 4

	for n < int(p.Length) {
		act, err := DecodeAction(data[n:])
		if err != nil {
			return errors.New("failed to decode actions")
		}
		p.ActionSet = append(p.ActionSet, act)
		n += int(act.Len())
	}
	return nil
}

type ContinuationPropOdpPort struct {
	*PropHeader /* Type: NXCPT_ODP_PORT */
	OdpPort     uint32
}

func (p *ContinuationPropOdpPort) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *ContinuationPropOdpPort) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + 4
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	binary.BigEndian.PutUint32(data[n:], p.OdpPort)
	return
}

func (p *ContinuationPropOdpPort) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationPropOdpPort message")
	}
	n += int(p.PropHeader.Len())

	p.OdpPort = binary.BigEndian.Uint32(data[n:])
	return nil
}

// Decode Continuation Property types.
func DecodeContinuationProp(data []byte) (Property, error) {
	t := binary.BigEndian.Uint16(data[:2])
	var p Property
	switch t {
	case NXCPT_BRIDGE:
		p = new(ContinuationPropBridge)
	case NXCPT_STACK:
		p = new(ContinuationPropStack)
	case NXCPT_MIRRORS:
		p = new(ContinuationPropMirrors)
	case NXCPT_CONNTRACKED:
		p = new(ContinuationPropConntracked)
	case NXCPT_TABLE_ID:
		p = new(ContinuationPropTableID)
	case NXCPT_COOKIE:
		p = new(ContinuationPropCookie)
	case NXCPT_ACTIONS:
		p = new(ContinuationPropActions)
	case NXCPT_ACTION_SET:
		p = new(ContinuationPropActionSet)
	case NXCPT_ODP_PORT:
		p = new(ContinuationPropOdpPort)
	}
	err := p.UnmarshalBinary(data)
	if err != nil {
		return p, err
	}
	return p, nil
}

// nx_packet_in2_prop_type
const (
	/* Packet. */
	NXPINT_PACKET    = iota /* Raw packet data. */
	NXPINT_FULL_LEN         /* ovs_be32: Full packet len, if truncated. */
	NXPINT_BUFFER_ID        /* ovs_be32: Buffer ID, if buffered. */

	/* Information about the flow that triggered the packet-in. */
	NXPINT_TABLE_ID /* uint8_t: Table ID. */
	NXPINT_COOKIE   /* ovs_be64: Flow cookie. */

	/* Other. */
	NXPINT_REASON       /* uint8_t, one of OFPR_*. */
	NXPINT_METADATA     /* NXM or OXM for metadata fields. */
	NXPINT_USERDATA     /* From NXAST_CONTROLLER2 userdata. */
	NXPINT_CONTINUATION /* Private data for continuing processing. */
)

type PacketIn2PropPacket struct {
	*PropHeader
	Packet protocol.Ethernet
	pad    []uint8
}

func (p *PacketIn2PropPacket) Len() (n uint16) {
	n = p.PropHeader.Len() + p.Packet.Len()

	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *PacketIn2PropPacket) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + p.Packet.Len()
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	b, err = p.Packet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	return
}

func (p *PacketIn2PropPacket) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropPacket message")
	}
	n += int(p.PropHeader.Len())

	if err := p.Packet.UnmarshalBinary(data[n:p.Length]); err != nil {
		return err
	}
	return nil
}

type PacketIn2PropFullLen struct {
	*PropHeader /* Type: NXPINT_FULL_LEN */
	FullLen     uint32
}

func (p *PacketIn2PropFullLen) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropFullLen) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + 4
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	binary.BigEndian.PutUint32(data[n:], p.FullLen)
	return
}

func (p *PacketIn2PropFullLen) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropFullLen message")
	}
	n += int(p.PropHeader.Len())

	p.FullLen = binary.BigEndian.Uint32(data[n:])
	return nil
}

type PacketIn2PropBufferID struct {
	*PropHeader /* Type: NXPINT_BUFFER_ID */
	BufferID    uint32
}

func (p *PacketIn2PropBufferID) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropBufferID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + 4
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	binary.BigEndian.PutUint32(data[n:], p.BufferID)
	return
}

func (p *PacketIn2PropBufferID) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropBufferID message")
	}
	n += int(p.PropHeader.Len())

	p.BufferID = binary.BigEndian.Uint32(data[n:])
	return nil
}

type PacketIn2PropTableID struct {
	*PropHeader /* Type: NXPINT_TABLE_ID */
	TableID     uint8
	pad         [3]uint8
}

func (p *PacketIn2PropTableID) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropTableID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + 1
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	data[n] = p.TableID
	return
}

func (p *PacketIn2PropTableID) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropTableID message")
	}
	n += int(p.PropHeader.Len())

	p.TableID = data[n]
	return nil
}

type PacketIn2PropCookie struct {
	*PropHeader /* Type: NXPINT_COOKIE */
	pad         [4]uint8
	Cookie      uint64
}

func (p *PacketIn2PropCookie) Len() (n uint16) {
	return p.PropHeader.Len() + 12
}

func (p *PacketIn2PropCookie) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.Len()
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	n += 4

	binary.BigEndian.PutUint64(data[n:], p.Cookie)
	return
}

func (p *PacketIn2PropCookie) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropCookie message")
	}
	n += int(p.PropHeader.Len())
	n += 4

	p.Cookie = binary.BigEndian.Uint64(data[n:])
	return nil
}

type PacketIn2PropReason struct {
	*PropHeader /* Type: NXPINT_COOKIE */
	Reason      uint8
	pad         [3]uint8
}

func (p *PacketIn2PropReason) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropReason) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + 1
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	data[n] = p.Reason
	return
}

func (p *PacketIn2PropReason) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropReason message")
	}
	n += int(p.PropHeader.Len())

	p.Reason = data[n]
	return nil
}

type PacketIn2PropMetadata struct {
	*PropHeader /* Type: NXPINT_METADATA */
	Fields      []MatchField
	pad         []uint8
}

func (p *PacketIn2PropMetadata) Len() (n uint16) {
	n = p.PropHeader.Len()
	for _, field := range p.Fields {
		n += field.Len()
	}
	return ((n + 7) / 8) * 8
}

func (p *PacketIn2PropMetadata) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	l := p.PropHeader.Len()
	for _, field := range p.Fields {
		l += field.Len()
	}
	p.Length = l
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	for _, field := range p.Fields {
		b, err = field.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(field.Len())
	}
	return
}

func (p *PacketIn2PropMetadata) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropMetadata message")
	}
	n += int(p.PropHeader.Len())

	for n < int(p.Length) {
		field := new(MatchField)
		if err := field.UnmarshalBinary(data[n:]); err != nil {
			return err
		}
		p.Fields = append(p.Fields, *field)
		n += int(field.Len())
	}
	return nil
}

type PacketIn2PropUserdata struct {
	*PropHeader /* Type: NXPINT_USERDATA */
	Userdata    []uint8
	pad         []uint8
}

func (p *PacketIn2PropUserdata) Len() (n uint16) {
	n = p.PropHeader.Len() + uint16(len(p.Userdata))
	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *PacketIn2PropUserdata) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	p.Length = p.PropHeader.Len() + uint16(len(p.Userdata))
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	copy(data[n:], p.Userdata)
	return
}

func (p *PacketIn2PropUserdata) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropUserdata message")
	}
	n += int(p.PropHeader.Len())

	p.Userdata = data[n:p.Length]
	return nil
}

type PacketIn2PropContinuation struct {
	*PropHeader  /* Type: NXPINT_CONTINUATION */
	Continuation []byte
	pad          []uint8
}

func (p *PacketIn2PropContinuation) Len() (n uint16) {
	n = p.PropHeader.Len() + uint16(len(p.Continuation))
	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *PacketIn2PropContinuation) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	var b []byte
	n := 0

	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	copy(data[n:p.Length], p.Continuation)
	return
}

func (p *PacketIn2PropContinuation) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0

	if err := p.PropHeader.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2PropContinuation message")
	}
	n += int(p.PropHeader.Len())

	p.Continuation = data[n:p.Length]
	return nil
}

// Decode PacketIn2 Property types.
func DecodePacketIn2Prop(data []byte) (Property, error) {
	t := binary.BigEndian.Uint16(data[:2])
	var p Property
	switch t {
	case NXPINT_PACKET:
		p = new(PacketIn2PropPacket)
	case NXPINT_FULL_LEN:
		p = new(PacketIn2PropFullLen)
	case NXPINT_BUFFER_ID:
		p = new(PacketIn2PropBufferID)
	case NXPINT_TABLE_ID:
		p = new(PacketIn2PropTableID)
	case NXPINT_COOKIE:
		p = new(PacketIn2PropCookie)
	case NXPINT_REASON:
		p = new(PacketIn2PropReason)
	case NXPINT_METADATA:
		p = new(PacketIn2PropMetadata)
	case NXPINT_USERDATA:
		p = new(PacketIn2PropUserdata)
	case NXPINT_CONTINUATION:
		p = new(PacketIn2PropContinuation)
	}
	err := p.UnmarshalBinary(data)
	if err != nil {
		return p, err
	}
	return p, nil
}

type PacketIn2 struct {
	Props []Property
}

func (p *PacketIn2) Len() (n uint16) {
	n = 0
	for _, prop := range p.Props {
		n += prop.Len()
	}
	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *PacketIn2) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0

	for _, prop := range p.Props {
		b, err := prop.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(prop.Len())
	}
	return
}

func (p *PacketIn2) UnmarshalBinary(data []byte) error {
	n := 0

	for n < len(data) {
		prop, err := DecodePacketIn2Prop(data[n:])
		if err != nil {
			break
		}
		p.Props = append(p.Props, prop)
		n += int(prop.Len())
	}

	return nil
}

func NewPacketIn2(props []Property) *VendorHeader {
	msg := NewNXTVendorHeader(Type_PacketIn2)
	msg.VendorData = &PacketIn2{
		Props: props,
	}
	return msg
}

type Resume struct {
	Props []Property
}

func (p *Resume) Len() (n uint16) {
	n = 0
	for _, prop := range p.Props {
		n += prop.Len()
	}
	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *Resume) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0

	for _, prop := range p.Props {
		b, err := prop.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(prop.Len())
	}
	return
}

func (p *Resume) UnmarshalBinary(data []byte) error {
	n := 0

	for n < len(data) {
		prop, err := DecodePacketIn2Prop(data[n:])
		if err != nil {
			break
		}
		p.Props = append(p.Props, prop)
		n += int(prop.Len())
	}
	return nil
}

func NewResume(props []Property) *VendorHeader {
	msg := NewNXTVendorHeader(Type_Resume)
	msg.VendorData = &Resume{
		Props: props,
	}
	return msg
}

func decodeVendorData(experimenterType uint32, data []byte) (msg util.Message, err error) {
	switch experimenterType {
	case Type_SetPacketInFormat:
		msg = new(PacketInFormat)
	case Type_SetControllerId:
		msg = new(ControllerID)
	case Type_TlvTableMod:
		msg = new(TLVTableMod)
	case Type_TlvTableReply:
		msg = new(TLVTableReply)
	case Type_BundleCtrl:
		msg = new(BundleControl)
	case Type_BundleAdd:
		msg = new(BundleAdd)
	case Type_PacketIn2:
		msg = new(PacketIn2)
	}
	err = msg.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return msg, err
}
