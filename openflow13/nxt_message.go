package openflow13

import (
	"encoding/binary"
	"errors"

	"github.com/contiv/libOpenflow/util"
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
	h := NewOfp13Header()
	h.Type = Type_Experimenter
	return &VendorHeader{
		Header:           h,
		Vendor:           NxExperimenterID,
		ExperimenterType: msgType,
	}
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

func decodeVendorData(experimenterType uint32, data []byte) (msg util.Message, err error) {
	switch experimenterType {
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
	}
	err = msg.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return msg, err
}
