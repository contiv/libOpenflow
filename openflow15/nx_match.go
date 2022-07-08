package openflow15

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type Uint16Message struct {
	Data uint16
}

func newUint16Message(data uint16) *Uint16Message {
	return &Uint16Message{Data: data}
}

func (m *Uint16Message) Len() uint16 {
	return 2
}

func (m *Uint16Message) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint16(data, m.Data)
	return
}

func (m *Uint16Message) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("the []byte is too short to unmarshal a full Uint16Message")
	}
	m.Data = binary.BigEndian.Uint16(data[:2])
	return nil
}

type Uint32Message struct {
	Data uint32
}

func newUint32Message(data uint32) *Uint32Message {
	return &Uint32Message{Data: data}
}

func (m *Uint32Message) Len() uint16 {
	return 4
}

func (m *Uint32Message) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint32(data, m.Data)
	return
}

func (m *Uint32Message) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("the []byte is too short to unmarshal a full Uint32Message")
	}
	m.Data = binary.BigEndian.Uint32(data[:4])
	return nil
}

type ByteArrayField struct {
	Data   []byte
	Length uint8
}

// Len returns the length of ByteArrayField. The length of ByteArrayField should be multiple of 8 byte.
func (m *ByteArrayField) Len() uint16 {
	return uint16(m.Length)
}

func (m *ByteArrayField) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	copy(data, m.Data)
	return
}

func (m *ByteArrayField) UnmarshalBinary(data []byte) error {
	expectLength := m.Len()
	if len(data) < int(expectLength) {
		return errors.New("The byte array has wrong size to unmarshal ByteArrayField message")
	}
	m.Data = data[:expectLength]
	return nil
}

type CTStates struct {
	data uint32
	mask uint32
}

func NewCTStates() *CTStates {
	return new(CTStates)
}

// SetNew sets ct_state as "+new".
func (s *CTStates) SetNew() {
	s.data |= 1 << 0
	s.mask |= 1 << 0
}

// UnsetNew sets ct_state as "-new".
func (s *CTStates) UnsetNew() {
	s.data &^= 1 << NX_CT_STATE_NEW_OFS
	s.mask |= 1 << NX_CT_STATE_NEW_OFS
}

// SetEst sets ct_state as "+est".
func (s *CTStates) SetEst() {
	s.data |= 1 << NX_CT_STATE_EST_OFS
	s.mask |= 1 << NX_CT_STATE_EST_OFS
}

// UnsetEst sets ct_state as "-est".
func (s *CTStates) UnsetEst() {
	s.data &^= 1 << NX_CT_STATE_EST_OFS
	s.mask |= 1 << NX_CT_STATE_EST_OFS
}

// SetRel sets ct_state as "+rel".
func (s *CTStates) SetRel() {
	s.data |= 1 << NX_CT_STATE_REL_OFS
	s.mask |= 1 << NX_CT_STATE_REL_OFS
}

// UnsetRel sets ct_state as "-rel".
func (s *CTStates) UnsetRel() {
	s.data &^= 1 << NX_CT_STATE_REL_OFS
	s.mask |= 1 << NX_CT_STATE_REL_OFS
}

// SetRpl sets ct_state as "+rpl".
func (s *CTStates) SetRpl() {
	s.data |= 1 << NX_CT_STATE_RPL_OFS
	s.mask |= 1 << NX_CT_STATE_RPL_OFS
}

// UnsetRpl sets ct_state as "-rpl".
func (s *CTStates) UnsetRpl() {
	s.data &^= 1 << NX_CT_STATE_RPL_OFS
	s.mask |= 1 << NX_CT_STATE_RPL_OFS
}

// SetInv sets ct_state as "+inv".
func (s *CTStates) SetInv() {
	s.data |= 1 << NX_CT_STATE_INV_OFS
	s.mask |= 1 << NX_CT_STATE_INV_OFS
}

// UnsetInv sets ct_state as "-inv".
func (s *CTStates) UnsetInv() {
	s.data &^= 1 << NX_CT_STATE_INV_OFS
	s.mask |= 1 << NX_CT_STATE_INV_OFS
}

// SetTrk sets ct_state as "+trk".
func (s *CTStates) SetTrk() {
	s.data |= 1 << NX_CT_STATE_TRK_OFS
	s.mask |= 1 << NX_CT_STATE_TRK_OFS
}

// UnsetTrk sets ct_state as "-trk".
func (s *CTStates) UnsetTrk() {
	s.data &^= 1 << NX_CT_STATE_TRK_OFS
	s.mask |= 1 << NX_CT_STATE_TRK_OFS
}

// SetSNAT sets ct_state as "+snat".
func (s *CTStates) SetSNAT() {
	s.data |= 1 << NX_CT_STATE_SNAT_OFS
	s.mask |= 1 << NX_CT_STATE_SNAT_OFS
}

// UnsetSNAT sets ct_state as "-snat".
func (s *CTStates) UnsetSNAT() {
	s.data &^= 1 << NX_CT_STATE_SNAT_OFS
	s.mask |= 1 << NX_CT_STATE_SNAT_OFS
}

// SetDNAT sets ct_state as "+dnat".
func (s *CTStates) SetDNAT() {
	s.data |= 1 << NX_CT_STATE_DNAT_OFS
	s.mask |= 1 << NX_CT_STATE_DNAT_OFS
}

// UnsetDNAT sets ct_state as "-dnat".
func (s *CTStates) UnsetDNAT() {
	s.data &^= 1 << NX_CT_STATE_DNAT_OFS
	s.mask |= 1 << NX_CT_STATE_DNAT_OFS
}

type NXRange struct {
	start int
	end   int
}

func newNXRegHeader(idx int, hasMask bool) *MatchField {
	idKey := fmt.Sprintf("NXM_NX_REG%d", idx)
	header, _ := FindFieldHeaderByName(idKey, hasMask)
	return header
}

// This function will generate a MatchField with continuous reg mask according
// to dataRng. We may need to use NewRegMatchFieldWithMask if we want a discontinuous
// reg mask, such as, 0x5.
func NewRegMatchField(idx int, data uint32, dataRng *NXRange) *MatchField {
	var field *MatchField
	field = newNXRegHeader(idx, dataRng != nil)

	field.Value = newUint32Message(data)
	if dataRng != nil {
		field.Mask = newUint32Message(dataRng.ToUint32Mask())
	}
	return field
}

// This function will generate a MatchField with data/mask for Reg[idx]. The mask can
// be arbitrary bitwise, including continuous mask, such as, 0x7 and discontinous
// mask, such as, 0x5.
func NewRegMatchFieldWithMask(idx int, data uint32, mask uint32) *MatchField {
	var field *MatchField
	field = newNXRegHeader(idx, mask != 0)

	field.Value = newUint32Message(data)
	if mask != 0 {
		field.Mask = newUint32Message(mask)
	}
	return field
}

func newNXTunMetadataHeader(idx int, hasMask bool) *MatchField {
	idKey := fmt.Sprintf("NXM_NX_TUN_METADATA%d", idx)
	header, _ := FindFieldHeaderByName(idKey, hasMask)
	return header
}

func NewTunMetadataField(idx int, data []byte, mask []byte) *MatchField {
	var field *MatchField
	field = newNXTunMetadataHeader(idx, len(mask) > 0)

	field.Value = &ByteArrayField{
		Data:   data,
		Length: uint8(len(data)),
	}
	field.Length = uint8(len(data))
	if len(mask) > 0 {
		field.Mask = &ByteArrayField{
			Data:   mask,
			Length: uint8(len(mask)),
		}
		field.Length += uint8(len(mask))
	}
	return field
}

func NewCTStateMatchField(states *CTStates) *MatchField {
	field, _ := FindFieldHeaderByName("NXM_NX_CT_STATE", true)
	field.Value = newUint32Message(states.data)
	field.Mask = newUint32Message(states.mask)
	return field
}

func NewCTZoneMatchField(zone uint16) *MatchField {
	field, _ := FindFieldHeaderByName("NXM_NX_CT_ZONE", false)
	field.Value = newUint16Message(zone)
	return field
}

func NewCTMarkMatchField(mark uint32, mask *uint32) *MatchField {
	var field *MatchField
	field, _ = FindFieldHeaderByName("NXM_NX_CT_MARK", mask != nil)

	field.Value = newUint32Message(mark)
	if mask != nil {
		field.Mask = newUint32Message(*mask)
	}

	return field
}

type CTLabel struct {
	data [16]byte
}

func (m *CTLabel) Len() uint16 {
	return uint16(len(m.data))
}

func (m *CTLabel) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	copy(data, m.data[:])
	err = nil
	return
}

func (m *CTLabel) UnmarshalBinary(data []byte) error {
	m.data = [16]byte{}
	if len(data) < len(m.data) {
		copy(m.data[:], data)
	} else {
		copy(m.data[:], data[:16])
	}
	return nil
}

func newCTLabel(data [16]byte) *CTLabel {
	label := new(CTLabel)
	_ = label.UnmarshalBinary(data[:16])
	return label
}

func NewCTLabelMatchField(label [16]byte, mask *[16]byte) *MatchField {
	var field *MatchField
	field, _ = FindFieldHeaderByName("NXM_NX_CT_LABEL", mask != nil)

	field.Value = newCTLabel(label)
	if mask != nil {
		field.Mask = newCTLabel(*mask)
	}

	return field
}

func NewConjIDMatchField(conjID uint32) *MatchField {
	field, _ := FindFieldHeaderByName("NXM_NX_CONJ_ID", false)
	field.Value = newUint32Message(conjID)

	return field
}

func NewNxARPShaMatchField(addr net.HardwareAddr, mask net.HardwareAddr) *MatchField {
	var field *MatchField
	field, _ = FindFieldHeaderByName("NXM_NX_ARP_SHA", mask != nil)

	field.Value = &ArpXHaField{ArpHa: addr}
	if mask != nil {
		field.Mask = &ArpXHaField{ArpHa: mask}
	}

	return field
}

func NewNxARPThaMatchField(addr net.HardwareAddr, mask net.HardwareAddr) *MatchField {
	var field *MatchField
	field, _ = FindFieldHeaderByName("NXM_NX_ARP_THA", mask != nil)

	field.Value = &ArpXHaField{ArpHa: addr}
	if mask != nil {
		field.Mask = &ArpXHaField{ArpHa: mask}
	}

	return field
}

func NewNxARPSpaMatchField(addr net.IP, mask net.IP) *MatchField {
	var field *MatchField
	field, _ = FindFieldHeaderByName("NXM_OF_ARP_SPA", mask != nil)

	field.Value = &ArpXPaField{ArpPa: addr}
	if mask != nil {
		field.Mask = &ArpXPaField{ArpPa: mask}
	}

	return field
}

func NewNxARPTpaMatchField(addr net.IP, mask net.IP) *MatchField {
	var field *MatchField
	field, _ = FindFieldHeaderByName("NXM_OF_ARP_TPA", mask != nil)

	field.Value = &ArpXPaField{ArpPa: addr}
	if mask != nil {
		field.Mask = &ArpXPaField{ArpPa: mask}
	}

	return field
}
