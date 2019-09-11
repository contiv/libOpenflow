package openflow13

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type Uint16Message struct {
	data uint16
}

func newUint16Message(data uint16) *Uint16Message {
	return &Uint16Message{data: data}
}

func (m *Uint16Message) Len() uint16 {
	return 2
}

func (m *Uint16Message) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint16(data, m.data)
	return
}

func (m *Uint16Message) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("the byte array has wrong size to unmarshal Uint16Message")
	}
	m.data = binary.BigEndian.Uint16(data[:2])
	return nil
}

type Uint32Message struct {
	data uint32
}

func newUint32Message(data uint32) *Uint32Message {
	return &Uint32Message{data: data}
}

func (m *Uint32Message) Len() uint16 {
	return 4
}

func (m *Uint32Message) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint32(data, m.data)
	return
}

func (m *Uint32Message) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("the byte array has wrong size to unmarshal Uint16Message")
	}
	m.data = binary.BigEndian.Uint32(data[:4])
	return nil
}

type CTStates struct {
	data uint32
	mask uint32
}

func NewCTStates() *CTStates {
	return new(CTStates)
}

// ct_state = +new
func (s *CTStates) SetNew() {
	s.data |= 1 << 0
	s.mask |= 1 << 0
}

// ct_state = -new
func (s *CTStates) UnsetNew() {
	s.data |= 0 << NX_CT_STATE_NEW_OFS
	s.mask |= 1 << NX_CT_STATE_NEW_OFS
}

// ct_state = +est
func (s *CTStates) SetEst() {
	s.data |= 1 << NX_CT_STATE_EST_OFS
	s.mask |= 1 << NX_CT_STATE_EST_OFS
}

// ct_state = -est
func (s *CTStates) UnsetEst() {
	s.data |= 0 << NX_CT_STATE_EST_OFS
	s.mask |= 1 << NX_CT_STATE_EST_OFS
}

// ct_state = +rel
func (s *CTStates) SetRel() {
	s.data |= 1 << NX_CT_STATE_REL_OFS
	s.mask |= 1 << NX_CT_STATE_REL_OFS
}

// ct_state = -rel
func (s *CTStates) UnsetRel() {
	s.data |= 0 << NX_CT_STATE_REL_OFS
	s.mask |= 1 << NX_CT_STATE_REL_OFS
}

// ct_state = +rpl
func (s *CTStates) SetRpl() {
	s.data |= 1 << NX_CT_STATE_RPL_OFS
	s.mask |= 1 << NX_CT_STATE_RPL_OFS
}

// ct_state = -rpl
func (s *CTStates) UnsetRpl() {
	s.data |= 0 << NX_CT_STATE_RPL_OFS
	s.mask |= 1 << NX_CT_STATE_RPL_OFS
}

// ct_state = +inv
func (s *CTStates) SetInv() {
	s.data |= 1 << NX_CT_STATE_INV_OFS
	s.mask |= 1 << NX_CT_STATE_INV_OFS
}

// ct_state = -inv
func (s *CTStates) UnsetInv() {
	s.data |= 0 << NX_CT_STATE_INV_OFS
	s.mask |= 1 << NX_CT_STATE_INV_OFS
}

// ct_state = +trk
func (s *CTStates) SetTrk() {
	s.data |= 1 << NX_CT_STATE_TRK_OFS
	s.mask |= 1 << NX_CT_STATE_TRK_OFS
}

// ct_state = -trk
func (s *CTStates) UnsetTrk() {
	s.data |= 0 << NX_CT_STATE_TRK_OFS
	s.mask |= 1 << NX_CT_STATE_TRK_OFS
}

// ct_state = +snat
func (s *CTStates) SetSNAT() {
	s.data |= 1 << NX_CT_STATE_SNAT_OFS
	s.mask |= 1 << NX_CT_STATE_SNAT_OFS
}

// ct_state = -snat
func (s *CTStates) UnsetSNAT() {
	s.data |= 0 << NX_CT_STATE_SNAT_OFS
	s.mask |= 1 << NX_CT_STATE_SNAT_OFS
}

// ct_state = +dnat
func (s *CTStates) SetDNAT() {
	s.data |= 1 << NX_CT_STATE_DNAT_OFS
	s.mask |= 1 << NX_CT_STATE_DNAT_OFS
}

// ct_state = -dnat
func (s *CTStates) UnsetDNAT() {
	s.data |= 0 << NX_CT_STATE_DNAT_OFS
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

func NewRegMatchField(idx int, data uint32, dataRng *NXRange) *MatchField {
	var field *MatchField
	if dataRng != nil {
		field = newNXRegHeader(idx, true)
	} else {
		field = newNXRegHeader(idx, false)
	}

	field.Value = newUint32Message(data)

	if dataRng != nil {
		field.Mask = newUint32Message(dataRng.ToUint32Mask())
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
	if mask != nil {
		field, _ = FindFieldHeaderByName("NXM_NX_CT_MARK", true)
		field.Mask = newUint32Message(*mask)
	} else {
		field, _ = FindFieldHeaderByName("NXM_NX_CT_MARK", false)
	}
	field.Value = newUint32Message(mark)

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
	if mask != nil {
		field, _ = FindFieldHeaderByName("NXM_NX_CT_LABEL", true)
		field.Mask = newCTLabel(*mask)
	} else {
		field, _ = FindFieldHeaderByName("NXM_NX_CT_LABEL", false)
	}
	field.Value = newCTLabel(label)

	return field
}

func NewConjIDMatchField(conjID uint32) *MatchField {
	field, _ := FindFieldHeaderByName("NXM_NX_CONJ_ID", false)
	field.Value = newUint32Message(conjID)

	return field
}
