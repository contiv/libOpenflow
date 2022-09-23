package openflow15

// This file contains OFP 1.5 instruction defenitions

import (
	"encoding/binary"
	"errors"
	"fmt"

	"antrea.io/libOpenflow/util"

	"k8s.io/klog/v2"
)

// ofp_instruction_type 1.5
const (
	InstrType_GOTO_TABLE     = 1      /* Setup the next table in the lookup pipeline */
	InstrType_WRITE_METADATA = 2      /* Setup the metadata field for use later in pipeline */
	InstrType_WRITE_ACTIONS  = 3      /* Write the action(s) onto the datapath action set */
	InstrType_APPLY_ACTIONS  = 4      /* Applies the action(s) immediately */
	InstrType_CLEAR_ACTIONS  = 5      /* Clears all actions from the datapath action set */
	InstrType_DEPRECATED     = 6      /* Was Apply meter (rate limiter) */
	InstrType_STAT_TRIGGER   = 7      /* Statistics triggers */
	InstrType_EXPERIMENTER   = 0xFFFF /* Experimenter instruction */
)

// Generic instruction header
// ofp_instruction_header
type InstrHeader struct {
	Type   uint16
	Length uint16
}

type Instruction interface {
	util.Message
	AddAction(act Action, prepend bool) error
}

func (a *InstrHeader) Len() (n uint16) {
	return 4
}

func (a *InstrHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	binary.BigEndian.PutUint16(data[:2], a.Type)
	binary.BigEndian.PutUint16(data[2:4], a.Length)
	return
}

func (a *InstrHeader) UnmarshalBinary(data []byte) error {
	if len(data) != 4 {
		return errors.New("Wrong size to unmarshal an InstrHeader message.")
	}
	a.Type = binary.BigEndian.Uint16(data[:2])
	a.Length = binary.BigEndian.Uint16(data[2:4])
	return nil
}

func DecodeInstr(data []byte) (Instruction, error) {
	if len(data) < 2 {
		return nil, errors.New("data too short to decode Instruction")
	}
	t := binary.BigEndian.Uint16(data[:2])
	var a Instruction
	switch t {
	case InstrType_GOTO_TABLE:
		a = new(InstrGotoTable)
	case InstrType_WRITE_METADATA:
		a = new(InstrWriteMetadata)
	case InstrType_WRITE_ACTIONS:
		a = new(InstrActions)
	case InstrType_APPLY_ACTIONS:
		a = new(InstrActions)
	case InstrType_CLEAR_ACTIONS:
		a = new(InstrActions)
	case InstrType_DEPRECATED:
	case InstrType_STAT_TRIGGER:
	case InstrType_EXPERIMENTER:
	default:
		return nil, fmt.Errorf("unknown Instrheader type: %v", t)
	}

	err := a.UnmarshalBinary(data)
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal Instruction", "data", data)
		return nil, err
	}
	return a, nil
}

type InstrGotoTable struct {
	InstrHeader
	TableId uint8
	pad     []byte // 3 bytes
}

func (instr *InstrGotoTable) Len() (n uint16) {
	return 8
}

func (instr *InstrGotoTable) MarshalBinary() (data []byte, err error) {
	data, err = instr.InstrHeader.MarshalBinary()

	b := make([]byte, 4)
	b[0] = instr.TableId
	copy(b[3:], instr.pad)

	data = append(data, b...)
	return
}

func (instr *InstrGotoTable) UnmarshalBinary(data []byte) error {
	instr.InstrHeader.UnmarshalBinary(data[:4])

	instr.TableId = data[4]
	copy(instr.pad, data[5:8])

	return nil
}

func NewInstrGotoTable(tableId uint8) *InstrGotoTable {
	instr := new(InstrGotoTable)
	instr.Type = InstrType_GOTO_TABLE
	instr.TableId = tableId
	instr.pad = make([]byte, 3)
	instr.Length = instr.Len()

	return instr
}

func (instr *InstrGotoTable) AddAction(act Action, prepend bool) error {
	return errors.New("Not supported on this instrction")
}

type InstrWriteMetadata struct {
	InstrHeader
	pad          []byte // 4 bytes
	Metadata     uint64 /* Metadata value to write */
	MetadataMask uint64 /* Metadata write bitmask */
}

// FIXME: we need marshall/unmarshall/len/new functions for write metadata instr
func (instr *InstrWriteMetadata) Len() (n uint16) {
	return 24
}

func (instr *InstrWriteMetadata) MarshalBinary() (data []byte, err error) {
	data, err = instr.InstrHeader.MarshalBinary()

	b := make([]byte, 20)
	copy(b, instr.pad)
	binary.BigEndian.PutUint64(b[4:], instr.Metadata)
	binary.BigEndian.PutUint64(b[12:], instr.MetadataMask)

	data = append(data, b...)
	return
}

func (instr *InstrWriteMetadata) UnmarshalBinary(data []byte) error {
	instr.InstrHeader.UnmarshalBinary(data[:4])

	copy(instr.pad, data[4:8])
	instr.Metadata = binary.BigEndian.Uint64(data[8:16])
	instr.MetadataMask = binary.BigEndian.Uint64(data[16:24])

	return nil
}

func NewInstrWriteMetadata(metadata, metadataMask uint64) *InstrWriteMetadata {
	instr := new(InstrWriteMetadata)
	instr.Type = InstrType_WRITE_METADATA
	instr.pad = make([]byte, 4)
	instr.Metadata = metadata
	instr.MetadataMask = metadataMask
	instr.Length = instr.Len()

	return instr
}

func (instr *InstrWriteMetadata) AddAction(act Action, prepend bool) error {
	return errors.New("Not supported on this instrction")
}

// *_ACTION instructions
type InstrActions struct {
	InstrHeader
	pad     []byte   // 4 bytes
	Actions []Action /* 0 or more actions associated with OFPIT_WRITE_ACTIONS and OFPIT_APPLY_ACTIONS */
}

func (instr *InstrActions) Len() (n uint16) {
	n = 8

	for _, act := range instr.Actions {
		n += act.Len()
	}

	return
}

func (instr *InstrActions) MarshalBinary() (data []byte, err error) {
	data, err = instr.InstrHeader.MarshalBinary()

	b := make([]byte, 4)
	copy(b, instr.pad)
	data = append(data, b...)

	for _, act := range instr.Actions {
		b, err = act.MarshalBinary()
		data = append(data, b...)
	}

	return
}

func (instr *InstrActions) UnmarshalBinary(data []byte) error {
	instr.InstrHeader.UnmarshalBinary(data[:4])

	n := 8
	for n < int(instr.Length) {
		act, err := DecodeAction(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to decode InstrActions's Actions", "data", data[n:])
			return err
		}
		instr.Actions = append(instr.Actions, act)
		n += int(act.Len())
	}

	return nil
}

func (instr *InstrActions) AddAction(act Action, prepend bool) error {
	// Append or prepend to the list
	if prepend {
		instr.Actions = append([]Action{act}, instr.Actions...)
	} else {
		instr.Actions = append(instr.Actions, act)
	}

	instr.Length = instr.Len()
	return nil
}

func NewInstrWriteActions() *InstrActions {
	instr := new(InstrActions)
	instr.Type = InstrType_WRITE_ACTIONS
	instr.pad = make([]byte, 4)
	instr.Actions = make([]Action, 0)
	instr.Length = instr.Len()

	return instr
}

func NewInstrApplyActions() *InstrActions {
	instr := new(InstrActions)
	instr.Type = InstrType_APPLY_ACTIONS
	instr.pad = make([]byte, 4)
	instr.Actions = make([]Action, 0)
	instr.Length = instr.Len()

	return instr
}

// ofp_instruction_stat_trigger
type InstrStatTrigger struct {
	InstrHeader
	Flags      uint32
	Thresholds Stats
}

// ofp_stat_trigger_flags
const (
	STF_PERIODIC   = 1 << 0 /* Trigger for all multiples of thresholds. */
	STF_ONLY_FIRST = 1 << 1 /* Trigger on only first reach threshold. */
)

func NewInstrStatTrigger(flags uint32) *InstrStatTrigger {
	instr := new(InstrStatTrigger)
	instr.Type = InstrType_STAT_TRIGGER
	instr.Flags = flags
	instr.Length = instr.Len()

	return instr
}

func (instr *InstrStatTrigger) Len() (n uint16) {
	n = 8
	n += instr.Thresholds.Len()
	return
}

func (instr *InstrStatTrigger) MarshalBinary() (data []byte, err error) {
	data, err = instr.InstrHeader.MarshalBinary()
	if err != nil {
		return
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, instr.Flags)
	data = append(data, b...)

	b, err = instr.Thresholds.MarshalBinary()
	data = append(data, b...)

	return
}

func (instr *InstrStatTrigger) UnmarshalBinary(data []byte) error {
	instr.InstrHeader.UnmarshalBinary(data[:4])
	instr.Flags = binary.BigEndian.Uint32(data[4:8])
	err := instr.Thresholds.UnmarshalBinary(data[8:])
	if err != nil {
		klog.ErrorS(err, "Failed to marshal InstrStatTrigger's Thresholds", "data", data[8:])
		return err
	}
	return nil
}

func (instr *InstrStatTrigger) AddAction(act Action, prepend bool) error {
	return errors.New("Not supported on this instrction")
}
