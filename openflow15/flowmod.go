package openflow15

import (
	"encoding/binary"

	log "github.com/sirupsen/logrus"

	"antrea.io/libOpenflow/common"
)

// ofp_flow_mod
type FlowMod struct {
	common.Header
	Cookie     uint64
	CookieMask uint64

	TableId uint8 /* ID of the table to put the flow in */
	Command uint8 /* flowmod command */

	IdleTimeout uint16 /* Idle time before discarding (seconds). */
	HardTimeout uint16 /* Max time before discarding (seconds). */

	Priority uint16 /* Priority level of flow entry. */
	BufferId uint32 /* Buffered packet to apply to */

	OutPort    uint32
	OutGroup   uint32
	Flags      uint16
	Importance uint16

	Match        Match         // Fields to match
	Instructions []Instruction //  Instruction set - 0 or more.
}

func NewFlowMod() *FlowMod {
	f := new(FlowMod)
	f.Header = NewOfp15Header()
	f.Header.Type = Type_FlowMod
	// Add a generator for f.Cookie here
	f.Cookie = 0
	f.CookieMask = 0

	f.TableId = 0
	f.Command = FC_ADD

	f.IdleTimeout = 0
	f.HardTimeout = 0
	// Add a priority gen here
	f.Priority = 1000
	f.BufferId = 0xffffffff
	f.OutPort = P_ANY
	f.OutGroup = OFPG_ANY
	f.Flags = 0

	f.Match = *NewMatch()
	f.Instructions = make([]Instruction, 0)
	return f
}

func (f *FlowMod) AddInstruction(i Instruction) {
	f.Instructions = append(f.Instructions, i)
}

func (f *FlowMod) Len() (n uint16) {
	n = f.Header.Len()
	n += 40
	n += f.Match.Len()
	if f.Command == FC_DELETE || f.Command == FC_DELETE_STRICT {
		return
	}
	for _, v := range f.Instructions {
		n += v.Len()
	}
	return
}

func (f *FlowMod) MarshalBinary() (data []byte, err error) {
	f.Header.Length = f.Len()
	data, err = f.Header.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 40)
	n := 0
	binary.BigEndian.PutUint64(bytes[n:], f.Cookie)
	n += 8
	binary.BigEndian.PutUint64(bytes[n:], f.CookieMask)
	n += 8
	bytes[n] = f.TableId
	n += 1
	bytes[n] = f.Command
	n += 1
	binary.BigEndian.PutUint16(bytes[n:], f.IdleTimeout)
	n += 2
	binary.BigEndian.PutUint16(bytes[n:], f.HardTimeout)
	n += 2
	binary.BigEndian.PutUint16(bytes[n:], f.Priority)
	n += 2
	binary.BigEndian.PutUint32(bytes[n:], f.BufferId)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], f.OutPort)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], f.OutPort)
	n += 4
	binary.BigEndian.PutUint16(bytes[n:], f.Flags)
	n += 2
	binary.BigEndian.PutUint16(bytes[n:], f.Importance)
	n += 2
	data = append(data, bytes...)

	bytes, err = f.Match.MarshalBinary()
	if err != nil {
		return
	}
	data = append(data, bytes...)

	for _, instr := range f.Instructions {
		bytes, err = instr.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
		log.Debugf("flowmod instr: %v", bytes)
	}

	log.Debugf("Flowmod(%d): %v", len(data), data)
	return
}

func (f *FlowMod) UnmarshalBinary(data []byte) error {
	n := 0
	f.Header.UnmarshalBinary(data[n:])
	n += int(f.Header.Len())

	f.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8
	f.CookieMask = binary.BigEndian.Uint64(data[n:])
	n += 8
	f.TableId = data[n]
	n += 1
	f.Command = data[n]
	n += 1
	f.IdleTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	f.HardTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	f.Priority = binary.BigEndian.Uint16(data[n:])
	n += 2
	f.BufferId = binary.BigEndian.Uint32(data[n:])
	n += 4
	f.OutPort = binary.BigEndian.Uint32(data[n:])
	n += 4
	f.OutGroup = binary.BigEndian.Uint32(data[n:])
	n += 4
	f.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	f.Importance = binary.BigEndian.Uint16(data[n:])
	n += 2

	f.Match.UnmarshalBinary(data[n:])
	n += int(f.Match.Len())

	for n < int(f.Header.Length) {
		instr := DecodeInstr(data[n:])
		f.Instructions = append(f.Instructions, instr)
		n += int(instr.Len())
	}
	return nil
}

// ofp_flow_mod_command 1.5
const (
	FC_ADD = iota // OFPFC_ADD = 0
	FC_MODIFY
	FC_MODIFY_STRICT
	FC_DELETE
	FC_DELETE_STRICT
)

// ofp_flow_mod_flags 1.5
const (
	FF_SEND_FLOW_REM = 1 << 0 /* Send flow removed message when flow expires or is deleted. */
	FF_CHECK_OVERLAP = 1 << 1 /* Check for overlapping entries first */
	FF_RESET_COUNTS  = 1 << 2 /* Reset flow packet and byte counts */
	FF_NO_PKT_COUNTS = 1 << 3 /* Don’t keep track of packet count */
	FF_NO_BYT_COUNTS = 1 << 4 /* Don’t keep track of byte count */
)

// ofp_flow_removed
type FlowRemoved struct {
	common.Header
	TableId  uint8
	Reason   uint8
	Priority uint16

	IdleTimeout uint16
	HardTimeout uint16
	Cookie      uint64

	Match Match
	Stats
}

func NewFlowRemoved() *FlowRemoved {
	f := new(FlowRemoved)
	f.Header = NewOfp15Header()
	f.Header.Type = Type_FlowRemoved
	f.Match = *NewMatch()
	f.Stats = *NewStats() //OXS_OF_DURATION is mandatory
	return f
}

func (f *FlowRemoved) Len() (n uint16) {
	n = f.Header.Len()
	n += 16
	n += f.Match.Len()
	n += f.Stats.Len()
	return
}

func (f *FlowRemoved) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(f.Len()))
	n := 0

	f.Header.Length = f.Len()
	bytes, err := f.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], bytes)
	n += int(f.Header.Len())

	data[n] = f.TableId
	n += 1

	data[n] = f.Reason
	n += 1

	binary.BigEndian.PutUint16(data[n:], f.Priority)
	n += 2

	binary.BigEndian.PutUint16(data[n:], f.IdleTimeout)
	n += 2
	binary.BigEndian.PutUint16(data[n:], f.HardTimeout)
	n += 2

	binary.BigEndian.PutUint64(data[n:], f.Cookie)
	n += 8

	bytes, err = f.Match.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], bytes)
	n += int(f.Match.Len())

	var b []byte
	b, err = f.Stats.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)

	return
}

func (f *FlowRemoved) UnmarshalBinary(data []byte) error {
	n := 0
	var err error
	err = f.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(f.Header.Len())

	f.TableId = data[n]
	n += 1
	f.Reason = data[n]
	n += 1
	f.Priority = binary.BigEndian.Uint16(data[n:])
	n += 2

	f.IdleTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	f.HardTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2

	f.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8

	err = f.Match.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(f.Match.Len())

	err = f.Stats.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(f.Stats.Len())

	return err
}

// ofp_flow_removed_reason
const (
	RR_IDLE_TIMEOUT    = iota /* Flow idle time exceeded idle_timeout. */
	RR_HARD_TIMEOUT           /* Time exceeded hard_timeout. */
	RR_DELETE                 /* Evicted by a DELETE flow mod. */
	RR_GROUP_DELETE           /* Group was removed. */
	OFPRR_METER_DELETE        /* Meter was removed. */
	OFPRR_EVICTION            /* Switch eviction to free resources. */
)
