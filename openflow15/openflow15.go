package openflow15

// Package openflow15 provides OpenFlow 1.5 structs along with Read
// and Write methods for each.
// OpenFlow Wire Protocol 0x06
//
// Struct documentation is taken from the OpenFlow Switch
// Specification Version 1.5
// url https://opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.5.1.pdf

import (
	"encoding/binary"
	"errors"
	"net"

	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/util"
)

const (
	VERSION = 6
)

// Returns a new OpenFlow header with version field set to v1.5.
var NewOfp15Header func() common.Header = common.NewHeaderGenerator(VERSION)

// Echo request/reply messages can be sent from either the
// switch or the controller, and must return an echo reply. They
// can be used to indicate the latency, bandwidth, and/or
// liveness of a controller-switch connection.
func NewEchoRequest() *common.Header {
	h := NewOfp15Header()
	h.Type = Type_EchoRequest
	return &h
}

// Echo request/reply messages can be sent from either the
// switch or the controller, and must return an echo reply. They
// can be used to indicate the latency, bandwidth, and/or
// liveness of a controller-switch connection.
func NewEchoReply() *common.Header {
	h := NewOfp15Header()
	h.Type = Type_EchoReply
	return &h
}

// ofp_type 1.5
const (
	/* Immutable messages. */
	Type_Hello        = 0
	Type_Error        = 1
	Type_EchoRequest  = 2
	Type_EchoReply    = 3
	Type_Experimenter = 4

	/* Switch configuration messages. */
	Type_FeaturesRequest  = 5
	Type_FeaturesReply    = 6
	Type_GetConfigRequest = 7
	Type_GetConfigReply   = 8
	Type_SetConfig        = 9

	/* Asynchronous messages. */
	Type_PacketIn    = 10
	Type_FlowRemoved = 11
	Type_PortStatus  = 12

	/* Controller command messages. */
	Type_PacketOut = 13
	Type_FlowMod   = 14
	Type_GroupMod  = 15
	Type_PortMod   = 16
	Type_TableMod  = 17

	/* Multipart messages. */
	Type_MultiPartRequest = 18
	Type_MultiPartReply   = 19

	/* Barrier messages. */
	Type_BarrierRequest = 20
	Type_BarrierReply   = 21

	/* Controller role change request messages. */
	Type_RoleRequest = 24
	Type_RoleReply   = 25

	/* Asynchronous message configuration. */
	Type_GetAsyncRequest = 26
	Type_GetAsyncReply   = 27
	Type_SetAsync        = 28

	/* Meters and rate limiters configuration messages. */
	Type_MeterMod = 29

	/* Controller role change event messages. */
	Type_RoleStatus = 30

	/* Asynchronous messages. */
	Type_TableStatus = 31

	/* Request forwarding by the switch. */
	Type_RequestForward = 32

	/* Bundle operations (multiple messages as a single operation). */
	Type_BundleControl    = 33
	Type_BundleAddMessage = 34

	/* Controller Status async message. */
	Type_ControllerStatus = 35
)

func Parse(b []byte) (message util.Message, err error) {
	klog.V(4).InfoS("Openflow15 parse", "bytes", b)
	switch b[1] {
	case Type_Error:
		errMsg := new(ErrorMsg)
		err = errMsg.UnmarshalBinary(b)
		if err != nil {
			return
		}
		switch errMsg.Type {
		case ET_EXPERIMENTER:
			message = new(VendorError)
			err = message.UnmarshalBinary(b)
		default:
			message = errMsg
		}
		return
	case Type_Hello:
		message = new(common.Hello)
	case Type_EchoRequest:
		message = new(common.Header)
	case Type_EchoReply:
		message = new(common.Header)
	case Type_Experimenter:
		message = new(VendorHeader)
	case Type_FeaturesRequest:
		message = NewFeaturesRequest()
	case Type_FeaturesReply:
		message = NewFeaturesReply()
	case Type_GetConfigRequest:
		message = new(common.Header)
	case Type_GetConfigReply:
		message = NewGetConfigReply()
	case Type_SetConfig:
		message = NewSetConfig()
	case Type_PacketIn:
		message = NewPacketIn()
	case Type_FlowRemoved:
		message = NewFlowRemoved()
	case Type_PortStatus:
		message = NewPortStatus()
	case Type_PacketOut:
		message = NewPacketOut()
	case Type_FlowMod:
		message = NewFlowMod()
	case Type_GroupMod:
		message = NewGroupMod()
	case Type_PortMod:
		message = NewPortMod(0)
	case Type_TableMod:
		message = NewTableMod()
	case Type_BarrierRequest:
		message = new(common.Header)
	case Type_BarrierReply:
		message = new(common.Header)
	case Type_MultiPartRequest:
		message = new(MultipartRequest)
	case Type_MultiPartReply:
		message = new(MultipartReply)
	case Type_RoleRequest:
		message = NewRoleRequest()
	case Type_RoleReply:
		message = NewRoleReply()
	case Type_GetAsyncRequest:
		message = NewGetAsyncRequest()
	case Type_GetAsyncReply:
		message = NewGetAsyncReply()
	case Type_SetAsync:
		message = NewSetAsync()
	case Type_MeterMod:
		message = NewMeterMod()
	case Type_TableStatus:
		message = NewTableStatus()
	case Type_RequestForward:
		message = NewRequestForward()
	case Type_BundleControl:
		message = NewBundleCtrl(0, 0, 0)
	case Type_BundleAddMessage:
		message = NewBndleAdd(0, 0)
	case Type_ControllerStatus:
		message = NewControllerStatusHeader()
	default:
		return nil, errors.New("An unknown v1.5 packet type was received. Parse function will discard data.")
	}
	if message != nil {
		err = message.UnmarshalBinary(b)
	}
	klog.V(4).InfoS("Parsing result", "error", err, "message", message)
	return
}

type PacketOut struct {
	common.Header
	BufferId   uint32
	ActionsLen uint16
	pad        []byte
	Match      Match
	Actions    []Action
	Data       util.Message
}

func NewPacketOut() *PacketOut {
	p := new(PacketOut)
	p.Header = NewOfp15Header()
	p.Header.Type = Type_PacketOut
	p.BufferId = 0xffffffff
	p.ActionsLen = 0
	p.pad = make([]byte, 2)
	p.Match = *NewMatch()
	p.Actions = make([]Action, 0)
	p.Data = util.NewBuffer(make([]byte, 0))
	return p
}

func (p *PacketOut) AddAction(act Action) {
	p.Actions = append(p.Actions, act)
	p.ActionsLen += act.Len()
}

func (p *PacketOut) Len() (n uint16) {
	n += p.Header.Len()
	n += 8 /* buffer_id, actions_len, pad[2] */
	n += p.Match.Len()
	for _, a := range p.Actions {
		n += a.Len()
	}
	if p.Data != nil {
		n += p.Data.Len()
	}
	return
}

func (p *PacketOut) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	var b []byte
	n := 0

	p.Header.Length = p.Len()
	b, err = p.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)

	binary.BigEndian.PutUint32(data[n:], p.BufferId)
	n += 4
	binary.BigEndian.PutUint16(data[n:], p.ActionsLen)
	n += 2

	n += 2 /* for pad */

	b, err = p.Match.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += int(p.Match.Len())

	for _, a := range p.Actions {
		b, err = a.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += len(b)
	}

	if p.Data != nil {
		b, err = p.Data.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += len(b)
	}
	return
}

func (p *PacketOut) UnmarshalBinary(data []byte) (err error) {
	err = p.Header.UnmarshalBinary(data)
	if err != nil {
		return
	}
	n := p.Header.Len()

	p.BufferId = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.ActionsLen = binary.BigEndian.Uint16(data[n:])
	n += 2

	n += 2 // for pad

	if err = p.Match.UnmarshalBinary(data[n:]); err != nil {
		klog.ErrorS(err, "Failed to unmarshal PacketOut's Match", "data", data[n:])
		return err
	}
	n += p.Match.Len()
	a := n
	for n < (a + p.ActionsLen) {
		a, err := DecodeAction(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to decode PacketOut's Actions", "data", data[n:])
			return err
		}
		p.Actions = append(p.Actions, a)
		n += a.Len()
	}

	err = p.Data.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal PacketOut's Data", "data", data[n:])
	}
	return err
}

// ofp_packet_in 1.5 (same as 1.3)
type PacketIn struct {
	common.Header
	BufferId uint32
	TotalLen uint16
	Reason   uint8
	TableId  uint8
	Cookie   uint64
	Match    Match
	pad      []uint8
	Data     util.Message
}

func NewPacketIn() *PacketIn {
	p := new(PacketIn)
	p.Header = NewOfp15Header()
	p.Header.Type = Type_PacketIn
	p.BufferId = 0xffffffff
	p.TotalLen = 0
	p.Reason = 0
	p.TableId = 0
	p.Cookie = 0
	p.Match = *NewMatch()
	p.pad = make([]byte, 2)
	p.Data = util.NewBuffer(make([]byte, 0))
	return p
}

func (p *PacketIn) Len() (n uint16) {
	n += p.Header.Len()
	n += 16 /* buffer_id, total_len, reason, table_id, cookie */
	n += p.Match.Len()
	n += 2 /* pad */
	n += p.Data.Len()
	return
}

func (p *PacketIn) MarshalBinary() (data []byte, err error) {
	p.Header.Length = p.Len()
	data, err = p.Header.MarshalBinary()
	if err != nil {
		return
	}

	b := make([]byte, 16)
	n := 0
	binary.BigEndian.PutUint32(b, p.BufferId)
	n += 4
	binary.BigEndian.PutUint16(b[n:], p.TotalLen)
	n += 2
	b[n] = p.Reason
	n += 1
	b[n] = p.TableId
	n += 1
	binary.BigEndian.PutUint64(b[n:], p.Cookie)
	n += 8
	data = append(data, b...)

	b, err = p.Match.MarshalBinary()
	if err != nil {
		return
	}
	data = append(data, b...)

	b = make([]byte, 2)
	copy(b[0:], p.pad)
	data = append(data, b...)

	b, err = p.Data.MarshalBinary()
	if err != nil {
		return
	}
	data = append(data, b...)
	return
}

func (p *PacketIn) UnmarshalBinary(data []byte) error {
	err := p.Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	n := p.Header.Len()

	p.BufferId = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.TotalLen = binary.BigEndian.Uint16(data[n:])
	n += 2
	p.Reason = data[n]
	n += 1
	p.TableId = data[n]
	n += 1
	p.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8

	if err := p.Match.UnmarshalBinary(data[n:]); err != nil {
		klog.ErrorS(err, "Failed to unmarshal PacketIn's Match", "data", data[n:])
		return err
	}
	n += p.Match.Len()

	copy(p.pad, data[n:])
	n += 2

	err = p.Data.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal PacketIn's Data", "data", data[n:])
	}
	return err
}

// ofp_packet_in_reason 1.5
const (
	R_TABLE_MISS   = iota /* No matching flow (table-miss flow entry). */
	R_APPLY_ACTION        /* Output to controller in apply-actions. */
	R_INVALID_TTL         /* Packet has invalid TTL */
	R_ACTION_SET          /* Output to controller in action set. */
	R_GROUP               /* Output to controller in group bucket. */
	R_PACKET_OUT          /* Output to controller in packet-out. */
)

func NewConfigRequest() *common.Header {
	h := NewOfp15Header()
	h.Type = Type_GetConfigRequest
	return &h
}

// ofp_config_flags 1.5
const (
	C_FRAG_NORMAL = 0
	C_FRAG_DROP   = 1
	C_FRAG_REASM  = 2
	C_FRAG_MASK   = 3
)

// ofp_switch_config 1.5
type SwitchConfig struct {
	common.Header
	Flags       uint16 // OFPC_* flags
	MissSendLen uint16
}

func NewSetConfig() *SwitchConfig {
	c := new(SwitchConfig)
	c.Header = NewOfp15Header()
	c.Header.Type = Type_SetConfig
	c.Flags = 0
	c.MissSendLen = 0
	return c
}

func NewGetConfigReply() *SwitchConfig {
	c := new(SwitchConfig)
	c.Header = NewOfp15Header()
	c.Header.Type = Type_GetConfigReply
	c.Flags = 0
	c.MissSendLen = 0
	return c
}

func (c *SwitchConfig) Len() (n uint16) {
	n = c.Header.Len()
	n += 4
	return
}

func (c *SwitchConfig) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(c.Len()))
	var bytes []byte
	n := 0

	c.Header.Length = c.Len()
	bytes, err = c.Header.MarshalBinary()
	copy(data[n:], bytes)
	n += len(bytes)
	binary.BigEndian.PutUint16(data[n:], c.Flags)
	n += 2
	binary.BigEndian.PutUint16(data[n:], c.MissSendLen)
	n += 2
	return
}

func (c *SwitchConfig) UnmarshalBinary(data []byte) error {
	var err error
	n := 0

	err = c.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(c.Header.Len())
	c.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	c.MissSendLen = binary.BigEndian.Uint16(data[n:])
	n += 2
	return err
}

type ErrorMsg struct {
	common.Header
	Type uint16
	Code uint16
	Data util.Buffer
}

func NewErrorMsg() *ErrorMsg {
	e := new(ErrorMsg)
	e.Header = NewOfp15Header()
	e.Header.Type = Type_Error
	e.Data = *util.NewBuffer(make([]byte, 0))
	return e
}

func (e *ErrorMsg) Len() (n uint16) {
	n = e.Header.Len()
	n += 2
	n += 2
	n += e.Data.Len()
	return
}

func (e *ErrorMsg) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(e.Len()))
	n := 0

	e.Header.Length = e.Len()

	bytes, err := e.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], bytes)
	n += len(bytes)

	binary.BigEndian.PutUint16(data[n:], e.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], e.Code)
	n += 2

	bytes, err = e.Data.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], bytes)
	n += len(bytes)
	return
}

func (e *ErrorMsg) UnmarshalBinary(data []byte) error {
	n := 0
	err := e.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(e.Header.Len())

	if len(data) < int(e.Header.Length) || len(data) < int(n)+4 {
		return errors.New("data too short to unmarshal ErrorMsg")
	}
	e.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	e.Code = binary.BigEndian.Uint16(data[n:])
	n += 2

	err = e.Data.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal ErrorMsg's Data", "data", data[n:])
		return err
	}
	n += int(e.Data.Len())
	return nil
}

// ofp_error_type 1.5
const (
	ET_HELLO_FAILED          = 0      /* Hello protocol failed. */
	ET_BAD_REQUEST           = 1      /* Request was not understood. */
	ET_BAD_ACTION            = 2      /* Error in action description. */
	ET_BAD_INSTRUCTION       = 3      /* Error in instruction list. */
	PET_BAD_MATCH            = 4      /* Error in match. */
	ET_FLOW_MOD_FAILED       = 5      /* Problem modifying flow entry. */
	ET_GROUP_MOD_FAILED      = 6      /* Problem modifying group entry. */
	ET_PORT_MOD_FAILED       = 7      /* Port mod request failed. */
	ET_TABLE_MOD_FAILED      = 8      /* Table mod request failed. */
	ET_QUEUE_OP_FAILED       = 9      /* Queue operation failed. */
	ET_SWITCH_CONFIG_FAILED  = 10     /* Switch config request failed. */
	ET_ROLE_REQUEST_FAILED   = 11     /* Controller Role request failed. */
	ET_METER_MOD_FAILED      = 12     /* Error in meter. */
	ET_TABLE_FEATURES_FAILED = 13     /* Setting table features failed. */
	ET_BAD_PROPERTY          = 14     /* Some property is invalid. */
	ET_ASYNC_CONFIG_FAILED   = 15     /* Asynchronous config request failed. */
	ET_FLOW_MONITOR_FAILED   = 16     /* Setting flow monitor failed. */
	ET_BUNDLE_FAILED         = 17     /* Bundle operation failed. */
	ET_EXPERIMENTER          = 0xffff /* Experimenter error messages. */
)

// ofp_hello_failed_code 1.5
const (
	HFC_INCOMPATIBLE = iota
	HFC_EPERM
)

// ofp_bad_request_code 1.5
const (
	BRC_BAD_VERSION = iota
	BRC_BAD_TYPE
	BRC_BAD_MULTIPART
	BRC_BAD_EXPERIMENTER

	BRC_BAD_EXP_TYPE
	BRC_EPERM
	BRC_BAD_LEN
	BRC_BUFFER_EMPTY
	BRC_BUFFER_UNKNOWN
	BRC_BAD_TABLE_ID
	BRC_IS_SLAVE
	BRC_BAD_PORT
	BRC_BAD_PACKET
	BRC_MULTIPART_BUFFER_OVERFLOW
	BRC_MULTIPART_REQUEST_TIMEOUT
	BRC_MULTIPART_REPLY_TIMEOUT
	BRC_MULTIPART_BAD_SCHED
	BRC_PIPELINE_FIELDS_ONLY
	BRC_UNKNOWN
)

// ofp_bad_action_code 1.5
const (
	BAC_BAD_TYPE = iota
	BAC_BAD_LEN
	BAC_BAD_EXPERIMENTER
	BAC_BAD_EXP_TYPE
	BAC_BAD_OUT_PORT
	BAC_BAD_ARGUMENT
	BAC_EPERM
	BAC_TOO_MANY
	BAC_BAD_QUEUE
	BAC_BAD_OUT_GROUP
	BAC_MATCH_INCONSISTENT
	BAC_UNSUPPORTED_ORDER
	BAC_BAD_TAG
	BAC_BAD_SET_TYPE
	BAC_BAD_SET_LEN
	BAC_BAD_SET_ARGUMENT
	BAC_BAD_SET_MASK
	BAC_BAD_METER
)

// ofp_bad_instruction_code 1.5
const (
	BIC_UNKNOWN_INST = iota
	BIC_UNSUP_INST
	BIC_BAD_TABLE_ID
	BIC_UNSUP_METADATA
	BIC_UNSUP_METADATA_MASK
	BIC_BAD_EXPERIMENTER
	BIC_BAD_EXP_TYPE
	BIC_BAD_LEN
	BIC_EPERM
	BIC_DUP_INST
)

// ofp_bad_match_code 1.5
const (
	BMC_BAD_TYPE = iota
	BMC_BAD_LEN
	BMC_BAD_TAG
	BMC_BAD_DL_ADDR_MASK
	BMC_BAD_NW_ADDR_MASK
	BMC_BAD_WILDCARDS
	BMC_BAD_FIELD
	BMC_BAD_VALUE
	BMC_BAD_MASK
	BMC_BAD_PREREQ
	BMC_DUP_FIELD
	BMC_EPERM
)

// ofp_flow_mod_failed_code 1.5
const (
	FMFC_UNKNOWN = iota
	FMFC_TABLE_FULL
	FMFC_BAD_TABLE_ID
	FMFC_OVERLAP
	FMFC_EPERM
	FMFC_BAD_TIMEOUT
	FMFC_BAD_COMMAND
	FMFC_BAD_FLAGS
	OFPFMFC_CANT_SYNC
	FMFC_BAD_PRIORITY
	FMFC_IS_SYNC
)

// ofp_group_mod_failed_code 1.5
const (
	GMFC_GROUP_EXISTS = iota
	GMFC_INVALID_GROUP
	GMFC_WEIGHT_UNSUPPORTED
	GMFC_OUT_OF_GROUPS
	GMFC_OUT_OF_BUCKETS
	GMFC_CHAINING_UNSUPPORTED
	GMFC_WATCH_UNSUPPORTED
	GMFC_LOOP
	GMFC_UNKNOWN_GROUP
	GMFC_CHAINED_GROUP
	GMFC_BAD_TYPE
	GMFC_BAD_COMMAND
	GMFC_BAD_BUCKET
	GMFC_BAD_WATCH
	GMFC_EPERM
	GMFC_UNKNOWN_BUCKET
	GMFC_BUCKET_EXISTS
)

// ofp_port_mod_failed_code 1.5
const (
	PMFC_BAD_PORT = iota
	PMFC_BAD_HW_ADDR
	PMFC_BAD_CONFIG
	PMFC_BAD_ADVERTISE
	PMFC_EPERM
)

// ofp_table_mod_failed_code 1.5
const (
	TMFC_BAD_TABLE = iota
	TMFC_BAD_CONFIG
	TMFC_EPERM
)

// ofp_queue_op_failed_code 1.0
const (
	QOFC_BAD_PORT = iota
	QOFC_BAD_QUEUE
	QOFC_EPERM
)

// ofp_switch_config_failed_code 1.5
const (
	SCFC_BAD_FLAGS = iota
	SCFC_BAD_LEN
	SCFC_EPERM
)

// ofp_role_request_failed_code
const (
	RRFC_STALE = iota
	RRFC_UNSUP
	RRFC_BAD_ROLE
	RRFC_ID_UNSUP
	RRFC_ID_IN_USE
)

// ofp_meter_mod_failed_code
const (
	MMFC_UNKNOWN = iota
	MMFC_METER_EXISTS
	MMFC_INVALID_METER
	MMFC_UNKNOWN_METER
	MMFC_BAD_COMMAND
	MMFC_BAD_FLAGS
	MMFC_BAD_RATE
	MMFC_BAD_BURST
	MMFC_BAD_BAND
	MMFC_BAD_BAND_VALUE
	MMFC_OUT_OF_METERS
	MMFC_OUT_OF_BANDS
)

// ofp_table_features_failed_code
const (
	TFFC_BAD_TABLE = iota
	TFFC_BAD_METADATA
	TFFC_EPERM
	TFFC_BAD_CAPA
	TFFC_BAD_MAX_ENT
	TFFC_BAD_FEATURES
	TFFC_BAD_COMMAND
	TFFC_TOO_MANY
)

// ofp_bad_property_code
const (
	BPC_BAD_TYPE = iota
	BPC_BAD_LEN
	BPC_BAD_VALUE
	BPC_TOO_MANY
	BPC_DUP_TYPE
	BPC_BAD_EXPERIMENTER
	BPC_BAD_EXP_TYPE
	BPC_BAD_EXP_VALUE
	BPC_EPERM
)

// ofp_async_config_failed_cod
const (
	ACFC_INVALID = iota
	ACFC_UNSUPPORTED
	ACFC_EPERM
)

//  ofp_flow_monitor_failed_code
const (
	MOFC_UNKNOWN = iota
	MOFC_MONITOR_EXISTS
	MOFC_INVALID_MONITOR
	MOFC_UNKNOWN_MONITOR
	MOFC_BAD_COMMAND
	MOFC_BAD_FLAGS
	MOFC_BAD_TABLE_ID
	MOFC_BAD_OUT
)

// ofp_bundle_failed_code
const (
	BFC_UNKNOWN = iota
	BFC_EPERM
	BFC_BAD_ID
	BFC_BUNDLE_EXIST
	BFC_BUNDLE_CLOSED
	BFC_OUT_OF_BUNDLES
	BFC_BAD_TYPE
	BFC_BAD_FLAGS
	BFC_MSG_BAD_LEN
	BFC_MSG_BAD_XID
	BFC_MSG_UNSUP
	BFC_MSG_CONFLICT
	BFC_MSG_TOO_MANY
	BFC_MSG_FAILED
	BFC_TIMEOUT
	BFC_BUNDLE_IN_PROGRESS
	BFC_SCHED_NOT_SUPPORTED
	BFC_SCHED_FUTURE
	BFC_SCHED_PAST
)

// ofp_switch_features
type SwitchFeatures struct {
	common.Header
	DPID         net.HardwareAddr // Size 8
	Buffers      uint32
	NumTables    uint8
	AuxilaryId   uint8
	pad          []uint8 // Size 2
	Capabilities uint32
	Reserved     uint32
}

// FeaturesRequest constructor
func NewFeaturesRequest() *common.Header {
	req := NewOfp15Header()
	req.Type = Type_FeaturesRequest
	return &req
}

// FeaturesReply constructor
func NewFeaturesReply() *SwitchFeatures {
	res := new(SwitchFeatures)
	res.Header = NewOfp15Header()
	res.Header.Type = Type_FeaturesReply
	res.DPID = make([]byte, 8)
	res.pad = make([]byte, 2)
	res.Capabilities = 0
	res.Reserved = 0
	return res
}

func (s *SwitchFeatures) Len() (n uint16) {
	n = s.Header.Len()
	n += uint16(len(s.DPID))
	n += 16
	return
}

func (s *SwitchFeatures) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	var bytes []byte
	n := 0

	s.Header.Length = s.Len()
	bytes, err = s.Header.MarshalBinary()
	copy(data[n:], bytes)
	n += len(bytes)

	copy(data[n:], s.DPID)
	n += len(s.DPID)

	binary.BigEndian.PutUint32(data[n:], s.Buffers)
	n += 4
	data[n] = s.NumTables
	n += 1
	data[n] = s.AuxilaryId
	n += 1
	copy(data[n:], s.pad)
	n += len(s.pad)

	binary.BigEndian.PutUint32(data[n:], s.Capabilities)
	n += 4
	binary.BigEndian.PutUint32(data[n:], s.Reserved)
	n += 4
	return
}

func (s *SwitchFeatures) UnmarshalBinary(data []byte) error {
	var err error
	n := 0

	err = s.Header.UnmarshalBinary(data[n:])
	n = int(s.Header.Len())
	copy(s.DPID, data[n:])
	n += len(s.DPID)

	s.Buffers = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.NumTables = data[n]
	n += 1
	s.AuxilaryId = data[n]
	n += 1

	copy(s.pad, data[n:])
	n += len(s.pad)
	s.Capabilities = binary.BigEndian.Uint32(data[n:])
	n += 4

	return err
}

// ofp_capabilities 1.5
const (
	C_FLOW_STATS      = 1 << 0
	C_TABLE_STATS     = 1 << 1
	C_PORT_STATS      = 1 << 2
	C_GROUP_STATS     = 1 << 3
	C_IP_REASM        = 1 << 5
	C_QUEUE_STATS     = 1 << 6
	C_PORT_BLOCKED    = 1 << 8
	C_BUNDLES         = 1 << 9
	C_FLOW_MONITORING = 1 << 10
)

// ofp_vendor 1.5
type VendorHeader struct {
	Header           common.Header /*Type OFPT_VENDOR*/
	Vendor           uint32
	ExperimenterType uint32
	VendorData       util.Message
}

func (v *VendorHeader) Len() (n uint16) {
	length := uint16(16)
	if v.VendorData != nil {
		length += v.VendorData.Len()
	}
	return length
}

func (v *VendorHeader) MarshalBinary() (data []byte, err error) {
	v.Header.Length = v.Len()
	data = make([]byte, v.Len())
	b, err := v.Header.MarshalBinary()
	n := 0
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint32(data[n:], v.Vendor)
	n += 4
	binary.BigEndian.PutUint32(data[n:], v.ExperimenterType)
	n += 4
	if v.VendorData != nil {
		vd, err := v.VendorData.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], vd)
		n += len(vd)
	}
	return
}

func (v *VendorHeader) UnmarshalBinary(data []byte) error {
	if len(data) < 16 {
		return errors.New("The []byte the wrong size to unmarshal an " +
			"VendorHeader message.")
	}
	v.Header.UnmarshalBinary(data)
	n := int(v.Header.Len())
	v.Vendor = binary.BigEndian.Uint32(data[n:])
	n += 4
	v.ExperimenterType = binary.BigEndian.Uint32(data[n:])
	n += 4
	if n < int(v.Header.Length) {
		var err error
		v.VendorData, err = decodeVendorData(v.ExperimenterType, data[n:v.Header.Length])
		if err != nil {
			return err
		}
	}
	return nil
}

// ofp_role_request
type RoleRequest struct {
	common.Header
	Role         uint32
	Shortid      uint16
	pad          uint16
	GenerationId uint64
}
type RoleReply = RoleRequest

// ofp_controller_role
const (
	CR_ROLE_NOCHANGE = iota /* Don’t change current role. */
	CR_ROLE_EQUAL           /* Default role, full access. */
	CR_ROLE_MASTER          /* Full access, at most one master. */
	CR_ROLE_SLAVE           /* Read-only access. */
)

func NewRoleRequest() *RoleRequest {
	f := new(RoleRequest)
	f.Header = NewOfp15Header()
	f.Header.Type = Type_RoleRequest
	return f
}

func NewRoleReply() *RoleReply {
	f := new(RoleReply)
	f.Header = NewOfp15Header()
	f.Header.Type = Type_RoleReply
	return f
}

func (m *RoleRequest) Len() uint16 {
	n := m.Header.Len()
	n += 16
	return n
}

func (m *RoleRequest) MarshalBinary() (data []byte, err error) {
	m.Header.Length = m.Len()
	data = make([]byte, m.Len())
	b, err := m.Header.MarshalBinary()
	n := 0
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint32(data[n:], m.Role)
	n += 4
	binary.BigEndian.PutUint16(data[n:], m.Shortid)
	n += 2
	n += 2 //pad
	binary.BigEndian.PutUint64(data[n:], m.GenerationId)
	n += 8
	return
}

func (m *RoleRequest) UnmarshalBinary(data []byte) (err error) {
	n := 0

	err = m.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = int(m.Header.Len())

	m.Role = binary.BigEndian.Uint32(data[n:])
	n += 4
	m.Shortid = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2 //pad
	m.GenerationId = binary.BigEndian.Uint64(data[n:])
	n += 8
	return
}

func NewGetAsyncRequest() *common.Header {
	h := NewOfp15Header()
	h.Type = Type_GetAsyncRequest
	return &h
}

type Async_Config struct {
	common.Header
	Properties []util.Message
}

type GetAsyncReply = Async_Config
type SetAsync = Async_Config

func NewGetAsyncReply() *GetAsyncReply {
	r := new(Async_Config)
	r.Header = NewOfp15Header()
	r.Header.Type = Type_GetAsyncReply
	return r
}

func NewSetAsync() *SetAsync {
	s := new(SetAsync)
	s.Header = NewOfp15Header()
	s.Header.Type = Type_SetAsync
	return s
}

// ofp_async_config_prop_type
const (
	ACPT_PACKET_IN_SLAVE       = 0      /* Packet-in mask for slave. */
	ACPT_PACKET_IN_MASTER      = 1      /* Packet-in mask for master. */
	ACPT_PORT_STATUS_SLAVE     = 2      /* Port-status mask for slave. */
	ACPT_PORT_STATUS_MASTER    = 3      /* Port-status mask for master. */
	ACPT_FLOW_REMOVED_SLAVE    = 4      /* Flow removed mask for slave. */
	ACPT_FLOW_REMOVED_MASTER   = 5      /* Flow removed mask for master. */
	ACPT_ROLE_STATUS_SLAVE     = 6      /* Role status mask for slave. */
	ACPT_ROLE_STATUS_MASTER    = 7      /* Role status mask for master. */
	ACPT_TABLE_STATUS_SLAVE    = 8      /* Table status mask for slave. */
	ACPT_TABLE_STATUS_MASTER   = 9      /* Table status mask for master. */
	ACPT_REQUESTFORWARD_SLAVE  = 10     /* RequestForward mask for slave. */
	ACPT_REQUESTFORWARD_MASTER = 11     /* RequestForward mask for master. */
	ACPT_FLOW_STATS_SLAVE      = 12     /* Flow stats mask for slave. */
	ACPT_FLOW_STATS_MASTER     = 13     /* Flow stats mask for master. */
	ACPT_CONT_STATUS_SLAVE     = 14     /* Controller status mask for slave. */
	ACPT_CONT_STATUS_MASTER    = 15     /* Controller status mask for master. */
	ACPT_EXPERIMENTER_SLAVE    = 0xFFFE /* Experimenter for slave. */
	ACPT_EXPERIMENTER_MASTER   = 0xFFFF /* Experimenter for master. */
)

func (a *Async_Config) Len() uint16 {
	n := a.Header.Len()
	for _, p := range a.Properties {
		n += p.Len()
	}
	return n
}

func (a *Async_Config) MarshalBinary() (data []byte, err error) {
	a.Header.Length = a.Len()
	data, err = a.Header.MarshalBinary()
	if err != nil {
		return
	}
	for _, p := range a.Properties {
		var b []byte
		b, err = p.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, b...)
	}
	return
}

func (a *Async_Config) UnmarshalBinary(data []byte) (err error) {
	n := uint16(0)
	err = a.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = a.Header.Len()

	for n < a.Header.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case ACPT_PACKET_IN_SLAVE:
			fallthrough
		case ACPT_PACKET_IN_MASTER:
			fallthrough
		case ACPT_PORT_STATUS_SLAVE:
			fallthrough
		case ACPT_PORT_STATUS_MASTER:
			fallthrough
		case ACPT_FLOW_REMOVED_SLAVE:
			fallthrough
		case ACPT_FLOW_REMOVED_MASTER:
			fallthrough
		case ACPT_ROLE_STATUS_SLAVE:
			fallthrough
		case ACPT_ROLE_STATUS_MASTER:
			fallthrough
		case ACPT_TABLE_STATUS_SLAVE:
			fallthrough
		case ACPT_TABLE_STATUS_MASTER:
			fallthrough
		case ACPT_REQUESTFORWARD_SLAVE:
			fallthrough
		case ACPT_REQUESTFORWARD_MASTER:
			fallthrough
		case ACPT_FLOW_STATS_SLAVE:
			fallthrough
		case ACPT_FLOW_STATS_MASTER:
			fallthrough
		case ACPT_CONT_STATUS_SLAVE:
			fallthrough
		case ACPT_CONT_STATUS_MASTER:
			p = new(AsyncConfigPropReasons)

		case ACPT_EXPERIMENTER_SLAVE:
			fallthrough
		case ACPT_EXPERIMENTER_MASTER:
			p = new(AsyncConfigPropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal Async Config's Properties", "structure", p, "data", data[n:])
			return err
		}
		n += p.Len()
		a.Properties = append(a.Properties, p)
	}
	return
}

type AsyncConfigPropHeader struct {
	Type   uint16
	Length uint16
}

func (h *AsyncConfigPropHeader) Len() uint16 {
	return 4
}

func (h *AsyncConfigPropHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(h.Len()))
	n := 0

	binary.BigEndian.PutUint16(data[n:], h.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], h.Length)
	n += 2
	return
}

func (h *AsyncConfigPropHeader) UnmarshalBinary(data []byte) (err error) {
	h.Type = binary.BigEndian.Uint16(data[0:])
	h.Length = binary.BigEndian.Uint16(data[2:])
	return
}

// ofp_async_config_prop_reasons
type AsyncConfigPropReasons struct {
	Header AsyncConfigPropHeader
	Mask   uint32
}

func (p *AsyncConfigPropReasons) Len() uint16 {
	n := p.Header.Len()
	n += 4
	return n
}

func (p *AsyncConfigPropReasons) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	p.Header.Length = 4
	b, err := p.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, b)
	n := p.Header.Len()

	binary.BigEndian.PutUint32(data[n:], p.Mask)
	n += 4
	return
}

func (p *AsyncConfigPropReasons) UnmarshalBinary(data []byte) (err error) {
	p.Header.UnmarshalBinary(data)
	n := p.Header.Len()

	p.Mask = binary.BigEndian.Uint32(data[n:])
	n += 4
	return
}

// ofp_async_config_prop_experimenter
type AsyncConfigPropExperimenter struct {
	Header       AsyncConfigPropHeader
	Experimenter uint32
	Data         []byte
	Pad          []byte
}

func (p *AsyncConfigPropExperimenter) Len() uint16 {
	n := p.Header.Len()
	n += 4
	n += uint16(len(p.Data))
	//n += uint16((8 - (len(p.Data) % 8)) % 8)  // pad to make multiple of 8
	n += uint16(8 - (len(p.Data) % 8)) // pad to make multiple of 8
	return n
}

func (p *AsyncConfigPropExperimenter) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	p.Header.Length = 4 + uint16(len(p.Data))
	b, err := p.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, b)
	n := p.Header.Len()

	binary.BigEndian.PutUint32(data[n:], p.Experimenter)
	n += 4

	copy(data[n:], p.Data)
	n += uint16(len(p.Data))

	return
}

func (p *AsyncConfigPropExperimenter) UnmarshalBinary(data []byte) (err error) {
	p.Header.UnmarshalBinary(data)
	n := p.Header.Len()

	p.Experimenter = binary.BigEndian.Uint32(data[n:])
	n += 4

	p.Data = make([]byte, p.Header.Length)
	copy(p.Data, data[n:])
	n += uint16(len(p.Data))
	return
}

// ofp_role_status
type RoleStatus struct {
	common.Header
	Role         uint32
	Reason       uint8
	Pad          []byte // 3 bytes
	GenerationId uint64
	Properties   []util.Message
}

// ofp_controller_role_reason
const (
	CRR_MASTER_REQUEST = iota /* Another controller asked to be master. */
	CRR_CONFIG                /* Configuration changed on the switch. */
	CRR_EXPERIMENTER          /* Experimenter data changed. */
)

func NewRoleStatus() *RoleStatus {
	r := new(RoleStatus)
	r.Header = NewOfp15Header()
	r.Header.Type = Type_RoleStatus
	r.Pad = make([]byte, 3)
	return r
}

func (r *RoleStatus) Len() uint16 {
	n := r.Header.Len()
	n += 16
	for _, p := range r.Properties {
		n += p.Len()
	}
	return n
}

func (r *RoleStatus) MarshalBinary() (data []byte, err error) {
	r.Header.Length = r.Len()
	data = make([]byte, r.Len())

	var b []byte
	b, err = r.Header.MarshalBinary()
	if err != nil {
		return
	}
	n := 0
	copy(data[n:], b)
	n = int(r.Header.Len())

	binary.BigEndian.PutUint32(data[n:], r.Role)
	n += 4

	data[n] = r.Reason
	n++

	copy(data[n:], r.Pad)
	n += len(r.Pad)

	binary.BigEndian.PutUint64(data[n:], r.GenerationId)
	n += 8

	for _, p := range r.Properties {
		var b []byte
		b, err = p.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += len(b)
	}
	return
}

func (r *RoleStatus) UnmarshalBinary(data []byte) (err error) {
	n := uint16(0)
	err = r.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = r.Header.Len()

	r.Role = binary.BigEndian.Uint32(data[n:])
	n += 4

	r.Reason = data[n]
	n++

	n += 3 //Pad

	r.GenerationId = binary.BigEndian.Uint64(data[n:])
	n += 8

	for n < r.Header.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case RPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal RoleStatus's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		r.Properties = append(r.Properties, p)
	}
	return
}

// ofp_role_prop_type
const (
	RPT_EXPERIMENTER = 0xFFFF /* Experimenter property. */
)

// ofp_role_prop_header
type PropHeader struct {
	Type   uint16
	Length uint16
}

func (h *PropHeader) Len() uint16 {
	return 4
}

func (h *PropHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(h.Len()))
	n := 0

	binary.BigEndian.PutUint16(data[n:], h.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], h.Length)
	n += 2
	return
}

func (h *PropHeader) UnmarshalBinary(data []byte) (err error) {
	h.Type = binary.BigEndian.Uint16(data[0:])
	h.Length = binary.BigEndian.Uint16(data[2:])
	return
}

// ofp_role_prop_experimenter
type PropExperimenter struct {
	Header       PropHeader
	Experimenter uint32
	ExpType      uint32
	Data         []uint32
	Pad          []byte
}

func (p *PropExperimenter) Len() uint16 {
	n := p.Header.Len()
	n += 8
	l := uint16(len(p.Data) * 4)
	n += l
	//n += uint16((8 - (l % 8)) % 8)  // pad to make multiple of 8
	n += uint16(8 - (l % 8)) // pad to make multiple of 8
	return n
}

func (p *PropExperimenter) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	p.Header.Length = 8 + uint16(len(p.Data)*4)
	b, err := p.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, b)
	n := p.Header.Len()

	binary.BigEndian.PutUint32(data[n:], p.Experimenter)
	n += 4
	binary.BigEndian.PutUint32(data[n:], p.ExpType)
	n += 4

	for _, d := range p.Data {
		binary.BigEndian.PutUint32(data[n:], d)
		n += 4
	}

	return
}

func (p *PropExperimenter) UnmarshalBinary(data []byte) (err error) {
	p.Header.UnmarshalBinary(data)
	n := p.Header.Len()

	p.Experimenter = binary.BigEndian.Uint32(data[n:])
	n += 4

	p.ExpType = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < p.Header.Length+p.Header.Len() {
		d := binary.BigEndian.Uint32(data[n:])
		p.Data = append(p.Data, d)
		n += 4
	}
	return
}

// ofp_table_desc
type TableDesc struct {
	Length     uint16
	TableId    uint8
	Pad        uint8
	Config     uint32
	Properties []util.Message
}

// ofp_table_config
const (
	TC_DEPRECATED_MASK = 3      /* Deprecated bits */
	TC_EVICTION        = 1 << 2 /* Authorise table to evict flows. */
	TC_VACANCY_EVENTS  = 1 << 3 /* Enable vacancy events. */
)

func NewTableDesc(id uint8) *TableDesc {
	t := new(TableDesc)
	t.TableId = id
	return t
}

func (t *TableDesc) Len() uint16 {
	var n uint16 = 8
	for _, p := range t.Properties {
		n += p.Len()
	}
	return n
}

func (t *TableDesc) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(t.Len()))
	t.Length = t.Len()
	var n uint16 = 0
	binary.BigEndian.PutUint16(data[n:], t.Length)
	n += 2

	data[n] = t.TableId
	n += 2 // skipping Pad

	binary.BigEndian.PutUint32(data[n:], t.Config)
	n += 4

	for _, p := range t.Properties {
		var b []byte
		b, err = p.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += p.Len()
	}
	return
}

func (t *TableDesc) UnmarshalBinary(data []byte) (err error) {
	var n uint16 = 0
	t.Length = binary.BigEndian.Uint16(data[n:])
	n += 2

	t.TableId = data[n]
	n += 2 // skipping Pad

	t.Config = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < t.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case OFPTMPT_EVICTION:
			p = new(TableModPropEviction)
		case OFPTMPT_VACANCY:
			p = new(TableModPropVacancy)
		case OFPTMPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal TableDesc's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		t.Properties = append(t.Properties, p)
	}
	return
}

// ofp_table_mod_prop_type
const (
	OFPTMPT_EVICTION     = 0x2    /* Eviction property. */
	OFPTMPT_VACANCY      = 0x3    /* Vacancy property. */
	OFPTMPT_EXPERIMENTER = 0xFFFF /* Experimenter property. */
)

// ofp_table_mod_prop_eviction
type TableModPropEviction struct {
	Header PropHeader
	Flags  uint32
}

// ofp_table_mod_prop_eviction_flag
const (
	TMPEF_OTHER      = 1 << 0 /* Using other factors. */
	TMPEF_IMPORTANCE = 1 << 1 /* Using flow entry importance. */
	TMPEF_LIFETIME   = 1 << 2 /* Using flow entry lifetime. */
)

func NewTableModPropEviction() *TableModPropEviction {
	n := new(TableModPropEviction)
	n.Header.Type = OFPTMPT_EVICTION
	return n
}

func (t *TableModPropEviction) Len() uint16 {
	n := t.Header.Len()
	n += 4
	return n
}

func (t *TableModPropEviction) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(t.Len()))
	t.Header.Length = t.Header.Len() + 4
	var b []byte
	b, err = t.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, b)
	n := t.Header.Len()

	binary.BigEndian.PutUint32(data[n:], t.Flags)
	n += 4
	return
}

func (t *TableModPropEviction) UnmarshalBinary(data []byte) (err error) {
	var n uint16 = 0
	err = t.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n += t.Header.Len()
	t.Flags = binary.BigEndian.Uint32(data[n:])
	return
}

// ofp_table_mod_prop_vacancy
type TableModPropVacancy struct {
	Header      PropHeader
	VacancyDown uint8
	VacancyUp   uint8
	Vacancy     uint8
	Pad         uint8
}

func NewTableModPropVacancy() *TableModPropVacancy {
	n := new(TableModPropVacancy)
	n.Header.Type = OFPTMPT_VACANCY
	return n
}

func (t *TableModPropVacancy) Len() uint16 {
	n := t.Header.Len()
	n += 4
	return n
}

func (t *TableModPropVacancy) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(t.Len()))
	t.Header.Length = t.Header.Len() + 4
	var b []byte
	b, err = t.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, b)
	n := t.Header.Len()

	data[n] = t.VacancyUp
	n++
	data[n] = t.VacancyDown
	n++
	data[n] = t.Vacancy
	n++

	return
}

func (t *TableModPropVacancy) UnmarshalBinary(data []byte) (err error) {
	var n uint16 = 0
	err = t.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n += t.Header.Len()

	t.VacancyUp = data[n]
	n++

	t.VacancyDown = data[n]
	n++

	t.Vacancy = data[n]
	n++
	return
}

type TableStatus struct {
	common.Header
	Reason uint8
	Pad    []byte // 7 bytes
	Table  TableDesc
}

// ofp_table_reason
const (
	TR_VACANCY_DOWN = 3 /* Vacancy down threshold event. */
	TR_VACANCY_UP   = 4 /* Vacancy up threshold event. */
)

func NewTableStatus() *TableStatus {
	t := new(TableStatus)
	t.Header = NewOfp15Header()
	t.Header.Type = Type_TableStatus
	t.Pad = make([]byte, 7)
	return t
}

func (t *TableStatus) Len() uint16 {
	n := t.Header.Len()
	n += 8
	n += t.Table.Len()
	return n
}

func (t *TableStatus) MarshalBinary() (data []byte, err error) {
	t.Header.Length = t.Len()
	data = make([]byte, t.Len())

	var b []byte
	b, err = t.Header.MarshalBinary()
	if err != nil {
		return
	}
	n := 0
	copy(data[n:], b)
	n = int(t.Header.Len())

	data[n] = t.Reason
	n += 8

	b, err = t.Table.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)

	return
}

func (t *TableStatus) UnmarshalBinary(data []byte) (err error) {
	n := uint16(0)
	err = t.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = t.Header.Len()

	t.Reason = data[n]
	n++
	n += 7 //Pad

	err = t.Table.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal TableStatus's Table", "data", data[n:])
	}
	return
}

// ofp_table_mod
type TableMod struct {
	common.Header
	TableId    uint8
	Pad        []byte // 3 bytes
	Config     uint32
	Properties []util.Message
}

func NewTableMod() *TableMod {
	n := new(TableMod)
	n.Header = NewOfp15Header()
	n.Header.Type = Type_TableMod
	n.Pad = make([]byte, 3)
	return n
}

func (t *TableMod) Len() uint16 {
	var n uint16 = t.Header.Len()
	n += 8
	for _, prop := range t.Properties {
		n += prop.Len()
	}
	return n
}

func (t *TableMod) MarshalBinary() (data []byte, err error) {
	t.Header.Length = t.Len()
	data = make([]byte, t.Len())

	var b []byte
	b, err = t.Header.MarshalBinary()
	if err != nil {
		return
	}
	var n uint16
	copy(data[n:], b)
	n = t.Header.Len()

	data[n] = t.TableId
	n++
	n += 3 // Pad

	binary.BigEndian.PutUint32(data[n:], t.Config)
	n += 4

	for _, prop := range t.Properties {
		b, err = prop.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += prop.Len()
	}
	return
}

func (t *TableMod) UnmarshalBinary(data []byte) (err error) {
	var n uint16 = 0
	err = t.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = t.Header.Len()

	t.TableId = data[n]
	n++
	n += 3 // Pad

	t.Config = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < uint16(len(data)) {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case OFPTMPT_EVICTION:
			p = new(TableModPropEviction)
		case OFPTMPT_VACANCY:
			p = new(TableModPropVacancy)
		case OFPTMPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal TableMod's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		t.Properties = append(t.Properties, p)
	}
	return
}

type RequestForward struct {
	common.Header
	Request common.Header
}

func NewRequestForward() *RequestForward {
	r := new(RequestForward)
	r.Header = NewOfp15Header()
	r.Header.Type = Type_RequestForward
	return r
}

func (r *RequestForward) Len() uint16 {
	n := r.Header.Len()
	return n * 2
}

func (r *RequestForward) MarshalBinary() (data []byte, err error) {
	r.Header.Length = r.Len()
	data = make([]byte, r.Len())

	var b []byte
	b, err = r.Header.MarshalBinary()
	if err != nil {
		return
	}
	var n uint16 = 0
	copy(data[n:], b)
	n = r.Header.Len()

	b, err = r.Request.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += r.Request.Len()

	return
}

func (r *RequestForward) UnmarshalBinary(data []byte) (err error) {
	var n uint16 = 0
	err = r.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = r.Header.Len()

	err = r.Request.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal RequestForward's Request", "data", data[n:])
		return
	}
	n += r.Request.Len()
	return
}

// ofp_bundle_ctrl_msg
type BundleCtrl struct {
	common.Header
	BundleId   uint32
	Type       uint16
	Flags      uint16
	Properties []util.Message
}

// ofp_bundle_ctrl_type
const (
	BCT_OPEN_REQUEST = iota
	BCT_OPEN_REPLY
	BCT_CLOSE_REQUEST
	BCT_CLOSE_REPLY
	BCT_COMMIT_REQUEST
	BCT_COMMIT_REPLY
	BCT_DISCARD_REQUEST
	BCT_DISCARD_REPLY
)

// ofp_bundle_flags
const (
	BF_ATOMIC  = 1 << 0 /* Execute atomically. */
	BF_ORDERED = 1 << 1 /* Execute in specified order. */
	BF_TIME    = 1 << 2 /* Execute in specified time. */
)

// ofp_bundle_prop_type
const (
	BPT_TIME         = 1      /* Time property. */
	BPT_EXPERIMENTER = 0xFFFF /* Experimenter property. */
)

func NewBundleCtrl(id uint32, bundleType uint16, flags uint16) *BundleCtrl {
	c := new(BundleCtrl)
	c.Header = NewOfp15Header()
	c.Header.Type = Type_BundleControl
	c.BundleId = id
	c.Type = bundleType
	c.Flags = flags
	return c
}

func (c *BundleCtrl) Len() uint16 {
	n := c.Header.Len()
	n += 8
	for _, p := range c.Properties {
		n += p.Len()
	}
	return n
}

func (c *BundleCtrl) MarshalBinary() (data []byte, err error) {
	c.Header.Length = c.Len()
	data = make([]byte, c.Len())

	var b []byte
	b, err = c.Header.MarshalBinary()
	if err != nil {
		return
	}
	var n uint16
	copy(data[n:], b)
	n = c.Header.Len()

	binary.BigEndian.PutUint32(data[n:], c.BundleId)
	n += 4

	binary.BigEndian.PutUint16(data[n:], c.Type)
	n += 2

	binary.BigEndian.PutUint16(data[n:], c.Flags)
	n += 2

	for _, p := range c.Properties {
		var b []byte
		b, err = p.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += p.Len()
	}
	return
}

func (c *BundleCtrl) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = c.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = c.Header.Len()

	c.BundleId = binary.BigEndian.Uint32(data[n:])
	n += 4

	c.Type = binary.BigEndian.Uint16(data[n:])
	n += 2

	c.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2

	for n < c.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case BPT_TIME:
			p = new(BundlePropTime)
		case BPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal BundleCtrl's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		c.Properties = append(c.Properties, p)
	}
	return
}

// ofp_bundle_prop_time
type BundlePropTime struct {
	Header    PropHeader
	Pad       uint32
	SchedTime OfpTime
}

func (t *BundlePropTime) Len() uint16 {
	n := t.Header.Len()
	n += 4
	n += t.SchedTime.Len()
	return n
}

func (t *BundlePropTime) MarshalBinary() (data []byte, err error) {
	t.Header.Length = t.Len()
	data = make([]byte, t.Len())

	var b []byte
	b, err = t.Header.MarshalBinary()
	if err != nil {
		return
	}
	var n uint16
	copy(data[n:], b)
	n = t.Header.Len()

	n += 4 // Pad

	b, err = t.SchedTime.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += t.SchedTime.Len()
	return
}

func (t *BundlePropTime) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = t.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = t.Header.Len()

	n += 4 // Pad

	err = t.SchedTime.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal BundlePropTime's SchedTime", "data", data[n:])
		return
	}
	n += t.SchedTime.Len()

	return
}

// ofp_time
type OfpTime struct {
	Seconds     uint64
	NanoSeconds uint32
	Pad         uint32
}

func (t *OfpTime) Len() uint16 {
	return 16
}

func (t *OfpTime) MarshalBinary() (data []byte, err error) {
	data = make([]byte, t.Len())
	n := 0

	binary.BigEndian.PutUint64(data[n:], t.Seconds)
	n += 8
	binary.BigEndian.PutUint32(data[n:], t.NanoSeconds)
	n += 4
	return
}

func (t *OfpTime) UnmarshalBinary(data []byte) (err error) {
	n := 0
	t.Seconds = binary.BigEndian.Uint64(data[n:])
	n += 8
	t.NanoSeconds = binary.BigEndian.Uint32(data[n:])
	n += 4
	return
}

// ofp_bundle_add_msg
type BndleAdd struct {
	common.Header
	BundleId   uint32
	Pad        uint16
	Flags      uint16
	Message    util.Message
	Properties []util.Message
}

func NewBndleAdd(id uint32, flags uint16) *BndleAdd {
	c := new(BndleAdd)
	c.Header = NewOfp15Header()
	c.Header.Type = Type_BundleAddMessage
	c.BundleId = id
	c.Flags = flags
	return c
}

func (c *BndleAdd) Len() uint16 {
	n := c.Header.Len()
	n += 8

	n += c.Message.Len()
	for _, p := range c.Properties {
		n += p.Len()
	}
	return n
}

func (c *BndleAdd) MarshalBinary() (data []byte, err error) {
	c.Header.Length = c.Len()
	data = make([]byte, c.Len())

	var b []byte
	b, err = c.Header.MarshalBinary()
	if err != nil {
		return
	}
	klog.V(4).InfoS("BndleAdd MarshalBinary", "Header", c.Header)
	var n uint16
	copy(data[n:], b)
	n = c.Header.Len()

	binary.BigEndian.PutUint32(data[n:], c.BundleId)
	n += 4

	n += 2 // Pad

	binary.BigEndian.PutUint16(data[n:], c.Flags)
	n += 2

	b, err = c.Message.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += uint16(len(b))

	for _, p := range c.Properties {
		b, err = p.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += p.Len()
	}

	return
}

func (c *BndleAdd) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = c.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = c.Header.Len()

	c.BundleId = binary.BigEndian.Uint32(data[n:])
	n += 4

	n += 2 // Pad

	c.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2

	c.Message, err = Parse(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to parse BndleAdd's Message", "data", data[n:])
		return
	}
	n += c.Message.Len()

	for n < c.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case BPT_TIME:
			p = new(BundlePropTime)
		case BPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal BndleAdd's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		c.Properties = append(c.Properties, p)
	}

	return
}

// ofp_controller_status_header
type ControllerStatusHeader struct {
	common.Header
	Status ControllerStatus
}

func NewControllerStatusHeader() *ControllerStatusHeader {
	c := new(ControllerStatusHeader)
	c.Header = NewOfp15Header()
	c.Header.Type = Type_ControllerStatus
	return c
}

func (c *ControllerStatusHeader) Len() uint16 {
	n := c.Header.Len()
	n += c.Status.Len()
	return n
}

func (c *ControllerStatusHeader) MarshalBinary() (data []byte, err error) {
	c.Header.Length = c.Len()
	data = make([]byte, c.Len())

	var b []byte
	b, err = c.Header.MarshalBinary()
	if err != nil {
		return
	}
	var n uint16
	copy(data[n:], b)
	n = c.Header.Len()

	b, err = c.Status.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], b)
	n += uint16(len(b))

	return
}

func (c *ControllerStatusHeader) UnmarshalBinary(data []byte) (err error) {
	n := uint16(0)
	err = c.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = c.Header.Len()

	err = c.Status.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal ControllerStatusHeader's Status", "data", data[n:])
	}
	return
}

// ofp_controller_status
type ControllerStatus struct {
	Length        uint16
	ShortId       uint16
	Role          uint32
	Reason        uint8
	ChannelStatus uint8
	Pad           []uint8        // 6 bytes
	Properties    []util.Message // ofp_controller_status_prop_header
}

func NewControllerStatus() *ControllerStatus {
	n := new(ControllerStatus)
	n.Pad = make([]byte, 6)
	return n
}

func (c *ControllerStatus) Len() (n uint16) {
	n = 16
	for _, p := range c.Properties {
		n += p.Len()
	}
	return n
}

func (c *ControllerStatus) MarshalBinary() (data []byte, err error) {
	data = make([]byte, c.Len())
	var n uint16

	binary.BigEndian.PutUint16(data[n:], c.Length)
	n += 2

	binary.BigEndian.PutUint16(data[n:], c.ShortId)
	n += 2

	binary.BigEndian.PutUint32(data[n:], c.Role)
	n += 4

	data[n] = c.Reason
	n++

	data[n] = c.ChannelStatus
	n++

	n += 6 // Pad

	for _, p := range c.Properties {
		var b []byte
		b, err = p.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += uint16(len(b))
	}
	return
}

func (c *ControllerStatus) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	c.Length = binary.BigEndian.Uint16(data[n:])
	n += 2

	c.ShortId = binary.BigEndian.Uint16(data[n:])
	n += 2

	c.Role = binary.BigEndian.Uint32(data[n:])
	n += 4

	c.Reason = data[n]
	n++

	c.ChannelStatus = data[n]
	n++

	n += 6 //Pad

	for n < uint16(len(data)) {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case CSPT_URI:
			p = new(ControllerStatusPropUri)
		case CSPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal ControllerStatus's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		c.Properties = append(c.Properties, p)
	}
	return
}

// ofp_controller_status_reason
const (
	CSR_REQUEST            = iota /* Controller requested status. */
	CSR_CHANNEL_STATUS            /* Oper status of channel changed. */
	CSR_ROLE                      /* Controller role changed. */
	CSR_CONTROLLER_ADDED          /* New controller added. */
	CSR_CONTROLLER_REMOVED        /* Controller removed from config. */
	CSR_SHORT_ID                  /* Controller ID changed. */
	CSR_EXPERIMENTER              /* Experimenter data changed. */
)

// ofp_control_channel_status
const (
	CT_STATUS_UP   = iota /* Control channel is operational. */
	CT_STATUS_DOWN        /* Control channel is not operational. */
)

// ofp_controller_status_prop_type
const (
	CSPT_URI          = 0      /* Connection URI property. */
	CSPT_EXPERIMENTER = 0xFFFF /* Experimenter property. */
)

// ofp_controller_status_prop_uri
type ControllerStatusPropUri struct {
	Header PropHeader
	Uri    []byte
	Pad    []byte // to make multiple of 8
	// Header.Length does not include Pad
}

func NewControllerStatusPropUri() *ControllerStatusPropUri {
	n := new(ControllerStatusPropUri)
	n.Header.Type = CSPT_URI
	return n
}

func (p *ControllerStatusPropUri) Len() (n uint16) {
	n = p.Header.Len()
	n += uint16(len(p.Uri))
	//n += uint16(8 - (len(p.Uri) % 8))  // Pad
	return
}

func (p *ControllerStatusPropUri) MarshalBinary() (data []byte, err error) {
	// Pad is not part of Header.Length
	p.Header.Length = p.Len() // - uint16(8 - (len(p.Uri) % 8))
	data = make([]byte, p.Len())

	var b []byte
	b, err = p.Header.MarshalBinary()
	if err != nil {
		return
	}
	var n uint16
	copy(data[n:], b)
	n = p.Header.Len()

	copy(data[n:], p.Uri)
	n += uint16(len(p.Uri))

	return
}

func (p *ControllerStatusPropUri) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = p.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = p.Header.Len()

	p.Uri = make([]byte, p.Header.Length-4)
	copy(p.Uri, data[n:])
	n += uint16(len(p.Uri))

	return
}

// BarrierRequest constructor
func NewBarrierRequest() *common.Header {
	req := NewOfp15Header()
	req.Type = Type_BarrierRequest
	return &req
}

// BarrierReply constructor
func NewBarrierReply() *common.Header {
	req := NewOfp15Header()
	req.Type = Type_BarrierReply
	return &req
}

type Property interface {
	Header() *PropHeader
	util.Message
}

func (p *PropHeader) Header() *PropHeader {
	return p
}
