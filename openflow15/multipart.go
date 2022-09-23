package openflow15

import (
	"encoding/binary"
	"errors"
	"fmt"

	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/util"
)

// ofp_multipart_request
type MultipartRequest struct {
	common.Header
	Type  uint16
	Flags uint16
	pad   []byte // 4 bytes
	Body  []util.Message
}

func (s *MultipartRequest) Len() (n uint16) {
	n = s.Header.Len() + 8
	for _, body := range s.Body {
		n += body.Len()
	}
	return
}

func (s *MultipartRequest) MarshalBinary() (data []byte, err error) {
	s.Header.Length = s.Len()
	if data, err = s.Header.MarshalBinary(); err != nil {
		return
	}

	b := make([]byte, 8)
	n := 0
	binary.BigEndian.PutUint16(b[n:], s.Type)
	n += 2
	binary.BigEndian.PutUint16(b[n:], s.Flags)
	n += 2
	n += 4 // for padding
	data = append(data, b...)

	for _, body := range s.Body {
		b, err = body.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, b...)
	}

	klog.V(4).InfoS("Sending MultipartRequest succeeded", "dataLength", len(data), "data", data)

	return
}

func (s *MultipartRequest) UnmarshalBinary(data []byte) error {
	err := s.Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	n := s.Header.Len()

	s.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	s.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 4 // for padding
	for n < s.Header.Length {
		var req util.Message
		switch s.Type {
		case MultipartType_Desc:
			// The request body is empty.
		case MultipartType_FlowDesc:
			// The request body is struct ofp_flow_stats_request.
			req = NewFlowStatsRequest()
		case MultipartType_AggregateStats:
			// The request body is struct ofp_aggregate_stats_request.
			req = new(AggregateStatsRequest)
		case MultipartType_TableStats:
			// The request body is empty.
		case MultipartType_Port:
			// The request body is struct ofp_port_multipart_request.
			req = new(PortMultipartRequst)
		case MultipartType_QueueStats:
			// The request body is struct ofp_queue_multipart_request.
			req = new(QueueMultipartRequest)
		case MultipartType_GroupStats:
			// The request body is struct ofp_group_multipart_request.
			req = new(GroupMultipartRequest)
		case MultipartType_GroupDesc:
			// The request body is struct ofp_group_multipart_request.
			req = new(GroupMultipartRequest)
		case MultipartType_GroupFeatures:
			// The request body is empty.
		case MultipartType_MeterStats:
			// The request body is struct ofp_meter_multipart_request.
			req = new(MeterMultipartRequest)
		case MultipartType_MeterDesc:
			// The request body is struct ofp_meter_multipart_request.
			req = new(MeterMultipartRequest)
		case MultipartType_MeterFeatures:
			// The request body is empty.
		case MultipartType_TableFeatures:
			// The request body is either empty or contains an array of
			// struct ofp_table_features containing the controller’s
			// desired view of the switch. If the switch is unable to
			// set the specified view an error is returned.
			req = new(TableFeatures)
		case MultipartType_PortDesc:
			// The request body is struct ofp_port_multipart_request.
			req = new(PortMultipartRequest)
		case MultipartType_TableDesc:
			// The request body is empty.
		case MultipartType_QueueDesc:
			// The request body is struct ofp_queue_multipart_request.
			req = new(QueueMultipartRequest)
		case MultipartType_FlowMonitor:
			// The request body is an array of struct ofp_flow_monitor_request.
			req = new(FlowMonitorRequest)
		case MultipartType_FlowStats:
			//  The request body is struct ofp_flow_stats_request.
			req = NewFlowStatsRequest()
		case MultipartType_ControllerStatus:
			// The request body is empty.
		case MultipartType_BundleFeatures:
			// The request body is ofp_bundle_features_request.
			req = new(BundleFeaturesRequest)
		case MultipartType_Experimenter:
		}

		if req != nil {
			err = req.UnmarshalBinary(data[n:])
			if err != nil {
				klog.ErrorS(err, "Failed to unmarshal MultipartRequest's Body", "data", data[n:])
				return err
			}
			n += req.Len()
			s.Body = append(s.Body, req)
		}
	}
	return nil
}

// ofp_multipart_reply
type MultipartReply struct {
	common.Header
	Type  uint16
	Flags uint16
	pad   []byte // 4 bytes
	Body  []util.Message
}

func (s *MultipartReply) Len() (n uint16) {
	n = s.Header.Len()
	n += 8
	for _, r := range s.Body {
		n += uint16(r.Len())
	}
	return
}

func (s *MultipartReply) MarshalBinary() (data []byte, err error) {
	s.Header.Length = s.Len()
	data, err = s.Header.MarshalBinary()

	b := make([]byte, 8)
	n := 0
	binary.BigEndian.PutUint16(b[n:], s.Type)
	n += 2
	binary.BigEndian.PutUint16(b[n:], s.Flags)
	n += 2
	n += 4 // for padding
	data = append(data, b...)

	for _, r := range s.Body {
		b, err = r.MarshalBinary()
		data = append(data, b...)
	}

	return
}

func (s *MultipartReply) UnmarshalBinary(data []byte) error {
	err := s.Header.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	n := s.Header.Len()

	s.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	s.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 4 // for padding
	var req []util.Message
	for n < s.Header.Length {
		var repl util.Message
		switch s.Type {
		case MultipartType_Desc:
			// The reply body is struct ofp_desc.
			repl = NewDescStats()
		case MultipartType_FlowDesc:
			// The reply body is an array of struct ofp_flow_desc.
			repl = NewFlowDesc()
		case MultipartType_AggregateStats:
			//  The reply body is struct ofp_aggregate_stats_reply.
			repl = new(AggregateStatsReply)
		case MultipartType_TableStats:
			//  The reply body is an array of struct ofp_table_stats.
			repl = new(TableStats)
		case MultipartType_Port:
			// The reply body is an array of struct ofp_port_stats.
			repl = new(PortStats)
		case MultipartType_QueueStats:
			// The reply body is an array of struct ofp_queue_stats.
			repl = new(QueueStats)
		case MultipartType_GroupStats:
			// The reply is an array of struct ofp_group_stats.
			repl = new(GroupStats)
		case MultipartType_GroupDesc:
			// The reply body is an array of struct ofp_group_desc.
			repl = new(GroupDesc)
		case MultipartType_GroupFeatures:
			// The reply body is struct ofp_group_features.
			repl = NewGroupFeatures()
		case MultipartType_MeterStats:
			// The reply body is an array of struct ofp_meter_stats.
			repl = new(MeterStats)
		case MultipartType_MeterDesc:
			// The reply body is an array of struct ofp_meter_desc.
			repl = new(MeterDesc)
		case MultipartType_MeterFeatures:
			// The reply body is struct ofp_meter_features.
			repl = new(MeterFeatures)
		case MultipartType_TableFeatures:
			// The reply body is an array of struct ofp_table_features.
			repl = new(TableFeatures)
		case MultipartType_PortDesc:
			//  The reply body is an array of struct ofp_port.
			repl = NewPort(0)
		case MultipartType_TableDesc:
			// The reply body is an array of struct ofp_table_desc.
			repl = new(TableDesc)
		case MultipartType_QueueDesc:
			// The reply body is an array of struct ofp_queue_desc.
			repl = new(QueueDesc)
		case MultipartType_FlowMonitor:
			// The reply body is an array of struct ofp_flow_update_header.
			// switch on event
			switch binary.BigEndian.Uint16(data[n+2:]) {
			case FME_INITIAL:
				repl = NewFlowUpdateFull(FME_INITIAL)
			case FME_ADDED:
				repl = NewFlowUpdateFull(FME_ADDED)
			case FME_REMOVED:
				repl = NewFlowUpdateFull(FME_REMOVED)
			case FME_MODIFIED:
				repl = NewFlowUpdateFull(FME_MODIFIED)
			case FME_ABBREV:
				repl = NewFlowUpdateAbbrev()
			case FME_PAUSED:
				repl = NewFlowUpdatePaused(FME_PAUSED)
			case FME_RESUMED:
				repl = NewFlowUpdatePaused(FME_RESUMED)
			default:
				return fmt.Errorf("Unknown Event type %d", binary.BigEndian.Uint16(data[n+2:]))
			}

		case MultipartType_FlowStats:
			// The reply body is an array of struct ofp_flow_stats.
			repl = NewFlowStats()
		case MultipartType_ControllerStatus:
			// The reply body is an array of struct ofp_controller_status.
			repl = NewControllerStatus()
		case MultipartType_BundleFeatures:
			// The reply body is struct ofp_bundle_features.
			repl = NewBundleFeatures()
		case MultipartType_Experimenter:
			break
		}

		err = repl.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal MultipartReply's Body", "data", data[n:])
			return err
		}
		if repl == nil {
			return fmt.Errorf("reply structure is nil in MultipartReply UnmarshalBinary")
		}
		n += repl.Len()
		req = append(req, repl)
	}

	s.Body = req

	return err
}

// ofp_multipart_request_flags & ofp_multipart_reply_flags
const (
	OFPMPF_REQ_MORE   = 1 << 0 /* More requests to follow. */
	OFPMPF_REPLY_MORE = 1 << 0 /* More replies to follow. */
)

// _stats_types
const (
	/* Description of this OpenFlow switch.
	 * The request body is empty.
	 * The reply body is struct ofp_desc_stats. */
	MultipartType_Desc = iota

	/* Individual flow statistics.
	 * The request body is struct ofp_flow_stats_request.
	 * The reply body is an array of struct ofp_flow_stats. */
	MultipartType_FlowDesc = 1

	/* Aggregate flow statistics.
	 * The request body is struct ofp_aggregate_stats_request.
	 * The reply body is struct ofp_aggregate_stats_reply. */
	MultipartType_AggregateStats = 2

	/* Flow table statistics.
	 * The request body is empty.
	 * The reply body is an array of struct ofp_table_stats. */
	MultipartType_TableStats = 3

	/* Port statistics.
	 * The request body is struct ofp_port_stats_request.
	 * The reply body is an array of struct ofp_port_stats. */
	MultipartType_Port = 4

	/* Queue statistics for a port
	 * The request body is struct _queue_stats_request.
	 * The reply body is an array of struct ofp_queue_stats */
	MultipartType_QueueStats = 5

	/* Group counter statistics.
	 * The request body is struct ofp_group_stats_request.
	 * The reply is an array of struct ofp_group_stats. */
	MultipartType_GroupStats = 6

	/* Group description.
	 * The request body is empty.
	 * The reply body is an array of struct ofp_group_desc. */
	MultipartType_GroupDesc = 7

	/* Group features.
	 * The request body is empty.
	 * The reply body is struct ofp_group_features. */
	MultipartType_GroupFeatures = 8

	/* Meter statistics.
	 * The request body is struct ofp_meter_multipart_requests.
	 * The reply body is an array of struct ofp_meter_stats. */
	MultipartType_MeterStats = 9

	/* Meter configuration.
	 * The request body is struct ofp_meter_multipart_request.
	 * The reply body is an array of struct ofp_meter_desc. */
	MultipartType_MeterDesc = 10

	/* Meter features.
	 * The request body is empty.
	 * The reply body is struct ofp_meter_features. */
	MultipartType_MeterFeatures = 11

	/* Table features.
	 * The request body is either empty or contains an array of
	 * struct ofp_table_features containing the controller’s
	 * desired view of the switch. If the switch is unable to
	 * set the specified view an error is returned.
	 * The reply body is an array of struct ofp_table_features. */
	MultipartType_TableFeatures = 12

	/* Port description.
	 * The request body is struct ofp_port_multipart_request.
	 * The reply body is an array of struct ofp_port. */
	MultipartType_PortDesc = 13

	/* Table description.
	 * The request body is empty.
	 * The reply body is an array of struct ofp_table_desc. */
	MultipartType_TableDesc = 14

	/* Queue description.
	 * The request body is struct ofp_queue_multipart_request.
	 * The reply body is an array of struct ofp_queue_desc. */
	MultipartType_QueueDesc = 15

	/* Flow monitors. Reply may be an asynchronous message.
	 * The request body is an array of struct ofp_flow_monitor_request.
	 * The reply body is an array of struct ofp_flow_update_header. */
	MultipartType_FlowMonitor = 16

	/* Individual flow statistics (without description).
	 * The request body is struct ofp_flow_stats_request.
	 * The reply body is an array of struct ofp_flow_stats. */
	MultipartType_FlowStats = 17

	/* Controller status.
	 * The request body is empty.
	 * The reply body is an array of struct ofp_controller_status. */
	MultipartType_ControllerStatus = 18

	/* Bundle features.
	 * The request body is ofp_bundle_features_request.
	 * The reply body is struct ofp_bundle_features. */
	MultipartType_BundleFeatures = 19

	/* Experimenter extension.
	 * The request and reply bodies begin with
	 * struct ofp_experimenter_multipart_header.
	 * The request and reply bodies are otherwise experimenter-defined. */
	MultipartType_Experimenter = 0xffff
)

func NewMpRequest(mpType uint16) *MultipartRequest {
	m := new(MultipartRequest)
	m.Header = NewOfp15Header()
	m.Header.Type = Type_MultiPartRequest
	m.Type = mpType
	m.pad = make([]byte, 4)
	m.Body = make([]util.Message, 0)
	return m
}

func NewMpReply(mpType uint16) *MultipartReply {
	m := new(MultipartReply)
	m.Header = NewOfp15Header()
	m.Header.Type = Type_MultiPartReply
	m.Type = mpType
	m.pad = make([]byte, 4)
	m.Body = make([]util.Message, 0)
	return m
}

// ofp_desc_stats 1.5
type DescStats struct {
	MfrDesc   []byte // Size DESC_STR_LEN
	HWDesc    []byte // Size DESC_STR_LEN
	SWDesc    []byte // Size DESC_STR_LEN
	SerialNum []byte // Size SERIAL_NUM_LEN
	DPDesc    []byte // Size DESC_STR_LEN
}

func NewDescStats() *DescStats {
	s := new(DescStats)
	s.MfrDesc = make([]byte, DESC_STR_LEN)
	s.HWDesc = make([]byte, DESC_STR_LEN)
	s.SWDesc = make([]byte, DESC_STR_LEN)
	s.SerialNum = make([]byte, SERIAL_NUM_LEN)
	s.DPDesc = make([]byte, DESC_STR_LEN)
	return s
}

func (s *DescStats) Len() (n uint16) {
	return uint16(DESC_STR_LEN*4 + SERIAL_NUM_LEN)
}

func (s *DescStats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	n := 0
	copy(data[n:], s.MfrDesc)
	n += len(s.MfrDesc)
	copy(data[n:], s.HWDesc)
	n += len(s.HWDesc)
	copy(data[n:], s.SWDesc)
	n += len(s.SWDesc)
	copy(data[n:], s.SerialNum)
	n += len(s.SerialNum)
	copy(data[n:], s.DPDesc)
	n += len(s.DPDesc)
	return
}

func (s *DescStats) UnmarshalBinary(data []byte) error {
	n := 0
	copy(s.MfrDesc, data[n:])
	n += len(s.MfrDesc)
	copy(s.HWDesc, data[n:])
	n += len(s.HWDesc)
	copy(s.SWDesc, data[n:])
	n += len(s.SWDesc)
	copy(s.SerialNum, data[n:])
	n += len(s.SerialNum)
	copy(s.DPDesc, data[n:])
	n += len(s.DPDesc)
	return nil
}

const (
	DESC_STR_LEN   = 256
	SERIAL_NUM_LEN = 32
)

const (
	OFPTT_MAX = 0xfe
	/* Fake tables. */
	OFPTT_ALL = 0xff /* Wildcard table used for table config, flow stats and flow deletes. */
)

// ofp_flow_stats_request
type FlowStatsRequest struct {
	TableId    uint8
	pad        []byte // 3 bytes
	OutPort    uint32
	OutGroup   uint32
	pad2       []byte // 4 bytes
	Cookie     uint64
	CookieMask uint64
	Match      Match
}

func NewFlowStatsRequest() *FlowStatsRequest {
	s := new(FlowStatsRequest)
	s.OutPort = P_ANY
	s.OutGroup = OFPG_ANY
	s.pad = make([]byte, 3)
	s.pad2 = make([]byte, 4)
	s.Match = *NewMatch()
	return s
}

func (s *FlowStatsRequest) Len() (n uint16) {
	return s.Match.Len() + 32
}

func (s *FlowStatsRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 32)
	n := 0
	data[n] = s.TableId
	n += 1
	copy(data[n:], s.pad)
	n += 3
	binary.BigEndian.PutUint32(data[n:], s.OutPort)
	n += 4
	binary.BigEndian.PutUint32(data[n:], s.OutGroup)
	n += 4
	copy(data[n:], s.pad2)
	n += 4
	binary.BigEndian.PutUint64(data[n:], s.Cookie)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.CookieMask)
	n += 8

	b, err := s.Match.MarshalBinary()
	data = append(data, b...)
	return
}

func (s *FlowStatsRequest) UnmarshalBinary(data []byte) error {
	n := 0
	s.TableId = data[n]
	n += 1
	copy(s.pad, data[n:n+3])
	n += 3
	s.OutPort = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.OutGroup = binary.BigEndian.Uint32(data[n:])
	n += 4
	copy(s.pad2, data[n:n+4])
	n += 4
	s.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.CookieMask = binary.BigEndian.Uint64(data[n:])
	n += 8

	err := s.Match.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal FlowStatsRequest's Match", "data", data[n:])
		return err
	}
	n += int(s.Match.Len())

	return err
}

// ofp_flow_stats
type FlowStats struct {
	Length   uint16
	Pad2     []byte // 2 bytes
	TableId  uint8
	Reason   uint8
	Priority uint16
	Match
	Stats []Stats
}

// ofp_flow_stats_reason
const (
	FSR_STATS_REQUEST = 0 /* Reply to a OFPMP_FLOW_STATS request. */
	FSR_STAT_TRIGGER  = 1 /* Status generated by OFPIT_STAT_TRIGGER. */
)

func NewFlowStats() *FlowStats {
	f := new(FlowStats)
	f.Match = *NewMatch()
	f.Pad2 = make([]byte, 2)
	return f
}

func (s *FlowStats) Len() (n uint16) {
	n = 8 + s.Match.Len()
	for _, stat := range s.Stats {
		n += stat.Len()
	}
	return
}

func (s *FlowStats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	n := 0
	s.Length = s.Len()
	binary.BigEndian.PutUint16(data[n:], s.Length)
	n += 2
	n += 2 // Pad2
	data[n] = s.TableId
	n += 1
	data[n] = s.Reason
	n += 1

	binary.BigEndian.PutUint16(data[n:], s.Priority)
	n += 2

	b, err := s.Match.MarshalBinary()
	data = append(data, b...)
	n += len(b)

	for _, stat := range s.Stats {
		b, err = stat.MarshalBinary()
		data = append(data, b...)
		n += len(b)
	}
	return
}

func (s *FlowStats) UnmarshalBinary(data []byte) error {
	var n uint16
	s.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2 // Pad2
	s.TableId = data[n]
	n += 1
	s.Reason = data[n]
	n += 1
	s.Priority = binary.BigEndian.Uint16(data[n:])
	n += 2
	err := s.Match.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal FlowStats's Match", "data", data[n:])
		return err
	}
	n += s.Match.Len()

	for n < s.Length {
		stat := new(Stats)
		err = stat.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal FlowStats's Stat", "data", data[n:])
			return err
		}
		s.Stats = append(s.Stats, *stat)
		n += stat.Len()
	}
	return err
}

// ofp_aggregate_stats_request
type AggregateStatsRequest struct {
	TableId    uint8
	pad        []byte // 3 bytes
	OutPort    uint32
	OutGroup   uint32
	pad2       []byte // 4 bytes
	Cookie     uint64
	CookieMask uint64
	Match
}

func NewAggregateStatsRequest() *AggregateStatsRequest {
	a := new(AggregateStatsRequest)
	a.pad = make([]byte, 3)
	a.pad2 = make([]byte, 4)
	a.OutPort = P_ANY
	a.OutGroup = OFPG_ANY
	a.Match = *NewMatch()

	return a
}

func (s *AggregateStatsRequest) Len() (n uint16) {
	return s.Match.Len() + 32
}

func (s *AggregateStatsRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 32)
	n := 0
	data[n] = s.TableId
	n += 1
	copy(data[n:], s.pad)
	n += 3
	binary.BigEndian.PutUint32(data[n:], s.OutPort)
	n += 4
	binary.BigEndian.PutUint32(data[n:], s.OutGroup)
	n += 4
	copy(data[n:], s.pad2)
	n += 4
	binary.BigEndian.PutUint64(data[n:], s.Cookie)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.CookieMask)
	n += 8

	b, err := s.Match.MarshalBinary()
	data = append(data, b...)
	return
}

func (s *AggregateStatsRequest) UnmarshalBinary(data []byte) error {
	n := 0
	s.TableId = data[n]
	n += 1
	copy(s.pad, data[n:n+3])
	n += 3
	s.OutPort = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.OutGroup = binary.BigEndian.Uint32(data[n:])
	n += 4
	copy(s.pad2, data[n:n+4])
	n += 4
	s.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.CookieMask = binary.BigEndian.Uint64(data[n:])
	n += 8

	err := s.Match.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal AggregateStatsRequest's Match", "data", data[n:])
		return err
	}
	n += int(s.Match.Len())
	return nil
}

// ofp_aggregate_stats_reply
type AggregateStatsReply struct {
	Stats
}

func NewAggregateStatsReply() *AggregateStatsReply {
	n := new(AggregateStatsReply)
	return n
}

func (a *AggregateStatsReply) Len() uint16 {
	return a.Stats.Len()
}

func (s *AggregateStatsReply) MarshalBinary() (data []byte, err error) {
	return s.Stats.MarshalBinary()
}

func (s *AggregateStatsReply) UnmarshalBinary(data []byte) error {
	return s.Stats.UnmarshalBinary(data)
}

// ofp_aggregate_stats_reply
type AggregateStats struct {
	PacketCount uint64
	ByteCount   uint64
	FlowCount   uint32
	pad         []uint8 // Size 4
}

func NewAggregateStats() *AggregateStats {
	s := new(AggregateStats)
	s.pad = make([]byte, 4)
	return s
}

func (s *AggregateStats) Len() (n uint16) {
	return 24
}

func (s *AggregateStats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	n := 0
	binary.BigEndian.PutUint64(data[n:], s.PacketCount)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.ByteCount)
	n += 8
	binary.BigEndian.PutUint32(data[n:], s.FlowCount)
	n += 4
	copy(data[n:], s.pad)
	n += 4
	return
}

func (s *AggregateStats) UnmarshalBinary(data []byte) error {
	n := 0
	s.PacketCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.ByteCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.FlowCount = binary.BigEndian.Uint32(data[n:])
	n += 4
	copy(s.pad, data[n:])
	return nil
}

// ofp_table_stats
type TableStats struct {
	TableId      uint8
	pad          []uint8 // Size 3
	ActiveCount  uint32
	LookupCount  uint64
	MatchedCount uint64
}

func NewTableStats() *TableStats {
	s := new(TableStats)
	s.pad = make([]byte, 3)
	return s
}

func (s *TableStats) Len() (n uint16) {
	return 24
}

func (s *TableStats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	n := 0
	data[n] = s.TableId
	n += 1
	n += 3 // Pad
	binary.BigEndian.PutUint32(data[n:], s.ActiveCount)
	n += 4
	binary.BigEndian.PutUint64(data[n:], s.LookupCount)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.MatchedCount)
	n += 8
	return
}

func (s *TableStats) UnmarshalBinary(data []byte) error {
	n := 0
	s.TableId = data[0]
	n += 1
	n += 3
	s.ActiveCount = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.LookupCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.MatchedCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	return nil
}

const (
	MAX_TABLE_NAME_LEN = 32
)

// ofp_port_multipart_request
type PortMultipartRequst struct {
	PortNo uint32
	pad    []uint8 // Size 4
}

func NewPortStatsRequest(port uint32) *PortMultipartRequst {
	p := new(PortMultipartRequst)
	p.pad = make([]byte, 4)
	p.PortNo = port
	return p
}

func (s *PortMultipartRequst) Len() (n uint16) {
	return 8
}

func (s *PortMultipartRequst) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	binary.BigEndian.PutUint32(data, s.PortNo)
	return
}

func (s *PortMultipartRequst) UnmarshalBinary(data []byte) error {
	s.PortNo = binary.BigEndian.Uint32(data)
	return nil
}

// ofp_port_stats
type PortStats struct {
	Length       uint16
	pad          []byte // Size 2
	PortNo       uint32
	DurationSec  uint32
	DurationNSec uint32
	RxPackets    uint64
	TxPackets    uint64
	RxBytes      uint64
	TxBytes      uint64
	RxDropped    uint64
	TxDropped    uint64
	RxErrors     uint64
	TxErrors     uint64
	Properties   []util.Message
}

func NewPortStats(port uint32) *PortStats {
	p := new(PortStats)
	p.pad = make([]byte, 2)
	p.PortNo = port
	return p
}

func (s *PortStats) Len() (n uint16) {
	n = 80
	for _, p := range s.Properties {
		n += p.Len()
	}
	return
}

func (s *PortStats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	var n uint16
	s.Length = s.Len()
	binary.BigEndian.PutUint16(data[n:], s.Length)
	n += 2
	n += 2 // Pad
	binary.BigEndian.PutUint32(data[n:], s.PortNo)
	n += 4
	binary.BigEndian.PutUint32(data[n:], s.DurationSec)
	n += 4
	binary.BigEndian.PutUint32(data[n:], s.DurationNSec)
	n += 4
	binary.BigEndian.PutUint64(data[n:], s.RxPackets)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.TxPackets)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.RxBytes)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.TxBytes)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.RxDropped)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.TxDropped)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.RxErrors)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.TxErrors)
	n += 8

	for _, p := range s.Properties {
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

func (s *PortStats) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	s.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2 // Pad
	s.PortNo = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.DurationSec = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.DurationNSec = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.RxPackets = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.TxPackets = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.RxBytes = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.TxBytes = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.RxDropped = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.TxDropped = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.RxErrors = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.TxErrors = binary.BigEndian.Uint64(data[n:])
	n += 8

	for n < s.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case PSPT_ETHERNET:
			p = new(PortStatsPropEthernet)
		case PSPT_OPTICAL:
			p = new(PortStatsPropOptical)
		case PSPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal PortStats's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		s.Properties = append(s.Properties, p)
	}

	return nil
}

// ofp_port_stats_prop_type
const (
	PSPT_ETHERNET     = 0      /* Ethernet property. */
	PSPT_OPTICAL      = 1      /* Optical property. */
	PSPT_EXPERIMENTER = 0xFFFF /* Experimenter property. */
)

// ofp_port_stats_prop_ethernet
type PortStatsPropEthernet struct {
	Header     PropHeader
	Pad        []byte // 4 bytes
	RxFrameErr uint64
	RxOverErr  uint64
	RxCrcErr   uint64
	Collisions uint64
}

func NewPortStatsPropEthernet() *PortStatsPropEthernet {
	p := new(PortStatsPropEthernet)
	p.Header.Type = PSPT_ETHERNET
	p.Pad = make([]byte, 4)
	return p
}

func (prop *PortStatsPropEthernet) Len() uint16 {
	n := prop.Header.Len()
	n += 36
	return n
}

func (prop *PortStatsPropEthernet) MarshalBinary() (data []byte, err error) {
	prop.Header.Length = prop.Len()
	data, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 36)
	n := 4
	binary.BigEndian.PutUint64(bytes[n:], prop.RxFrameErr)
	n += 8
	binary.BigEndian.PutUint64(bytes[n:], prop.RxOverErr)
	n += 8
	binary.BigEndian.PutUint64(bytes[n:], prop.RxCrcErr)
	n += 8
	binary.BigEndian.PutUint64(bytes[n:], prop.Collisions)
	n += 8

	data = append(data, bytes...)
	return
}

func (prop *PortStatsPropEthernet) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = prop.Header.Len()
	n += 4 // Pad

	prop.RxFrameErr = binary.BigEndian.Uint64(data[n:])
	n += 8
	prop.RxOverErr = binary.BigEndian.Uint64(data[n:])
	n += 8
	prop.RxCrcErr = binary.BigEndian.Uint64(data[n:])
	n += 8
	prop.Collisions = binary.BigEndian.Uint64(data[n:])
	n += 8

	return
}

// ofp_port_stats_prop_optical
type PortStatsPropOptical struct {
	Header      PropHeader
	Pad         []byte // 4 bytes
	Flags       uint32
	TxFreqLmda  uint32
	TxOffset    uint32
	TxGridSpan  uint32
	RxFreqLmda  uint32
	RxOffset    uint32
	RxGridSpan  uint32
	TxPwr       uint16
	RxPwr       uint16
	BiasCurrent uint16
	Temperature uint16
}

// ofp_port_stats_optical_flags
const (
	OSF_RX_TUNE = 1 << 0 /* Receiver tune info valid */
	OSF_TX_TUNE = 1 << 1 /* Transmit tune info valid */
	OSF_TX_PWR  = 1 << 2 /* TX Power is valid */
	OSF_RX_PWR  = 1 << 4 /* RX power is valid */
	OSF_TX_BIAS = 1 << 5 /* Transmit bias is valid */
	OSF_TX_TEMP = 1 << 6 /* TX Temp is valid */
)

func NewPortStatsPropOptical() *PortStatsPropOptical {
	p := new(PortStatsPropOptical)
	p.Header.Type = PSPT_OPTICAL
	p.Pad = make([]byte, 4)
	return p
}

func (prop *PortStatsPropOptical) Len() uint16 {
	n := prop.Header.Len()
	n += 40
	return n
}

func (prop *PortStatsPropOptical) MarshalBinary() (data []byte, err error) {
	prop.Header.Length = prop.Len()
	data, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 40)
	n := 4
	binary.BigEndian.PutUint32(bytes[n:], prop.Flags)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.TxFreqLmda)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.TxOffset)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.TxGridSpan)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.RxFreqLmda)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.RxOffset)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.RxGridSpan)
	n += 4
	binary.BigEndian.PutUint16(bytes[n:], prop.TxPwr)
	n += 2
	binary.BigEndian.PutUint16(bytes[n:], prop.RxPwr)
	n += 2
	binary.BigEndian.PutUint16(bytes[n:], prop.BiasCurrent)
	n += 2
	binary.BigEndian.PutUint16(bytes[n:], prop.Temperature)
	n += 2

	data = append(data, bytes...)

	return
}

func (prop *PortStatsPropOptical) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = prop.Header.Len()
	n += 4 // Pad

	prop.Flags = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.TxFreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.TxOffset = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.TxGridSpan = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.RxFreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.RxOffset = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.RxGridSpan = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.TxPwr = binary.BigEndian.Uint16(data[n:])
	n += 2
	prop.RxPwr = binary.BigEndian.Uint16(data[n:])
	n += 2
	prop.BiasCurrent = binary.BigEndian.Uint16(data[n:])
	n += 2
	prop.Temperature = binary.BigEndian.Uint16(data[n:])
	n += 2

	return
}

// ofp_queue_multipart_request
type QueueMultipartRequest struct {
	PortNo  uint32
	QueueId uint32
}

func NewQueueStatsRequest() *QueueMultipartRequest {
	q := new(QueueMultipartRequest)
	return q
}

func (s *QueueMultipartRequest) Len() (n uint16) {
	return 8
}

func (s *QueueMultipartRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	n := 0
	binary.BigEndian.PutUint32(data[n:], s.PortNo)
	n += 4
	binary.BigEndian.PutUint32(data[n:], s.QueueId)
	n += 4
	return
}

func (s *QueueMultipartRequest) UnmarshalBinary(data []byte) error {
	n := 0
	s.PortNo = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.QueueId = binary.BigEndian.Uint32(data[n:])
	return nil
}

// ofp_queue_stats
type QueueStats struct {
	Length       uint16
	Pad          []byte // 6 bytes
	PortNo       uint32
	QueueId      uint32
	TxBytes      uint64
	TxPackets    uint64
	TxErrors     uint64
	DurationSec  uint32
	DurationNSec uint32
	Properties   []util.Message
}

func NewQueueStats() *QueueStats {
	n := new(QueueStats)
	n.Pad = make([]byte, 6)
	return n
}

// ofp_queue_stats_prop_type
const (
	QSPT_EXPERIMENTER = 0xffff /* Experimenter defined property. */
)

func (s *QueueStats) Len() (n uint16) {
	n = 48
	for _, p := range s.Properties {
		n += p.Len()
	}
	return
}

func (s *QueueStats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 48)
	var n uint16
	s.Length = s.Len()

	binary.BigEndian.PutUint16(data[n:], s.Length)
	n += 2
	n += 6 // Pad
	binary.BigEndian.PutUint32(data[n:], s.PortNo)
	n += 4
	binary.BigEndian.PutUint32(data[n:], s.QueueId)
	n += 4
	binary.BigEndian.PutUint64(data[n:], s.TxBytes)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.TxPackets)
	n += 8
	binary.BigEndian.PutUint64(data[n:], s.TxErrors)
	n += 8
	binary.BigEndian.PutUint32(data[n:], s.DurationSec)
	n += 4
	binary.BigEndian.PutUint32(data[n:], s.DurationNSec)
	n += 4

	for _, p := range s.Properties {
		var b []byte
		b, err = p.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, b...)
		n += p.Len()
	}
	return
}

func (s *QueueStats) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	s.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 6 // Pad
	s.PortNo = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.QueueId = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.TxBytes = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.TxPackets = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.TxErrors = binary.BigEndian.Uint64(data[n:])
	n += 8
	s.DurationSec = binary.BigEndian.Uint32(data[n:])
	n += 4
	s.DurationNSec = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < s.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case QSPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal QueueStats's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		s.Properties = append(s.Properties, p)
	}

	return nil
}

const (
	TFPT_INSTRUCTIONS         = 0      // Instructions property.
	TFPT_INSTRUCTIONS_MISS    = 1      // Instructions for table-miss.
	TFPT_NEXT_TABLES          = 2      // Next Table property.
	TFPT_NEXT_TABLES_MISS     = 3      // Next Table for table-miss.
	TFPT_WRITE_ACTIONS        = 4      // Write Actions property.
	TFPT_WRITE_ACTIONS_MISS   = 5      // Write Actions for table-miss.
	TFPT_APPLY_ACTIONS        = 6      // Apply Actions property.
	TFPT_APPLY_ACTIONS_MISS   = 7      // Apply Actions for table-miss
	TFPT_MATCH                = 8      // Match property.
	TFPT_WILDCARDS            = 10     // Wildcards property.
	TFPT_WRITE_SETFIELD       = 12     // Write Set-Field property.
	TFPT_WRITE_SETFIELD_MISS  = 13     // Write Set-Field for table-miss.
	TFPT_APPLY_SETFIELD       = 14     // Apply Set-Field property.
	TFPT_APPLY_SETFIELD_MISS  = 15     // Apply Set-Field for table-miss.
	TFPT_TABLE_SYNC_FROM      = 16     // Table synchronisation property.
	TFPT_WRITE_COPYFIELD      = 18     // Write Copy-Field property.
	TFPT_WRITE_COPYFIELD_MISS = 19     // Write Copy-Field for table-miss.
	TFPT_APPLY_COPYFIELD      = 20     // Apply Copy-Field property.
	TFPT_APPLY_COPYFIELD_MISS = 21     // Apply Copy-Field for table-miss.
	TFPT_PACKET_TYPES         = 22     // Packet types property.
	TFPT_EXPERIMENTER         = 0xfffe // EXPERIMENTER PROPERTY.
	TFPT_EXPERIMENTER_MISS    = 0xffff // EXPERIMENTER FOR TABLE-MISS.
)

/* Type could be:
 *		TFPT_INSTRUCTIONS
 *		TFPT_INSTRUCTIONS_MISS
 */
func NewInstructionProperty(Type uint16) *InstructionProperty {
	n := new(InstructionProperty)
	n.Type = Type
	return n
}

/* Type could be:
 *		TFPT_NEXT_TABLES
 *		TFPT_NEXT_TABLES_MISS
 *		TFPT_TABLE_SYNC_FROM
 */
func NewNextTableProperty(Type uint16) *NextTableProperty {
	n := new(NextTableProperty)
	n.Type = Type
	return n
}

/* Type could be:
 *		TFPT_APPLY_ACTIONS
 *		TFPT_APPLY_ACTIONS_MISS
 *		TFPT_WRITE_ACTIONS
 *		TFPT_WRITE_ACTIONS_MISS
 */
func NewActionProperty(Type uint16) *ActionProperty {
	n := new(ActionProperty)
	n.Type = Type
	return n
}

/* Type could be:
 *		TFPT_MATCH
 *		TFPT_WILDCARDS
 *		TFPT_WRITE_SETFIELD
 *		TFPT_WRITE_SETFIELD_MISS
 *		TFPT_APPLY_SETFIELD
 *		TFPT_APPLY_SETFIELD_MISS
 *		TFPT_WRITE_COPYFIELD
 *		TFPT_WRITE_COPYFIELD_MISS
 *		TFPT_APPLY_COPYFIELD
 *		TFPT_APPLY_COPYFIELD_MISS
 */
func NewSetFieldProperty(Type uint16) *SetFieldProperty {
	n := new(SetFieldProperty)
	n.Type = Type
	return n
}

/* Type could be:
 *		TFPT_EXPERIMENTER
 *		TFPT_EXPERIMENTER_MISS
 */
func NewTableExperimenterProperty(Type uint16) *TableExperimenterProperty {
	n := new(TableExperimenterProperty)
	n.Type = Type
	return n
}

type OFTablePropertyHeader struct {
	Type   uint16
	Length uint16
}

func (h *OFTablePropertyHeader) Len() uint16 {
	return 4
}

func (h *OFTablePropertyHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, h.Len())
	n := 0
	binary.BigEndian.PutUint16(data[n:], h.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], h.Length)
	return
}

func (h *OFTablePropertyHeader) UnmarshalBinary(data []byte) error {
	if len(data) < int(h.Len()) {
		return fmt.Errorf("the []byte is too short to unmarshal a full OFTablePropertyHeader message")
	}
	n := 0
	h.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	h.Length = binary.BigEndian.Uint16(data[n:])
	return nil
}

// ofp_table_feature_prop_instructions
type InstructionProperty struct {
	OFTablePropertyHeader
	Instructions []InstructionId
}

func (p *InstructionProperty) AddInstructionId(i InstructionId) {
	p.Instructions = append(p.Instructions, i)
	return
}

func (p *InstructionProperty) Len() uint16 {
	n := p.OFTablePropertyHeader.Len()
	for _, instr := range p.Instructions {
		n += instr.Len()
	}
	return (n + 7) / 8 * 8
}

func (p *InstructionProperty) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0
	header, err := p.OFTablePropertyHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], header)
	n += 4
	for _, instr := range p.Instructions {
		b, err := instr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(instr.Len())
	}
	return data, nil
}

func (p *InstructionProperty) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("the []byte is too short to unmarshal OFTablePropertyHeader message")
	}
	n := 0
	header := new(OFTablePropertyHeader)
	err := header.UnmarshalBinary(data[n:])
	p.OFTablePropertyHeader = *header
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return fmt.Errorf("the []byte is too short to unmarshal a full InstructionProperty message")
	}
	n += 4
	p.Instructions = make([]InstructionId, 0)
	for n < int(p.Length) {
		instr := new(InstructionId)
		err := instr.UnmarshalBinary(data[n : n+4])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal InstructionProperty's Instructions", "data", data[n:])
			return err
		}
		p.Instructions = append(p.Instructions, *instr)
		n += int(instr.Len())
	}
	return nil
}

// ofp_instruction_id
type InstructionId struct {
	Type   uint16
	Length uint16
	Data   []byte
}

func NewInstructionId(t uint16) *InstructionId {
	n := new(InstructionId)
	n.Type = t
	n.Data = make([]byte, 0)
	return n
}

func (i *InstructionId) Len() (n uint16) {
	n = 4
	n += uint16(len(i.Data))
	return n
}

func (i *InstructionId) MarshalBinary() (data []byte, err error) {
	data = make([]byte, i.Len())
	n := 0
	i.Length = i.Len()
	binary.BigEndian.PutUint16(data[n:], i.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], i.Length)
	n += 2
	copy(data[n:], i.Data)

	return
}

func (i *InstructionId) UnmarshalBinary(data []byte) (err error) {
	n := 0
	i.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	i.Length = binary.BigEndian.Uint16(data[n:])
	n += 2

	i.Data = make([]byte, i.Length-4)
	copy(i.Data, data[n:])

	return
}

type NextTableProperty struct {
	OFTablePropertyHeader
	TableIDs []uint8
}

func (p *NextTableProperty) Len() uint16 {
	return (p.OFTablePropertyHeader.Len() + uint16(len(p.TableIDs)) + 7) / 8 * 8
}

func (p *NextTableProperty) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0
	header, err := p.OFTablePropertyHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], header)
	n += 4
	for _, t := range p.TableIDs {
		data[n] = t
		n += 1
	}
	return
}

func (p *NextTableProperty) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("the []byte is too short to unmarshal OFTablePropertyHeader message")
	}
	n := 0
	header := new(OFTablePropertyHeader)
	err := header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	p.OFTablePropertyHeader = *header
	if len(data) < int(p.Length) {
		return fmt.Errorf("the []byte is too short to unmarshal a full NextTableProperty message")
	}
	n += 4
	p.TableIDs = make([]uint8, 0)
	for n < int(p.Length) {
		p.TableIDs = append(p.TableIDs, data[n])
		n += 1
	}
	return nil
}

type ActionProperty struct {
	OFTablePropertyHeader
	Actions []ActionId
}

func (p *ActionProperty) AddActionId(a ActionId) {
	p.Actions = append(p.Actions, a)
	return
}

func (p *ActionProperty) Len() uint16 {
	n := p.OFTablePropertyHeader.Len()
	for _, act := range p.Actions {
		n += act.Len()
	}
	return uint16(n+7) / 8 * 8
}

func (p *ActionProperty) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0
	header, err := p.OFTablePropertyHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], header)
	n += 4
	for _, act := range p.Actions {
		b, err := act.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(act.Len())
	}
	return data, nil
}

func (p *ActionProperty) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("the []byte is too short to unmarshal OFTablePropertyHeader message")
	}
	n := 0
	header := new(OFTablePropertyHeader)
	err := header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	p.OFTablePropertyHeader = *header
	if len(data) < int(p.Length) {
		return fmt.Errorf("the []byte is too short to unmarshal a full ActionProperty message")
	}
	n += 4
	p.Actions = make([]ActionId, 0)
	for n < int(p.Length) {
		act := new(ActionId)
		err := act.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal ActionProperty's Actions", "data", data[n:])
			return err
		}
		p.Actions = append(p.Actions, *act)
		n += int(act.Len())
	}
	return nil
}

// ofp_action_id
type ActionId struct {
	Type   uint16
	Length uint16
	Data   []byte
}

func NewActionId(t uint16) *ActionId {
	n := new(ActionId)
	n.Data = make([]byte, 0)
	n.Type = t
	return n
}

func (a *ActionId) Len() (n uint16) {
	n = 4
	n += uint16(len(a.Data))
	return n
}

func (a *ActionId) MarshalBinary() (data []byte, err error) {
	data = make([]byte, a.Len())
	n := 0
	a.Length = a.Len()
	binary.BigEndian.PutUint16(data[n:], a.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], a.Length)
	n += 2
	copy(data[n:], a.Data)

	return
}

func (a *ActionId) UnmarshalBinary(data []byte) (err error) {
	n := 0
	a.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	a.Length = binary.BigEndian.Uint16(data[n:])
	n += 2

	a.Data = make([]byte, a.Length-4)
	copy(a.Data, data[n:])

	return
}

type SetFieldProperty struct {
	OFTablePropertyHeader
	IDs []uint32
}

func (p *SetFieldProperty) Len() uint16 {
	n := p.OFTablePropertyHeader.Len()
	n += 4 * uint16(len(p.IDs))
	return uint16(n+7) / 8 * 8
}

func (p *SetFieldProperty) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0
	header, err := p.OFTablePropertyHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], header)
	n += 4
	for _, oid := range p.IDs {
		binary.BigEndian.PutUint32(data[n:], oid)
		n += 4
	}
	return data, nil
}

func (p *SetFieldProperty) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("the []byte is too short to unmarshal OFTablePropertyHeader message")
	}
	n := 0
	header := new(OFTablePropertyHeader)
	err := header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	p.OFTablePropertyHeader = *header
	if len(data) < int(p.Length) {
		return fmt.Errorf("the []byte is too short to unmarshal a full SetFieldProperty message")
	}
	n += 4
	p.IDs = make([]uint32, 0)
	for n < int(p.Length) {
		p.IDs = append(p.IDs, binary.BigEndian.Uint32(data[n:]))
		n += 4
	}
	return nil
}

type SetFieldPacketTypes struct {
	OFTablePropertyHeader
	OXMs []uint32
}

func (p *SetFieldPacketTypes) Len() uint16 {
	n := p.OFTablePropertyHeader.Len()
	n += 4 * uint16(len(p.OXMs))
	return uint16(n+7) / 8 * 8
}

func (p *SetFieldPacketTypes) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0
	header, err := p.OFTablePropertyHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], header)
	n += 4
	for _, o := range p.OXMs {
		binary.BigEndian.PutUint32(data[n:], o)
		n += 4
	}
	return data, nil
}

func (p *SetFieldPacketTypes) UnmarshalBinary(data []byte) error {
	n := 0
	header := new(OFTablePropertyHeader)
	err := header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	p.OFTablePropertyHeader = *header
	n += 4
	p.OXMs = make([]uint32, 0)
	for n < int(p.Length) {
		p.OXMs = append(p.OXMs, binary.BigEndian.Uint32(data[n:]))
		n += 4
	}
	return nil
}

type TableExperimenterProperty struct {
	OFTablePropertyHeader
	Experimenter     uint32
	ExperimenterType uint32
	ExperimenterData []uint32
}

func (p *TableExperimenterProperty) Len() uint16 {
	return p.OFTablePropertyHeader.Len() + 8 + uint16(4*len(p.ExperimenterData)+7)/8*8
}

func (p *TableExperimenterProperty) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	n := 0
	header, err := p.OFTablePropertyHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], header)
	n += 4
	binary.BigEndian.PutUint32(data[n:], p.Experimenter)
	n += 4
	binary.BigEndian.PutUint32(data[n:], p.ExperimenterType)
	n += 4
	for _, d := range p.ExperimenterData {
		binary.BigEndian.PutUint32(data[n:], d)
		n += 4
	}
	return data, nil
}

func (p *TableExperimenterProperty) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("the []byte is too short to unmarshal OFTablePropertyHeader message")
	}
	n := 0
	header := new(OFTablePropertyHeader)
	err := header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	p.OFTablePropertyHeader = *header
	if len(data) < int(p.Length) {
		return fmt.Errorf("the []byte is too short to unmarshal a full TableExperimenterProperty message")
	}
	n += 4
	p.Experimenter = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.ExperimenterType = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.ExperimenterData = make([]uint32, 0)
	for n < int(p.Length) {
		p.ExperimenterData = append(p.ExperimenterData, binary.BigEndian.Uint32(data[n:]))
		n += 4
	}
	return nil
}

// ofp_table_features
type TableFeatures struct {
	Length        uint16
	TableID       uint8
	Command       uint8
	Features      uint32
	Name          []byte // MAX_TABLE_NAME_LEN
	MetadataMatch uint64
	MetadataWrite uint64
	Capabilities  uint32
	MaxEntries    uint32
	Properties    []util.Message
}

// ofp_table_feature_flag
const (
	TFF_INGRESS_TABLE = 1 << 0 /* Can be configured as ingress table. */
	TFF_EGRESS_TABLE  = 1 << 1 /* Can be configured as egress table. */
	TFF_FIRST_EGRESS  = 1 << 4 /* Is the first egress table. */
)

// ofp_table_features_command
const (
	TFC_REPLACE = 0 /* Replace full pipeline. */
	TFC_MODIFY  = 1 /* Modify flow tables capabilities. */
	TFC_ENABLE  = 2 /* Enable flow tables in the pipeline. */
	TFC_DISABLE = 3 /* Disable flow tables in pipeline. */
)

func NewTableFeatures(t uint8) *TableFeatures {
	n := new(TableFeatures)
	n.TableID = t
	n.Name = make([]byte, MAX_TABLE_NAME_LEN)
	return n
}

func (f *TableFeatures) Len() uint16 {
	n := uint16(64)
	for _, p := range f.Properties {
		n += p.Len()
	}
	return n
}

func (f *TableFeatures) MarshalBinary() (data []byte, err error) {
	data = make([]byte, f.Len())
	n := 0
	f.Length = f.Len()
	binary.BigEndian.PutUint16(data[n:], f.Length)
	n += 2
	data[n] = f.TableID
	n += 1
	data[n] = f.Command
	n += 1
	binary.BigEndian.PutUint32(data[n:], f.Features)
	n += 4
	copy(data[n:], f.Name[:32])
	n += 32
	binary.BigEndian.PutUint64(data[n:], f.MetadataMatch)
	n += 8
	binary.BigEndian.PutUint64(data[n:], f.MetadataWrite)
	n += 8
	binary.BigEndian.PutUint32(data[n:], f.Capabilities)
	n += 4
	binary.BigEndian.PutUint32(data[n:], f.MaxEntries)
	n += 4
	for _, p := range f.Properties {
		pd, err := p.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], pd)
		n += int(p.Len())
	}
	return
}

func (f *TableFeatures) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("the []byte is too short to unmarshal TableFeatures message Length")
	}
	n := 0
	f.Length = binary.BigEndian.Uint16(data[n:])
	if len(data) < int(f.Length) {
		return fmt.Errorf("the []byte is too short to unmarshal a full TableFeatures message")
	}
	n += 2
	f.TableID = data[n]
	n += 1
	f.Command = data[n]
	n += 1
	f.Features = binary.BigEndian.Uint32(data[n:])
	n += 4
	f.Name = make([]byte, MAX_TABLE_NAME_LEN)
	copy(f.Name, data[n:n+32])
	n += 32
	f.MetadataMatch = binary.BigEndian.Uint64(data[n:])
	n += 8
	f.MetadataWrite = binary.BigEndian.Uint64(data[n:])
	n += 8
	f.Capabilities = binary.BigEndian.Uint32(data[n:])
	n += 4
	f.MaxEntries = binary.BigEndian.Uint32(data[n:])
	n += 4
	f.Properties = make([]util.Message, 0)
	for n < int(f.Length) {
		t := binary.BigEndian.Uint16(data[n:])
		var p util.Message
		switch t {
		case TFPT_INSTRUCTIONS:
			fallthrough
		case TFPT_INSTRUCTIONS_MISS:
			p = new(InstructionProperty)
		case TFPT_NEXT_TABLES:
			fallthrough
		case TFPT_NEXT_TABLES_MISS:
			fallthrough
		case TFPT_TABLE_SYNC_FROM:
			p = new(NextTableProperty)
		case TFPT_APPLY_ACTIONS:
			fallthrough
		case TFPT_APPLY_ACTIONS_MISS:
			fallthrough
		case TFPT_WRITE_ACTIONS:
			fallthrough
		case TFPT_WRITE_ACTIONS_MISS:
			p = new(ActionProperty)
		case TFPT_MATCH:
			fallthrough
		case TFPT_WILDCARDS:
			fallthrough
		case TFPT_WRITE_SETFIELD:
			fallthrough
		case TFPT_WRITE_SETFIELD_MISS:
			fallthrough
		case TFPT_APPLY_SETFIELD:
			fallthrough
		case TFPT_APPLY_SETFIELD_MISS:
			fallthrough
		case TFPT_WRITE_COPYFIELD:
			fallthrough
		case TFPT_WRITE_COPYFIELD_MISS:
			fallthrough
		case TFPT_APPLY_COPYFIELD:
			fallthrough
		case TFPT_APPLY_COPYFIELD_MISS:
			p = new(SetFieldProperty)
		case TFPT_EXPERIMENTER:
			fallthrough
		case TFPT_EXPERIMENTER_MISS:
			p = new(TableExperimenterProperty)
		}
		err := p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal TableFeatures's Properties", "data", data[n:])
			return err
		}
		f.Properties = append(f.Properties, p)
		n += int(p.Len())
	}
	return nil
}

// ofp_flow_desc
type FlowDesc struct {
	Length      uint16
	Pad2        uint16
	TableId     uint8
	Pad         uint8
	Priority    uint16
	IdleTimeout uint16
	HardTimeout uint16
	Flags       uint16
	Importance  uint16
	Cookie      uint64
	Match
	Stats
	Instructions []Instruction
}

func (f *FlowDesc) AddInstruction(i Instruction) {
	f.Instructions = append(f.Instructions, i)
}

func NewFlowDesc() *FlowDesc {
	n := new(FlowDesc)
	n.Match = *NewMatch()
	return n
}

func (f *FlowDesc) Len() uint16 {
	var n uint16 = 24
	n += f.Match.Len()
	n += f.Stats.Len()
	for _, i := range f.Instructions {
		n += i.Len()
	}
	return n
}

func (f *FlowDesc) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 24)
	n := 0

	f.Length = f.Len()
	binary.BigEndian.PutUint16(data[n:], f.Length)
	n += 2
	n += 2 // Pad

	data[n] = f.TableId
	n++
	n++ // Pad

	binary.BigEndian.PutUint16(data[n:], f.Priority)
	n += 2

	binary.BigEndian.PutUint16(data[n:], f.IdleTimeout)
	n += 2

	binary.BigEndian.PutUint16(data[n:], f.HardTimeout)
	n += 2

	binary.BigEndian.PutUint16(data[n:], f.Flags)
	n += 2

	binary.BigEndian.PutUint16(data[n:], f.Importance)
	n += 2

	binary.BigEndian.PutUint64(data[n:], f.Cookie)
	n += 8

	var bytes []byte
	bytes, err = f.Match.MarshalBinary()
	if err != nil {
		return
	}
	data = append(data, bytes...)

	bytes, err = f.Stats.MarshalBinary()
	if err != nil {
		return
	}
	data = append(data, bytes...)

	for _, i := range f.Instructions {
		bytes, err = i.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}
	return
}

func (f *FlowDesc) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	f.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2 // Pad

	f.TableId = data[n]
	n++
	n++ // Pad

	f.Priority = binary.BigEndian.Uint16(data[n:])
	n += 2

	f.IdleTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2

	f.HardTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2

	f.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2

	f.Importance = binary.BigEndian.Uint16(data[n:])
	n += 2

	f.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8

	err = f.Match.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal FlowDesc's Match", "data", data[n:])
		return
	}
	m_len := f.Match.Len()
	klog.V(4).InfoS("Match Len", "value", m_len)
	n += m_len

	klog.V(4).InfoS("Data passed to Stats UnmarshalBinary", "data", data[n:])
	err = f.Stats.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal FlowDesc's Stats", "data", data[n:])
		return
	}
	n += f.Stats.Len()

	for n < f.Length {
		i, err := DecodeInstr(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal FlowDesc's Instructions", "data", data[n:])
			return err
		}
		f.Instructions = append(f.Instructions, i)
		n += i.Len()
	}
	return
}

// ofp_group_multipart_request
type GroupMultipartRequest struct {
	GroupId uint32
	Pad     []byte // 4 bytes
}

func NewGroupMultipartRequest(id uint32) *GroupMultipartRequest {
	n := new(GroupMultipartRequest)
	n.GroupId = id
	n.Pad = make([]byte, 4)
	return n
}

func (s *GroupMultipartRequest) Len() (n uint16) {
	return 8
}

func (s *GroupMultipartRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	binary.BigEndian.PutUint32(data, s.GroupId)
	return
}

func (s *GroupMultipartRequest) UnmarshalBinary(data []byte) (err error) {
	s.GroupId = binary.BigEndian.Uint32(data)
	return
}

// ofp_group_stats
type GroupStats struct {
	Length       uint16
	Pad          []byte // 2 bytes
	GroupId      uint32
	RefCount     uint32
	Pad2         []byte // 4 bytes
	PacketCount  uint64
	ByteCount    uint64
	DurationSec  uint32
	DurationNSec uint32
	Stats        []BucketCounter
}

func NewGroupStats() *GroupStats {
	n := new(GroupStats)
	n.Pad = make([]byte, 2)
	n.Pad2 = make([]byte, 4)
	return n
}

func (g *GroupStats) Len() (n uint16) {
	n = 40
	for _, s := range g.Stats {
		n += s.Len()
	}
	return
}

func (g *GroupStats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 40)
	n := 0

	g.Length = g.Len()
	binary.BigEndian.PutUint16(data[n:], g.Length)
	n += 2
	n += 2 // Pad

	binary.BigEndian.PutUint32(data[n:], g.GroupId)
	n += 4

	binary.BigEndian.PutUint32(data[n:], g.RefCount)
	n += 4
	n += 4 // Pad2

	binary.BigEndian.PutUint64(data[n:], g.PacketCount)
	n += 8

	binary.BigEndian.PutUint64(data[n:], g.ByteCount)
	n += 8

	binary.BigEndian.PutUint32(data[n:], g.DurationSec)
	n += 4

	binary.BigEndian.PutUint32(data[n:], g.DurationNSec)
	n += 4

	for _, s := range g.Stats {
		var bytes []byte
		bytes, err = s.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}
	return
}

func (g *GroupStats) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	g.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2 // Pad

	g.GroupId = binary.BigEndian.Uint32(data[n:])
	n += 4

	g.RefCount = binary.BigEndian.Uint32(data[n:])
	n += 4
	n += 4 // Pad2

	g.PacketCount = binary.BigEndian.Uint64(data[n:])
	n += 8

	g.ByteCount = binary.BigEndian.Uint64(data[n:])
	n += 8

	g.DurationSec = binary.BigEndian.Uint32(data[n:])
	n += 4

	g.DurationNSec = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < g.Length {
		b := new(BucketCounter)
		err = b.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal GroupStats's Stats", "data", data[n:])
			return
		}
		g.Stats = append(g.Stats, *b)
		n += b.Len()
	}
	return
}

// ofp_bucket_counter
type BucketCounter struct {
	PacketCount uint64
	ByteCount   uint64
}

func NewBucketCounter() *BucketCounter {
	n := new(BucketCounter)
	return n
}

func (b *BucketCounter) Len() uint16 {
	return 16
}

func (g *BucketCounter) MarshalBinary() (data []byte, err error) {
	var n uint16
	data = make([]byte, g.Len())
	binary.BigEndian.PutUint64(data[n:], g.PacketCount)
	n += 8

	binary.BigEndian.PutUint64(data[n:], g.ByteCount)
	n += 8
	return
}

func (g *BucketCounter) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	g.PacketCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	g.ByteCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	return
}

// ofp_group_desc
type GroupDesc struct {
	Length         uint16
	Type           uint8
	Pad            uint8
	GroupId        uint32
	BucketArrayLen uint16
	Pad2           []byte // 6 bytes
	Buckets        []Bucket
	Properties     []util.Message
}

func NewGroupDesc() *GroupDesc {
	n := new(GroupDesc)
	n.Pad2 = make([]byte, 6)
	return n
}

// Add a bucket to group desc
func (g *GroupDesc) AddBucket(bkt Bucket) {
	g.Buckets = append(g.Buckets, bkt)
	g.BucketArrayLen += bkt.Len()
}

func (g *GroupDesc) Len() uint16 {
	var n uint16 = 16
	for _, b := range g.Buckets {
		n += b.Len()
	}
	for _, p := range g.Properties {
		n += p.Len()
	}
	return n
}

func (g *GroupDesc) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	var n uint16

	g.Length = g.Len()
	binary.BigEndian.PutUint16(data[n:], g.Length)
	n += 2

	data[n] = g.Type
	n++
	n++ // Pad

	binary.BigEndian.PutUint32(data[n:], g.GroupId)
	n += 4
	binary.BigEndian.PutUint16(data[n:], g.BucketArrayLen)
	n += 2
	n += 6 // 6 bytes

	for _, b := range g.Buckets {
		var bytes []byte
		bytes, err = b.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}

	for _, p := range g.Properties {
		var bytes []byte
		bytes, err = p.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}
	return
}

func (g *GroupDesc) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	g.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	g.Type = data[n]
	n++
	n++ // Pad

	g.GroupId = binary.BigEndian.Uint32(data[n:])
	n += 4
	g.BucketArrayLen = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 6 // 6 bytes

	for n < g.BucketArrayLen+16 {
		b := new(Bucket)
		err = b.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal GroupDesc's Buckets", "data", data[n:])
			return
		}
		g.Buckets = append(g.Buckets, *b)
		n += b.Len()
	}

	for n < g.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case GPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal GroupDesc's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		g.Properties = append(g.Properties, p)
	}
	return
}

// ofp_group_features
type GroupFeatures struct {
	Types        uint32
	Capabilities uint32
	MaxGroups    []uint32 // size 4
	Actions      []uint32 // size 4
}

// ofp_group_capabilities
const (
	GFC_SELECT_WEIGHT   = 1 << 0 /* Support weight for select groups */
	GFC_SELECT_LIVENESS = 1 << 1 /* Support liveness for select groups */
	GFC_CHAINING        = 1 << 2 /* Support chaining groups */
	GFC_CHAINING_CHECKS = 1 << 3 /* Check chaining for loops and delete */
)

func NewGroupFeatures() *GroupFeatures {
	n := new(GroupFeatures)
	n.MaxGroups = make([]uint32, 4)
	n.Actions = make([]uint32, 4)
	return n
}

func (g *GroupFeatures) Len() uint16 {
	return 40
}

func (g *GroupFeatures) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 40)
	var n uint16

	binary.BigEndian.PutUint32(data[n:], g.Types)
	n += 4
	binary.BigEndian.PutUint32(data[n:], g.Capabilities)
	n += 4

	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(data[n:], g.MaxGroups[i])
		n += 4
	}
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(data[n:], g.Actions[i])
		n += 4
	}
	return
}

func (g *GroupFeatures) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	g.Types = binary.BigEndian.Uint32(data[n:])
	n += 4
	g.Capabilities = binary.BigEndian.Uint32(data[n:])
	n += 4

	for i := 0; i < 4; i++ {
		g.MaxGroups[i] = binary.BigEndian.Uint32(data[n:])
		n += 4
	}
	for i := 0; i < 4; i++ {
		g.Actions[i] = binary.BigEndian.Uint32(data[n:])
		n += 4
	}
	return
}

// ofp_meter_multipart_request
type MeterMultipartRequest struct {
	MeterId uint32
	Pad     []byte // 4 bytes
}

func NewMeterMultipartRequest(id uint32) *MeterMultipartRequest {
	n := new(MeterMultipartRequest)
	n.Pad = make([]byte, 4)
	n.MeterId = id
	return n
}

func (m *MeterMultipartRequest) Len() uint16 {
	return 8
}

func (m *MeterMultipartRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint32(data[0:], m.MeterId)
	return
}

func (m *MeterMultipartRequest) UnmarshalBinary(data []byte) (err error) {
	m.MeterId = binary.BigEndian.Uint32(data)
	return
}

// ofp_meter_stats
type MeterStats struct {
	MeterId       uint32
	Length        uint16
	Pad           []byte // 6 bytes
	RefCount      uint32
	PacketInCount uint64
	ByteInCount   uint64
	DurationSec   uint32
	DurationNSec  uint32
	BandStats     []MeterBandStats
}

func NewMeterStats(id uint32) *MeterStats {
	n := new(MeterStats)
	n.Pad = make([]byte, 6)
	n.MeterId = id
	return n
}

func (m *MeterStats) AddBandStats(s MeterBandStats) {
	m.BandStats = append(m.BandStats, s)
	return
}

func (m *MeterStats) Len() uint16 {
	var n uint16 = 40
	for _, b := range m.BandStats {
		n += b.Len()
	}
	return n
}

func (m *MeterStats) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 40)

	var n uint16
	m.Length = m.Len()
	binary.BigEndian.PutUint32(data[n:], m.MeterId)
	n += 4
	binary.BigEndian.PutUint16(data[n:], m.Length)
	n += 2
	n += 6 // Pad
	binary.BigEndian.PutUint32(data[n:], m.RefCount)
	n += 4
	binary.BigEndian.PutUint64(data[n:], m.PacketInCount)
	n += 8
	binary.BigEndian.PutUint64(data[n:], m.ByteInCount)
	n += 8
	binary.BigEndian.PutUint32(data[n:], m.DurationSec)
	n += 4
	binary.BigEndian.PutUint32(data[n:], m.DurationNSec)
	n += 4

	for _, b := range m.BandStats {
		var bytes []byte
		bytes, err = b.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}
	return
}

func (m *MeterStats) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	m.MeterId = binary.BigEndian.Uint32(data[n:])
	n += 4
	m.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 6 // Pad
	m.RefCount = binary.BigEndian.Uint32(data[n:])
	n += 4
	m.PacketInCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	m.ByteInCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	m.DurationSec = binary.BigEndian.Uint32(data[n:])
	n += 4
	m.DurationNSec = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < m.Length {
		stats := new(MeterBandStats)
		err = stats.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal MeterStats's BandStats", "data", data[n:])
			return err
		}
		m.BandStats = append(m.BandStats, *stats)
		n += stats.Len()
	}
	return
}

// ofp_meter_band_stats
type MeterBandStats struct {
	PacketBandCount uint64
	ByteBandCount   uint64
}

func NewMeterBandStats() *MeterBandStats {
	n := new(MeterBandStats)
	return n
}

func (m *MeterBandStats) Len() uint16 {
	return 16
}

func (m *MeterBandStats) MarshalBinary() (data []byte, err error) {
	var n uint16
	data = make([]byte, m.Len())
	binary.BigEndian.PutUint64(data[n:], m.PacketBandCount)
	n += 8

	binary.BigEndian.PutUint64(data[n:], m.ByteBandCount)
	n += 8
	return
}

func (m *MeterBandStats) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	m.PacketBandCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	m.ByteBandCount = binary.BigEndian.Uint64(data[n:])
	n += 8
	return
}

// ofp_meter_desc
type MeterDesc struct {
	Length  uint16
	Flags   uint16
	MeterId uint32
	Bands   []util.Message // ofp_meter_band_header + body
}

func (m *MeterDesc) AddBand(b util.Message) {
	m.Bands = append(m.Bands, b)
	return
}

func NewMeterDesc(id uint32) *MeterDesc {
	n := new(MeterDesc)
	n.MeterId = id
	return n
}

func (m *MeterDesc) Len() uint16 {
	var n uint16 = 8
	for _, b := range m.Bands {
		n += b.Len()
	}
	return n
}

func (m *MeterDesc) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)

	var n uint16
	m.Length = m.Len()
	binary.BigEndian.PutUint16(data[n:], m.Length)
	n += 2
	binary.BigEndian.PutUint16(data[n:], m.Flags)
	n += 2
	binary.BigEndian.PutUint32(data[n:], m.MeterId)
	n += 4

	for _, b := range m.Bands {
		var bytes []byte
		bytes, err = b.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}
	return
}

func (m *MeterDesc) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	m.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	m.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	m.MeterId = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < m.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case MBT_DROP:
			p = new(MeterBandDrop)
		case MBT_DSCP_REMARK:
			p = new(MeterBandDSCP)
		case MBT_EXPERIMENTER:
			p = new(MeterBandExperimenter)
		default:
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal MeterDesc's Bands", "data", data[n:])
			return
		}
		m.Bands = append(m.Bands, p)
		n += p.Len()
	}
	return
}

// ofp_meter_features
type MeterFeatures struct {
	MaxMeter     uint32
	BandTypes    uint32
	Capabilities uint32
	MaxBands     uint8
	MaxColor     uint8
	Pad          []byte // 2 bytes
	Features     uint32
	Pad2         []byte // 4 bytes
}

// ofp_meter_feature_flags
const (
	MFF_ACTION_SET   = 1 << 0 /* Support meter action in action set. */
	MFF_ANY_POSITION = 1 << 1 /* Support any position in action list. */
	MFF_MULTI_LIST   = 1 << 2 /* Support multiple actions in action list. */
)

func NewMeterFeatures() *MeterFeatures {
	n := new(MeterFeatures)
	n.Pad = make([]byte, 2)
	n.Pad2 = make([]byte, 4)
	return n
}

func (m *MeterFeatures) Len() uint16 {
	return 24
}

func (m *MeterFeatures) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())

	var n uint16
	binary.BigEndian.PutUint32(data[n:], m.MaxMeter)
	n += 4
	binary.BigEndian.PutUint32(data[n:], m.BandTypes)
	n += 4
	binary.BigEndian.PutUint32(data[n:], m.Capabilities)
	n += 4
	data[n] = m.MaxBands
	n++
	data[n] = m.MaxColor
	n++
	n += 2 // Pad
	binary.BigEndian.PutUint32(data[n:], m.Features)
	n += 4

	return
}

func (m *MeterFeatures) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	m.MaxMeter = binary.BigEndian.Uint32(data[n:])
	n += 4
	m.BandTypes = binary.BigEndian.Uint32(data[n:])
	n += 4
	m.Capabilities = binary.BigEndian.Uint32(data[n:])
	n += 4
	m.MaxBands = data[n]
	n++
	m.MaxColor = data[n]
	n++
	n += 2 // Pad
	m.Features = binary.BigEndian.Uint32(data[n:])
	n += 4
	return
}

// ofp_port_multipart_request
type PortMultipartRequest struct {
	PortNo uint32
	Pad    []byte // 4 bytes
}

func NewPortMultipartRequest(num uint32) *PortMultipartRequest {
	n := new(PortMultipartRequest)
	n.PortNo = num
	return n
}

func (p *PortMultipartRequest) Len() uint16 {
	return 8
}

func (p *PortMultipartRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	binary.BigEndian.PutUint32(data[0:], p.PortNo)
	return
}

func (p *PortMultipartRequest) UnmarshalBinary(data []byte) (err error) {
	p.PortNo = binary.BigEndian.Uint32(data)
	return
}

// ofp_queue_desc
type QueueDesc struct {
	PortNo     uint32
	QueueId    uint32
	Length     uint16
	Pad        []byte // 6 bytes
	Properties []util.Message
}

func NewQueueDesc(id uint32) *QueueDesc {
	n := new(QueueDesc)
	n.QueueId = id
	n.Pad = make([]byte, 6)
	return n
}

func (q *QueueDesc) Len() uint16 {
	var n uint16 = 16
	for _, p := range q.Properties {
		n += p.Len()
	}
	return n
}

func (q *QueueDesc) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	q.Length = q.Len()
	var n uint16
	binary.BigEndian.PutUint32(data[n:], q.PortNo)
	n += 4
	binary.BigEndian.PutUint32(data[n:], q.QueueId)
	n += 4
	binary.BigEndian.PutUint16(data[n:], q.Length)
	n += 2
	n += 6 // Pad

	for _, prop := range q.Properties {
		var bytes []byte
		bytes, err = prop.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}

	return
}

func (q *QueueDesc) UnmarshalBinary(data []byte) (err error) {
	var n uint16

	q.PortNo = binary.BigEndian.Uint32(data[n:])
	n += 4
	q.QueueId = binary.BigEndian.Uint32(data[n:])
	n += 4

	q.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 6 // Pad

	for n < q.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case QDPT_MIN_RATE:
			p = new(QueueDescPropMinRate)
		case QDPT_MAX_RATE:
			p = new(QueueDescPropMaxRate)
		case QDPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal QueueDesc's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		q.Properties = append(q.Properties, p)
	}
	return
}

// ofp_queue_desc_prop_type
const (
	QDPT_MIN_RATE     = 1      /* Minimum datarate guaranteed. */
	QDPT_MAX_RATE     = 2      /* Maximum datarate. */
	QDPT_EXPERIMENTER = 0xffff /* Experimenter defined property. */
)

const Q_MIN_RATE_UNCFG = 0xffff
const Q_MAX_RATE_UNCFG = 0xffff

type QueueDescPropRate struct {
	Header PropHeader
	Rate   uint16
	Pad    uint16
}

// ofp_queue_desc_prop_min_rate
type QueueDescPropMinRate = QueueDescPropRate

// ofp_queue_desc_prop_max_rate
type QueueDescPropMaxRate = QueueDescPropRate

func NewQueueDescPropMinRate() *QueueDescPropRate {
	n := new(QueueDescPropRate)
	n.Header.Type = QDPT_MIN_RATE
	return n
}

func NewQueueDescPropMaxRate() *QueueDescPropRate {
	n := new(QueueDescPropRate)
	n.Header.Type = QDPT_MAX_RATE
	return n
}

func (prop *QueueDescPropRate) Len() uint16 {
	return 8
}

func (prop *QueueDescPropRate) MarshalBinary() (data []byte, err error) {
	data = make([]byte, prop.Len())

	prop.Header.Length = prop.Len()
	var bytes []byte
	bytes, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	copy(data, bytes)
	n := prop.Header.Len()

	binary.BigEndian.PutUint16(data[n:], prop.Rate)
	n += 2
	return
}

func (prop *QueueDescPropRate) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = prop.Header.Len()

	prop.Rate = binary.BigEndian.Uint16(data[n:])
	return
}

// ofp_flow_monitor_request
type FlowMonitorRequest struct {
	MonitorId uint32
	OutPort   uint32
	OutGroup  uint32
	Flags     uint16
	TableId   uint8
	Command   uint8
	Match
}

// ofp_flow_monitor_command
const (
	FMC_ADD    = 0 /* New flow monitor. */
	FMC_MODIFY = 1 /* Modify existing flow monitor. */
	FMC_DELETE = 2 /* Delete/cancel existing flow monitor. */
)

func NewFlowMonitorRequest(id uint32) *FlowMonitorRequest {
	n := new(FlowMonitorRequest)
	n.Match = *NewMatch()
	return n
}

func (mon *FlowMonitorRequest) Len() uint16 {
	var n uint16 = 16
	n += mon.Match.Len()
	return n
}

func (mon *FlowMonitorRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	var n uint16

	binary.BigEndian.PutUint32(data[n:], mon.MonitorId)
	n += 4
	binary.BigEndian.PutUint32(data[n:], mon.OutPort)
	n += 4
	binary.BigEndian.PutUint32(data[n:], mon.OutGroup)
	n += 4
	binary.BigEndian.PutUint16(data[n:], mon.Flags)
	n += 2
	data[n] = mon.TableId
	n++
	data[n] = mon.Command
	n++

	var bytes []byte
	bytes, err = mon.Match.MarshalBinary()
	if err != nil {
		return
	}
	data = append(data, bytes...)
	return
}

func (mon *FlowMonitorRequest) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	mon.MonitorId = binary.BigEndian.Uint32(data[n:])
	n += 4
	mon.OutPort = binary.BigEndian.Uint32(data[n:])
	n += 4
	mon.OutGroup = binary.BigEndian.Uint32(data[n:])
	n += 4
	mon.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	mon.TableId = data[n]
	n++
	mon.Command = data[n]
	n++

	err = mon.Match.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal FlowMonitorRequest's Match", "data", data[n:])
		return
	}
	return
}

// ofp_flow_update_header
type FlowUpdateHeader struct {
	Length uint16
	Event  uint16
}

// ofp_flow_update_event
const (
	/* struct ofp_flow_update_full. */
	FME_INITIAL  = 0 /* Flow present when flow monitor created. */
	FME_ADDED    = 1 /* Flow was added. */
	FME_REMOVED  = 2 /* Flow was removed. */
	FME_MODIFIED = 3 /* Flow instructions were changed. */
	/* struct ofp_flow_update_abbrev. */
	FME_ABBREV = 4 /* Abbreviated reply. */
	/* struct ofp_flow_update_header. */
	FME_PAUSED  = 5 /* Monitoring paused (out of buffer space). */
	FME_RESUMED = 6 /* Monitoring resumed. */
)

// ofp_flow_monitor_flags
const (
	/* When to send updates. */
	FMF_INITIAL = 1 << 0 /* Initially matching flows. */
	FMF_ADD     = 1 << 1 /* New matching flows as they are added. */
	FMF_REMOVED = 1 << 2 /* Old matching flows as they are removed. */
	FMF_MODIFY  = 1 << 3 /* Matching flows as they are changed. */
	/* What to include in updates. */
	FMF_INSTRUCTIONS = 1 << 4 /* If set, instructions are included. */
	FMF_NO_ABBREV    = 1 << 5 /* If set, include own changes in full. */
	FMF_ONLY_OWN     = 1 << 6 /* If set, don’t include other controllers. */
)

func NewFlowUpdateHeader(event uint16) *FlowUpdateHeader {
	n := new(FlowUpdateHeader)
	n.Event = event
	return n
}

func (f *FlowUpdateHeader) Len() uint16 {
	return 4
}

func (f *FlowUpdateHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)
	var n uint16
	binary.BigEndian.PutUint16(data[n:], f.Length)
	n += 2
	binary.BigEndian.PutUint16(data[n:], f.Event)
	n += 2

	return
}

func (f *FlowUpdateHeader) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	f.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	f.Event = binary.BigEndian.Uint16(data[n:])
	n += 2
	return
}

// ofp_flow_update_full
type FlowUpdateFull struct {
	FlowUpdateHeader
	TableId     uint8
	Reason      uint8
	IdleTimeout uint16
	HardTimeout uint16
	Priority    uint16
	Zeros       []byte // 4 bytes
	Cookie      uint64
	Match
	Instructions []Instruction
}

// FME_INITIAL or FME_ADDED or FME_REMOVED or FME_MODIFIED
func NewFlowUpdateFull(event uint16) *FlowUpdateFull {
	n := new(FlowUpdateFull)
	n.FlowUpdateHeader.Event = event
	n.Zeros = make([]byte, 4)
	n.Match = *NewMatch()
	return n
}

func (full *FlowUpdateFull) AddInstruction(i Instruction) {
	full.Instructions = append(full.Instructions, i)
	return
}

func (full *FlowUpdateFull) Len() uint16 {
	var n uint16 = 24
	n += full.Match.Len()
	for _, i := range full.Instructions {
		n += i.Len()
	}
	return n
}

func (full *FlowUpdateFull) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 24)
	var n uint16
	full.FlowUpdateHeader.Length = full.Len()
	var bytes []byte
	bytes, err = full.FlowUpdateHeader.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, bytes)
	n = full.FlowUpdateHeader.Len()

	data[n] = full.TableId
	n++
	data[n] = full.Reason
	n++

	binary.BigEndian.PutUint16(data[n:], full.IdleTimeout)
	n += 2
	binary.BigEndian.PutUint16(data[n:], full.HardTimeout)
	n += 2
	binary.BigEndian.PutUint16(data[n:], full.Priority)
	n += 2
	n += 4 // Zeros
	binary.BigEndian.PutUint64(data[n:], full.Cookie)
	n += 8

	bytes, err = full.Match.MarshalBinary()
	if err != nil {
		return
	}
	data = append(data, bytes...)

	for _, i := range full.Instructions {
		bytes, err = i.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}
	return
}

func (full *FlowUpdateFull) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = full.FlowUpdateHeader.UnmarshalBinary(data)
	if err != nil {
		return
	}
	n = full.FlowUpdateHeader.Len()
	full.TableId = data[n]
	n++
	full.Reason = data[n]
	n++

	full.IdleTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	full.HardTimeout = binary.BigEndian.Uint16(data[n:])
	n += 2
	full.Priority = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 4 // Zeros
	full.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8

	err = full.Match.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal FlowUpdateFull's Match", "data", data[n:])
		return
	}
	n += full.Match.Len()
	for n < full.FlowUpdateHeader.Length {
		i, err := DecodeInstr(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal FlowUpdateFull's Instructions", "data", data[n:])
			return err
		}
		full.Instructions = append(full.Instructions, i)
		n += i.Len()
	}
	return
}

// ofp_flow_update_abbrev
type FlowUpdateAbbrev struct {
	FlowUpdateHeader
	Xid uint32
}

func NewFlowUpdateAbbrev() *FlowUpdateAbbrev {
	n := new(FlowUpdateAbbrev)
	n.FlowUpdateHeader.Event = FME_ABBREV
	return n
}

func (abbr *FlowUpdateAbbrev) Len() uint16 {
	return 8
}

func (abbr *FlowUpdateAbbrev) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	abbr.FlowUpdateHeader.Length = abbr.Len()
	var bytes []byte
	bytes, err = abbr.FlowUpdateHeader.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, bytes)
	n := abbr.FlowUpdateHeader.Len()
	binary.BigEndian.PutUint32(data[n:], abbr.Xid)
	return
}

func (abbr *FlowUpdateAbbrev) UnmarshalBinary(data []byte) (err error) {
	err = abbr.FlowUpdateHeader.UnmarshalBinary(data)
	if err != nil {
		return
	}
	n := abbr.FlowUpdateHeader.Len()
	abbr.Xid = binary.BigEndian.Uint32(data[n:])
	return
}

// ofp_flow_update_paused
type FlowUpdatePaused struct {
	FlowUpdateHeader
	Zeros uint32
}

// FME_PAUSED or FME_RESUMED
func NewFlowUpdatePaused(event uint16) *FlowUpdatePaused {
	n := new(FlowUpdatePaused)
	n.FlowUpdateHeader.Event = event
	return n
}

func (pause *FlowUpdatePaused) Len() uint16 {
	return 8
}

func (pause *FlowUpdatePaused) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	pause.FlowUpdateHeader.Length = pause.Len()
	var bytes []byte
	bytes, err = pause.FlowUpdateHeader.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, bytes)
	return
}

func (pause *FlowUpdatePaused) UnmarshalBinary(data []byte) (err error) {
	err = pause.FlowUpdateHeader.UnmarshalBinary(data)
	if err != nil {
		return
	}
	return
}

// ofp_bundle_features_request
type BundleFeaturesRequest struct {
	FeaturesRequestFlag uint32
	Pad                 uint32
	Properties          []util.Message
}

func NewBundleFeaturesRequest() *BundleFeaturesRequest {
	n := new(BundleFeaturesRequest)
	return n
}

func (b *BundleFeaturesRequest) Len() uint16 {
	var n uint16 = 8
	for _, p := range b.Properties {
		n += p.Len()
	}
	return n
}

func (b *BundleFeaturesRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	var n uint16
	binary.BigEndian.PutUint32(data[n:], b.FeaturesRequestFlag)
	n += 4
	n += 4 // Pad

	for _, prop := range b.Properties {
		var bytes []byte
		bytes, err = prop.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
		n += prop.Len()
	}
	return
}

func (b *BundleFeaturesRequest) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	b.FeaturesRequestFlag = binary.BigEndian.Uint32(data[n:])
	n += 4
	n += 4 // Pad

	for n < uint16(len(data)) {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case TMPBF_TIME_CAPABILITY:
			p = new(BundleFeaturesPropTime)
		case TMPBF_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal BundleFeaturesRequest's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		b.Properties = append(b.Properties, p)
	}
	return
}

// ofp_bundle_feature_flags
const (
	BF_TIMESTAMP      = 1 << 0 /* Request includes a timestamp. */
	BF_TIME_SET_SCHED = 1 << 1 /* Request includes the sched_max_future and
	* sched_max_past parameters. */
)

// ofp_bundle_features_prop_type
const (
	TMPBF_TIME_CAPABILITY = 0x1    /* Time feature property. */
	TMPBF_EXPERIMENTER    = 0xFFFF /* Experimenter property. */
)

// ofp_bundle_features_prop_time
type BundleFeaturesPropTime struct {
	Header         PropHeader
	Pad            uint32
	SchedAccuracy  OfpTime
	SchedMaxFuture OfpTime
	SchedMaxPast   OfpTime
	Timestamp      OfpTime
}

func NewBundleFeaturesPropTime() *BundleFeaturesPropTime {
	n := new(BundleFeaturesPropTime)
	n.Header.Type = TMPBF_TIME_CAPABILITY
	return n
}

func (prop *BundleFeaturesPropTime) Len() uint16 {
	return 72
}

func (prop *BundleFeaturesPropTime) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 72)
	var n uint16
	var bytes []byte
	prop.Header.Length = prop.Len()
	bytes, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data, bytes)
	n += prop.Header.Len()
	n += 4 // Pad

	bytes, err = prop.SchedAccuracy.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], bytes)
	n += prop.SchedAccuracy.Len()

	bytes, err = prop.SchedMaxFuture.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], bytes)
	n += prop.SchedMaxFuture.Len()

	bytes, err = prop.SchedMaxPast.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], bytes)
	n += prop.SchedMaxPast.Len()

	bytes, err = prop.Timestamp.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], bytes)
	n += prop.Timestamp.Len()

	return
}

func (prop *BundleFeaturesPropTime) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal BundleFeaturesPropTime's Header", "data", data[n:])
		return
	}
	n += prop.Header.Len()
	n += 4 // Pad

	err = prop.SchedAccuracy.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal BundleFeaturesPropTime's SchedAccuracy", "data", data[n:])
		return
	}
	n += prop.SchedAccuracy.Len()

	err = prop.SchedMaxFuture.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal BundleFeaturesPropTime's SchedMaxFuture", "data", data[n:])
		return
	}
	n += prop.SchedMaxFuture.Len()

	err = prop.SchedMaxPast.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal BundleFeaturesPropTime's SchedMaxPast", "data", data[n:])
		return
	}
	n += prop.SchedMaxPast.Len()

	err = prop.Timestamp.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal BundleFeaturesPropTime's Timestamp", "data", data[n:])
		return
	}
	n += prop.Timestamp.Len()

	return
}

// ofp_bundle_features
type BundleFeatures struct {
	Capabilities uint16
	Pad          []byte // 6 bytes
	Properties   []util.Message
}

func NewBundleFeatures() *BundleFeatures {
	n := new(BundleFeatures)
	n.Pad = make([]byte, 6)
	return n
}

func (b *BundleFeatures) Len() uint16 {
	var n uint16 = 8
	for _, p := range b.Properties {
		n += p.Len()
	}
	return n
}

func (b *BundleFeatures) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	var n uint16

	binary.BigEndian.PutUint16(data[n:], b.Capabilities)
	n += 2
	n += 6 // Pad

	for _, prop := range b.Properties {
		var bytes []byte
		bytes, err = prop.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
		n += prop.Len()
	}
	return
}

func (b *BundleFeatures) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	b.Capabilities = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 6 // Pad

	for n < uint16(len(data)) {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case TMPBF_TIME_CAPABILITY:
			p = new(BundleFeaturesPropTime)
		case TMPBF_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal BundleFeatures's Properties", "data", data[n:])
			return err
		}
		n += p.Len()
		b.Properties = append(b.Properties, p)
	}
	return
}
