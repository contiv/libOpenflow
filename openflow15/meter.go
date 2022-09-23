package openflow15

// This file has all meter related defs

import (
	"encoding/binary"
	"fmt"

	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/util"
)

// ofp_meter_band_type
const (
	MBT_DROP         = 1      /* Drop packet. */
	MBT_DSCP_REMARK  = 2      /* Remark DSCP in the IP header. */
	MBT_EXPERIMENTER = 0xFFFF /* Experimenter meter band. */
)

// ofp_meter_mod_command
const (
	MC_ADD    = 0 /* New meter. */
	MC_MODIFY = 1 /* Modify specified meter. */
	MC_DELETE = 2 /* Delete specified meter. */
)

// ofp_meter_flags
const (
	MF_KBPS  = 0b0001 /* Rate value in kb/s (kilo-bit per second). */
	MF_PKTPS = 0b0010 /* Rate value in packet/sec. */
	MF_BURST = 0b0100 /* Do burst size. */
	MF_STATS = 0b1000 /* Collect statistics. */
)

// ofp_meter
const (
	/* Meter numbering. Flow meters can use any number up to OFPM_MAX. */
	M_MAX        = 0xffff0000 /* Last usable meter. */
	M_SLOWPATH   = 0xfffffffd /* Meter for slow datapath. */
	M_CONTROLLER = 0xfffffffe /* Meter for controller connection. */
	M_ALL        = 0xffffffff /* Represents all meters for stat requests commands. */
)

const (
	METER_BAND_HEADER_LEN = 12
	METER_BAND_LEN        = 16
)

// ofp_meter_band_header
type MeterBandHeader struct {
	Type      uint16 /* One of OFPMBT13_*. */
	Length    uint16 /* Length in bytes of this band. */
	Rate      uint32 /* Rate for this band. */
	BurstSize uint32 /* Size of bursts. */
}

func NewMeterBandHeader() *MeterBandHeader {
	return &MeterBandHeader{
		Length: METER_BAND_LEN,
	}
}

func (m *MeterBandHeader) Len() (n uint16) {
	return METER_BAND_HEADER_LEN
}

func (m *MeterBandHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	n := 0
	binary.BigEndian.PutUint16(data[n:], m.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], m.Length)
	n += 2
	binary.BigEndian.PutUint32(data[n:], m.Rate)
	n += 4
	binary.BigEndian.PutUint32(data[n:], m.BurstSize)

	return
}

func (m *MeterBandHeader) UnmarshalBinary(data []byte) error {
	n := 0
	m.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	m.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	m.Rate = binary.BigEndian.Uint32(data[n:])
	n += 4
	m.BurstSize = binary.BigEndian.Uint32(data[n:])

	return nil
}

// ofp_meter_band_drop
type MeterBandDrop struct {
	MeterBandHeader /* Type: OFPMBT_DROP. */
	pad             [4]uint8
}

func NewMeterBandDrop() *MeterBandDrop {
	n := new(MeterBandDrop)
	n.MeterBandHeader.Type = MBT_DROP
	n.MeterBandHeader.Length = METER_BAND_LEN
	return n
}

func (m *MeterBandDrop) Len() (n uint16) {
	return METER_BAND_LEN
}

func (m *MeterBandDrop) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	n := 0
	m.MeterBandHeader.Length = METER_BAND_LEN
	mbHdrBytes, err := m.MeterBandHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data, mbHdrBytes)
	n += METER_BAND_HEADER_LEN
	return
}

func (m *MeterBandDrop) UnmarshalBinary(data []byte) error {
	n := 0
	m.MeterBandHeader.UnmarshalBinary(data[n:])
	n += int(m.MeterBandHeader.Len())

	return nil
}

// ofp_meter_band_dscp_remark
type MeterBandDSCP struct {
	MeterBandHeader       /* Type: OFPMBT_DSCP_REMARK. */
	PrecLevel       uint8 /* Number of drop precedence level to add. */
	pad             [3]uint8
}

func NewMeterBandDSCP() *MeterBandDSCP {
	n := new(MeterBandDSCP)
	n.MeterBandHeader.Type = MBT_DSCP_REMARK
	n.MeterBandHeader.Length = METER_BAND_LEN
	return n
}

func (m *MeterBandDSCP) Len() (n uint16) {
	return METER_BAND_LEN
}

func (m *MeterBandDSCP) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	n := 0
	m.MeterBandHeader.Length = METER_BAND_LEN
	mbHdrBytes, err := m.MeterBandHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data, mbHdrBytes)
	n += METER_BAND_HEADER_LEN
	data[n] = m.PrecLevel
	return
}

func (m *MeterBandDSCP) UnmarshalBinary(data []byte) error {
	n := 0
	err := m.MeterBandHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(m.MeterBandHeader.Len())
	m.PrecLevel = data[n]

	return nil
}

type MeterBandExperimenter struct {
	MeterBandHeader        /* Type: OFPMBT13_EXPERIMENTER. */
	Experimenter    uint32 /* Experimenter ID which takes the same form as in struct ofp_experimenter_header. */
}

func (m *MeterBandExperimenter) Len() (n uint16) {
	return METER_BAND_LEN
}

func (m *MeterBandExperimenter) MarshalBinary() (data []byte, err error) {
	data = make([]byte, m.Len())
	n := 0
	mbHdrBytes, err := m.MeterBandHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data, mbHdrBytes)
	n += METER_BAND_HEADER_LEN
	binary.BigEndian.PutUint32(data[n:], m.Experimenter)
	return
}

func (m *MeterBandExperimenter) UnmarshalBinary(data []byte) error {
	n := 0
	err := m.MeterBandHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(m.MeterBandHeader.Len())
	m.Experimenter = binary.BigEndian.Uint32(data[n:])

	return nil
}

// MeterMod message
type MeterMod struct {
	common.Header
	Command    uint16         /* One of OFPMC_*. */
	Flags      uint16         /* Set of OFPMF_*. */
	MeterId    uint32         /* Meter instance. */
	MeterBands []util.Message /* List of MeterBand*. */
}

// Create a new meter mod message
func NewMeterMod() *MeterMod {
	m := new(MeterMod)
	m.Header = NewOfp15Header()
	m.Header.Type = Type_MeterMod
	m.MeterBands = make([]util.Message, 0)
	return m
}

// Add a meterBand to meter mod
func (m *MeterMod) AddMeterBand(mb util.Message) {
	m.MeterBands = append(m.MeterBands, mb)
}

func (m *MeterMod) Len() (n uint16) {
	n = m.Header.Len()
	n += 8
	if m.Command == MC_DELETE {
		return
	}

	for _, b := range m.MeterBands {
		n += b.Len()
	}

	return
}

func (m *MeterMod) MarshalBinary() (data []byte, err error) {
	m.Header.Length = m.Len()
	data = make([]byte, m.Len())
	n := 0
	hdrBytes, err := m.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data, hdrBytes)
	n += int(m.Header.Len())
	binary.BigEndian.PutUint16(data[n:], m.Command)
	n += 2
	binary.BigEndian.PutUint16(data[n:], m.Flags)
	n += 2
	binary.BigEndian.PutUint32(data[n:], m.MeterId)
	n += 4

	for _, mb := range m.MeterBands {
		mbBytes, err := mb.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], mbBytes)
		n += METER_BAND_LEN
		klog.V(4).InfoS("Metermod band", "bytes", mbBytes)
	}

	klog.V(4).InfoS("Metermod MarshalBinary succeeded", "dataLength", len(data), "data", data)

	return
}

func (m *MeterMod) UnmarshalBinary(data []byte) error {
	n := 0
	m.Header.UnmarshalBinary(data[n:])
	n += int(m.Header.Len())

	m.Command = binary.BigEndian.Uint16(data[n:])
	n += 2
	m.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	m.MeterId = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < int(m.Header.Length) {
		mbh := new(MeterBandHeader)
		err := mbh.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal MeterMod's MeterBandHeader", "data", data[n:])
			return err
		}
		n += int(mbh.Len())
		switch mbh.Type {
		case MBT_DROP:
			mbDrop := new(MeterBandDrop)
			mbDrop.MeterBandHeader = *mbh
			m.MeterBands = append(m.MeterBands, mbDrop)
		case MBT_DSCP_REMARK:
			mbDscp := new(MeterBandDSCP)
			mbDscp.MeterBandHeader = *mbh
			mbDscp.PrecLevel = data[n]
			m.MeterBands = append(m.MeterBands, mbDscp)
		case MBT_EXPERIMENTER:
			mbExp := new(MeterBandExperimenter)
			mbExp.MeterBandHeader = *mbh
			mbExp.Experimenter = binary.BigEndian.Uint32(data[n:])
			m.MeterBands = append(m.MeterBands, mbExp)
		default:
			return fmt.Errorf("unknown MeterBandHeader type : %v", mbh.Type)
		}
		n += 4
	}

	return nil
}
