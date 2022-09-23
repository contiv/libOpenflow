package openflow15

import (
	"encoding/binary"
	"errors"
	"net"

	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/util"
)

// ofp_port
type Port struct {
	PortNo uint32
	Length uint16
	Pad    []byte // 2 bytes
	HWAddr net.HardwareAddr
	pad2   []byte // 2 bytes for 64bit alignment
	Name   []byte // Size 16

	Config     uint32
	State      uint32
	Properties []util.Message
}

// ofp_port_desc_prop_type
const (
	PDPT_ETHERNET        = 0      /* Ethernet property. */
	PDPT_OPTICAL         = 1      /* Optical property. */
	PDPT_PIPELINE_INPUT  = 2      /* Ingress pipeline fields. */
	PDPT_PIPELINE_OUTPUT = 3      /* Egress pipeline fields. */
	PDPT_RECIRCULATE     = 4      /* Recirculation property. */
	PDPT_EXPERIMENTER    = 0xFFFF /* Experimenter property. */
)

func NewPort(num uint32) *Port {
	p := new(Port)
	p.HWAddr = make([]byte, ETH_ALEN)
	p.Name = make([]byte, 16)
	p.PortNo = num
	return p
}

func (p *Port) Len() (n uint16) {
	n = 40
	for _, prop := range p.Properties {
		n += prop.Len()
	}

	return n
}

func (p *Port) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	binary.BigEndian.PutUint32(data, p.PortNo)
	var n uint16 = 4
	p.Length = p.Len()
	binary.BigEndian.PutUint16(data[n:], p.Length)
	n += 2
	n += 2 // Pad
	copy(data[n:], p.HWAddr)
	n += uint16(len(p.HWAddr))
	n += 2 // Pad2
	copy(data[n:], p.Name)
	n += uint16(len(p.Name))

	binary.BigEndian.PutUint32(data[n:], p.Config)
	n += 4
	binary.BigEndian.PutUint32(data[n:], p.State)
	n += 4

	for _, prop := range p.Properties {
		var bytes []byte
		bytes, err = prop.MarshalBinary()
		if err != nil {
			return
		}
		copy(data[n:], bytes)
		n += prop.Len()
	}
	return
}

func (p *Port) UnmarshalBinary(data []byte) (err error) {
	p.PortNo = binary.BigEndian.Uint32(data)
	var n uint16 = 4
	p.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2 // Pad
	copy(p.HWAddr, data[n:])
	n += 6
	n += 2 // Pad2
	copy(p.Name, data[n:])
	n += 16

	p.Config = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.State = binary.BigEndian.Uint32(data[n:])
	n += 4
	for n < p.Length {
		var prop util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case PDPT_ETHERNET:
			prop = new(PortDescPropEthernet)
		case PDPT_OPTICAL:
			prop = new(PortDescPropOptical)
		case PDPT_PIPELINE_INPUT:
			prop = new(PortDescPropOxm)
		case PDPT_PIPELINE_OUTPUT:
			prop = new(PortDescPropOxm)
		case PDPT_RECIRCULATE:
			prop = new(PortDescPropRecirculate)
		case PDPT_EXPERIMENTER:
			prop = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = prop.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal Port's Properties", "data", data[n:])
			return err
		}
		n += prop.Len()
		p.Properties = append(p.Properties, prop)
	}
	return nil
}

// ofp_port_desc_prop_ethernet
type PortDescPropEthernet struct {
	Header     PropHeader
	Pad        []byte // 4 bytes
	Curr       uint32
	Advertised uint32
	Supported  uint32
	Peer       uint32
	CurrSpeed  uint32
	MaxSpeed   uint32
}

func NewPortDescPropEthernet() *PortDescPropEthernet {
	n := new(PortDescPropEthernet)
	n.Header.Type = PDPT_ETHERNET
	n.Pad = make([]byte, 4)
	return n
}

func (prop *PortDescPropEthernet) Len() uint16 {
	n := prop.Header.Len()
	n += 28
	return n
}

func (prop *PortDescPropEthernet) MarshalBinary() (data []byte, err error) {
	data = make([]byte, prop.Len())
	var bytes []byte

	prop.Header.Length = prop.Len()
	bytes, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	copy(data, bytes)
	n := prop.Header.Len()
	n += 4 // Pad
	binary.BigEndian.PutUint32(data[n:], prop.Curr)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.Advertised)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.Supported)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.Peer)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.CurrSpeed)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.MaxSpeed)
	n += 4
	return
}

func (prop *PortDescPropEthernet) UnmarshalBinary(data []byte) (err error) {
	var n uint16 = 0
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n += prop.Header.Len()
	n += 4 // Pad
	prop.Curr = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.Advertised = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.Supported = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.Peer = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.CurrSpeed = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.MaxSpeed = binary.BigEndian.Uint32(data[n:])
	n += 4

	return
}

// ofp_port_desc_prop_optical
type PortDescPropOptical struct {
	Header         PropHeader
	Pad            []byte // 4 bytes
	Supported      uint32
	TxMinFreqLmda  uint32
	TxMaxFreqLmda  uint32
	TxGridFreqLmda uint32
	RxMinFreqLmda  uint32
	RxMaxFreqLmda  uint32
	RxGridFreqLmda uint32
	TxPwrMin       uint16
	TxPwrMax       uint16
}

// ofp_optical_port_features
const (
	OPF_RX_TUNE  = 1 << 0 /* Receiver is tunable */
	OPF_TX_TUNE  = 1 << 1 /* Transmit is tunable */
	OPF_TX_PWR   = 1 << 2 /* Power is configurable */
	OPF_USE_FREQ = 1 << 3 /* Use Frequency, not wavelength */
)

func NewPortDescPropOptical() *PortDescPropOptical {
	n := new(PortDescPropOptical)
	n.Header.Type = PDPT_OPTICAL
	n.Pad = make([]byte, 4)
	return n
}

func (prop *PortDescPropOptical) Len() uint16 {
	return 40
}

func (prop *PortDescPropOptical) MarshalBinary() (data []byte, err error) {
	data = make([]byte, prop.Len())
	var bytes []byte

	prop.Header.Length = prop.Len()
	bytes, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	copy(data, bytes)
	n := prop.Header.Len()
	n += 4 // Pad
	binary.BigEndian.PutUint32(data[n:], prop.Supported)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.TxMinFreqLmda)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.TxMaxFreqLmda)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.TxGridFreqLmda)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.RxMinFreqLmda)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.RxMaxFreqLmda)
	n += 4
	binary.BigEndian.PutUint32(data[n:], prop.RxGridFreqLmda)
	n += 4
	binary.BigEndian.PutUint16(data[n:], prop.TxPwrMin)
	n += 2
	binary.BigEndian.PutUint16(data[n:], prop.TxPwrMax)
	n += 2
	return
}

func (prop *PortDescPropOptical) UnmarshalBinary(data []byte) (err error) {
	var n uint16 = 0
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n += prop.Header.Len()
	n += 4 // Pad
	prop.Supported = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.TxMinFreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.TxMaxFreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.TxGridFreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.RxMinFreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.RxMaxFreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.RxGridFreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4
	prop.TxPwrMin = binary.BigEndian.Uint16(data[n:])
	n += 2
	prop.TxPwrMax = binary.BigEndian.Uint16(data[n:])
	n += 2

	return
}

// ofp_port_desc_prop_oxm
type PortDescPropOxm struct {
	Header PropHeader
	OxmIds []uint32
}

func NewPortDescPropOxm(t uint16) *PortDescPropOxm {
	n := new(PortDescPropOxm)
	n.Header.Type = t //  PDPT_PIPELINE_INPUT or PDPT_PIPELINE_OUTPUT
	return n
}

func (prop *PortDescPropOxm) Len() uint16 {
	n := prop.Header.Len()
	n += uint16(len(prop.OxmIds) * 4)
	return (n + 7) / 8 * 8
}

func (prop *PortDescPropOxm) MarshalBinary() (data []byte, err error) {
	data = make([]byte, prop.Len())
	var bytes []byte

	prop.Header.Length = prop.Len()
	bytes, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	copy(data, bytes)
	n := prop.Header.Len()
	for _, oxm := range prop.OxmIds {
		binary.BigEndian.PutUint32(data[n:], oxm)
		n += 4
	}
	return
}

func (prop *PortDescPropOxm) UnmarshalBinary(data []byte) (err error) {
	var n uint16 = 0
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n += prop.Header.Len()
	n += 4 // Pad
	for n < prop.Header.Length {
		oxm := binary.BigEndian.Uint32(data[n:])
		prop.OxmIds = append(prop.OxmIds, oxm)
		n += 4
	}
	return
}

// ofp_port_desc_prop_recirculate
type PortDescPropRecirculate struct {
	Header  PropHeader
	PortNos []uint32
}

func NewPortDescPropRecirculate() *PortDescPropRecirculate {
	n := new(PortDescPropRecirculate)
	n.Header.Type = PDPT_RECIRCULATE
	return n
}

func (prop *PortDescPropRecirculate) Len() uint16 {
	n := prop.Header.Len()
	n += uint16(len(prop.PortNos) * 4)
	return (n + 7) / 8 * 8
}

func (prop *PortDescPropRecirculate) MarshalBinary() (data []byte, err error) {
	data = make([]byte, prop.Len())
	var bytes []byte

	prop.Header.Length = prop.Len()
	bytes, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	copy(data, bytes)
	n := prop.Header.Len()
	for _, p := range prop.PortNos {
		binary.BigEndian.PutUint32(data[n:], p)
		n += 4
	}
	return
}

func (prop *PortDescPropRecirculate) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n += prop.Header.Len()
	n += 4 // Pad
	for n < prop.Header.Length {
		p := binary.BigEndian.Uint32(data[n:])
		prop.PortNos = append(prop.PortNos, p)
		n += 4
	}
	return
}

// ofp_port_mod 1.5
type PortMod struct {
	common.Header
	PortNo uint32
	pad    []byte  // 4 bytes
	HWAddr []uint8 // 6 bytes
	pad2   []byte  // 2 bytes for 64byte alignment

	Config     uint32
	Mask       uint32
	Properties []util.Message
}

func NewPortMod(port int) *PortMod {
	p := new(PortMod)
	p.Header = NewOfp15Header()
	p.Header.Type = Type_PortMod
	p.PortNo = uint32(port)
	p.HWAddr = make([]byte, ETH_ALEN)
	p.pad = make([]byte, 4)
	p.pad2 = make([]byte, 2)
	return p
}

func (p *PortMod) Len() (n uint16) {
	n = p.Header.Len() + 24
	for _, prop := range p.Properties {
		n += prop.Len()
	}
	return
}

func (p *PortMod) MarshalBinary() (data []byte, err error) {
	p.Header.Length = p.Len()
	data, err = p.Header.MarshalBinary()
	if err != nil {
		return
	}
	b := make([]byte, 24)
	n := 0
	binary.BigEndian.PutUint32(b[n:], p.PortNo)
	n += 4
	copy(b[n:], p.pad)
	n += 4
	copy(b[n:], p.HWAddr)
	n += ETH_ALEN
	copy(b[n:], p.pad2)
	n += 2
	binary.BigEndian.PutUint32(b[n:], p.Config)
	n += 4
	binary.BigEndian.PutUint32(b[n:], p.Mask)
	n += 4
	data = append(data, b...)

	for _, prop := range p.Properties {
		var b []byte
		b, err = prop.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, b...)
	}

	return
}

func (p *PortMod) UnmarshalBinary(data []byte) (err error) {
	err = p.Header.UnmarshalBinary(data)
	n := p.Header.Len()

	p.PortNo = binary.BigEndian.Uint32(data[n:])
	n += 4
	copy(p.pad, data[n:n+4])
	n += 4
	copy(p.HWAddr, data[n:])
	n += uint16(len(p.HWAddr))
	copy(p.pad2, data[n:n+2])
	n += 2
	p.Config = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.Mask = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < p.Length {
		var prop util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case PMPT_ETHERNET:
			prop = new(PortModPropEthernet)
		case PMPT_OPTICAL:
			prop = new(PortModPropOptical)
		case PMPT_EXPERIMENTER:
			prop = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = prop.UnmarshalBinary(data[n:])
		if err != nil {
			klog.ErrorS(err, "Failed to unmarshal PortMod's Properties", "data", data[n:])
			return err
		}
		n += prop.Len()
		p.Properties = append(p.Properties, prop)
	}

	return err
}

const (
	ETH_ALEN          = 6
	MAX_PORT_NAME_LEN = 16
)

// ofp_port_config 1.5
const (
	PC_PORT_DOWN = 1 << 0

	PC_NO_RECV      = 1 << 2
	PC_NO_FWD       = 1 << 5
	PC_NO_PACKET_IN = 1 << 6
)

// ofp_port_state 1.5
const (
	PS_LINK_DOWN = 1 << 0
	PS_BLOCKED   = 1 << 1
	PS_LIVE      = 1 << 2
)

// ofp_port_no 1.5
const (
	P_MAX   = 0xffffff00
	P_UNSET = 0xfffffff7

	P_IN_PORT = 0xfffffff8
	P_TABLE   = 0xfffffff9

	P_NORMAL = 0xfffffffa
	P_FLOOD  = 0xfffffffb

	P_ALL        = 0xfffffffc
	P_CONTROLLER = 0xfffffffd
	P_LOCAL      = 0xfffffffe
	P_ANY        = 0xffffffff
)

// ofp_port_features
const (
	PF_10MB_HD  = 1 << 0
	PF_10MB_FD  = 1 << 1
	PF_100MB_HD = 1 << 2
	PF_100MB_FD = 1 << 3
	PF_1GB_HD   = 1 << 4
	PF_1GB_FD   = 1 << 5
	PF_10GB_FD  = 1 << 6
	PF_40GB_FD  = 1 << 7
	PF_100GB_FD = 1 << 8
	PF_1TB_FD   = 1 << 9
	PF_OTHER    = 1 << 10

	PF_COPPER     = 1 << 11
	PF_FIBER      = 1 << 12
	PF_AUTONEG    = 1 << 13
	PF_PAUSE      = 1 << 14
	PF_PAUSE_ASYM = 1 << 15
)

// ofp_port_mod_prop_type
const (
	PMPT_ETHERNET     = 0      /* Ethernet property. */
	PMPT_OPTICAL      = 1      /* Optical property. */
	PMPT_EXPERIMENTER = 0xFFFF /* Experimenter property. */
)

// ofp_port_mod_prop_ethernet
type PortModPropEthernet struct {
	Header    PropHeader
	Advertise uint32
}

func NewPortModPropEthernet(adv uint32) *PortModPropEthernet {
	p := new(PortModPropEthernet)
	p.Header.Type = PMPT_ETHERNET
	p.Advertise = adv
	return p
}

func (prop *PortModPropEthernet) Len() uint16 {
	n := prop.Header.Len()
	n += 4
	return n
}

func (prop *PortModPropEthernet) MarshalBinary() (data []byte, err error) {
	prop.Header.Length = prop.Len()

	data, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes[0:], prop.Advertise)
	data = append(data, bytes...)

	return
}

func (prop *PortModPropEthernet) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = prop.Header.Len()

	prop.Advertise = binary.BigEndian.Uint32(data[n:])

	return
}

// ofp_port_mod_prop_optical
type PortModPropOptical struct {
	Header    PropHeader
	Configure uint32
	FreqLmda  uint32
	FlOffset  uint32
	GridSpan  uint32
	TxPwr     uint32
}

func NewPortModPropOptical(conf, freq, flof, grid, txpwr uint32) *PortModPropOptical {
	p := new(PortModPropOptical)
	p.Header.Type = PMPT_OPTICAL
	p.Configure = conf
	p.FreqLmda = freq
	p.FlOffset = flof
	p.GridSpan = grid
	p.TxPwr = txpwr
	return p
}

func (prop *PortModPropOptical) Len() uint16 {
	n := prop.Header.Len()
	n += 20
	return n
}

func (prop *PortModPropOptical) MarshalBinary() (data []byte, err error) {
	prop.Header.Length = prop.Len()

	data, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}
	n := prop.Header.Len()
	bytes := make([]byte, 20)
	binary.BigEndian.PutUint32(bytes[n:], prop.Configure)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.FreqLmda)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.FlOffset)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.GridSpan)
	n += 4
	binary.BigEndian.PutUint32(bytes[n:], prop.TxPwr)
	data = append(data, bytes...)

	return
}

func (prop *PortModPropOptical) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = prop.Header.Len()

	prop.Configure = binary.BigEndian.Uint32(data[n:])
	n += 4

	prop.FreqLmda = binary.BigEndian.Uint32(data[n:])
	n += 4

	prop.FlOffset = binary.BigEndian.Uint32(data[n:])
	n += 4

	prop.GridSpan = binary.BigEndian.Uint32(data[n:])
	n += 4

	prop.TxPwr = binary.BigEndian.Uint32(data[n:])
	n += 4

	return
}

// ofp_port_status
type PortStatus struct {
	common.Header
	Reason uint8
	pad    []uint8 // Size 7
	Desc   Port
}

func NewPortStatus() *PortStatus {
	p := new(PortStatus)
	p.Header = NewOfp15Header()
	p.Header.Type = Type_PortStatus
	p.pad = make([]byte, 7)
	return p
}

func (p *PortStatus) Len() (n uint16) {
	n = p.Header.Len()
	n += 8
	n += p.Desc.Len()
	return
}

func (s *PortStatus) MarshalBinary() (data []byte, err error) {
	s.Header.Length = s.Len()
	if data, err = s.Header.MarshalBinary(); err != nil {
		return
	}

	b := make([]byte, 8)
	n := 0
	b[0] = s.Reason
	n += 1
	copy(b[n:], s.pad)
	data = append(data, b...)

	if b, err = s.Desc.MarshalBinary(); err != nil {
		return
	}
	data = append(data, b...)
	return
}

func (s *PortStatus) UnmarshalBinary(data []byte) error {
	if err := s.Header.UnmarshalBinary(data); err != nil {
		return err
	}
	n := int(s.Header.Len())

	s.Reason = data[n]
	n += 1
	copy(s.pad, data[n:])
	n += len(s.pad)
	s.Desc = *NewPort(0)

	err := s.Desc.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal PortStatus's Desc", "data", data[n:])
	}
	return err
}

// ofp_port_reason
const (
	PR_ADD = iota
	PR_DELETE
	PR_MODIFY
)
