package openflow15

import (
	"fmt"
	"strings"
)

const (
	// OFPP_IN_PORT is the default number of in_port field in resubmit actions.
	OFPP_IN_PORT = 0xfff8
)

// NX_CT_STATES
const (
	NX_CT_STATE_NEW_OFS  = 0
	NX_CT_STATE_EST_OFS  = 1
	NX_CT_STATE_REL_OFS  = 2
	NX_CT_STATE_RPL_OFS  = 3
	NX_CT_STATE_INV_OFS  = 4
	NX_CT_STATE_TRK_OFS  = 5
	NX_CT_STATE_SNAT_OFS = 6
	NX_CT_STATE_DNAT_OFS = 7
)

// NX_CT Flags
const (
	NX_CT_F_COMMIT    = 1 << 0
	NX_CT_F_FORCE     = 1 << 1
	NX_CT_RECIRC_NONE = 0xff
)

// NX_NAT_RANGE flags
const (
	NX_NAT_RANGE_IPV4_MIN  = 1 << 0
	NX_NAT_RANGE_IPV4_MAX  = 1 << 1
	NX_NAT_RANGE_IPV6_MIN  = 1 << 2
	NX_NAT_RANGE_IPV6_MAX  = 1 << 3
	NX_NAT_RANGE_PROTO_MIN = 1 << 4
	NX_NAT_RANGE_PROTO_MAX = 1 << 5
)

// NX_NAT flags
const (
	NX_NAT_F_SRC          = 1 << 0
	NX_NAT_F_DST          = 1 << 1
	NX_NAT_F_PERSISTENT   = 1 << 2
	NX_NAT_F_PROTO_HASH   = 1 << 3
	NX_NAT_F_PROTO_RANDOM = 1 << 4
	NX_NAT_F_MASK         = (NX_NAT_F_SRC | NX_NAT_F_DST | NX_NAT_F_PERSISTENT | NX_NAT_F_PROTO_HASH | NX_NAT_F_PROTO_RANDOM)
)

// NX_LEARN flags
const (
	NX_LEARN_F_SEND_FLOW_REM  = 1 << 0
	NX_LEARN_F_DELETE_LEARNED = 1 << 1
	NX_LEARN_F_WRITE_RESULT   = 1 << 2
)

// NX_LEARN field offset
const (
	LEARN_SPEC_HEADER_LOAD  = 11
	LEARN_SPEC_HEADER_MATCH = 13
)

// NXM_OF fields. The class number of these fields are 0x0000.
const (
	NXM_OF_IN_PORT uint8 = iota
	NXM_OF_ETH_DST
	NXM_OF_ETH_SRC
	NXM_OF_ETH_TYPE
	NXM_OF_VLAN_TCI
	NXM_OF_IP_TOS
	NXM_OF_IP_PROTO
	NXM_OF_IP_SRC
	NXM_OF_IP_DST
	NXM_OF_TCP_SRC
	NXM_OF_TCP_DST
	NXM_OF_UDP_SRC
	NXM_OF_UDP_DST
	NXM_OF_ICMP_TYPE
	NXM_OF_ICMP_CODE
	NXM_OF_ARP_OP
	NXM_OF_ARP_SPA
	NXM_OF_ARP_TPA
)

// TLV_Table_Mod commands.
const (
	NXTTMC_ADD = iota
	NXTTMC_DELETE
	NXTTMC_CLEAR
)

func newMatchFieldHeader(class uint16, field uint8, length uint8) *MatchField {
	var fieldLength = length
	return &MatchField{Class: class, Field: field, Length: fieldLength, HasMask: false}
}

// oxxFieldHeaderMap is map to find target field header without mask using an OVS known OXX field name
var oxxFieldHeaderMap = map[string]*MatchField{
	"NXM_OF_IN_PORT":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_IN_PORT, 2),
	"NXM_OF_ETH_DST":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_ETH_DST, 6),
	"NXM_OF_ETH_SRC":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_ETH_SRC, 6),
	"NXM_OF_ETH_TYPE":  newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_ETH_TYPE, 2),
	"NXM_OF_VLAN_TCI":  newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_VLAN_TCI, 2),
	"NXM_OF_IP_TOS":    newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_IP_TOS, 1),
	"NXM_OF_IP_PROTO":  newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_IP_PROTO, 1),
	"NXM_OF_IP_SRC":    newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_IP_SRC, 4),
	"NXM_OF_IP_DST":    newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_IP_DST, 4),
	"NXM_OF_TCP_SRC":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_TCP_SRC, 2),
	"NXM_OF_TCP_DST":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_TCP_DST, 2),
	"NXM_OF_UDP_SRC":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_UDP_SRC, 2),
	"NXM_OF_UDP_DST":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_UDP_DST, 2),
	"NXM_OF_ICMP_TYPE": newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_ICMP_TYPE, 1),
	"NXM_OF_ICMP_CODE": newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_ICMP_CODE, 1),
	"NXM_OF_ARP_OP":    newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_ARP_OP, 2),
	"NXM_OF_ARP_SPA":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_ARP_SPA, 4),
	"NXM_OF_ARP_TPA":   newMatchFieldHeader(OXM_CLASS_NXM_0, NXM_OF_ARP_TPA, 4),

	"NXM_NX_REG0":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG0, 4),
	"NXM_NX_REG1":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG1, 4),
	"NXM_NX_REG2":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG2, 4),
	"NXM_NX_REG3":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG3, 4),
	"NXM_NX_REG4":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG4, 4),
	"NXM_NX_REG5":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG5, 4),
	"NXM_NX_REG6":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG6, 4),
	"NXM_NX_REG7":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG7, 4),
	"NXM_NX_REG8":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG8, 4),
	"NXM_NX_REG9":          newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG9, 4),
	"NXM_NX_REG10":         newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG10, 4),
	"NXM_NX_REG11":         newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG11, 4),
	"NXM_NX_REG12":         newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG12, 4),
	"NXM_NX_REG13":         newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG13, 4),
	"NXM_NX_REG14":         newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG14, 4),
	"NXM_NX_REG15":         newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_REG15, 4),
	"NXM_NX_TUN_ID":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_ID, 8),
	"NXM_NX_ARP_SHA":       newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_ARP_SHA, 6),
	"NXM_NX_ARP_THA":       newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_ARP_THA, 6),
	"NXM_NX_IPV6_SRC":      newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_IPV6_SRC, 16),
	"NXM_NX_IPV6_DST":      newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_IPV6_DST, 16),
	"NXM_NX_ICMPV6_TYPE":   newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_ICMPV6_TYPE, 1),
	"NXM_NX_ICMPV6_CODE":   newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_ICMPV6_CODE, 1),
	"NXM_NX_ND_TARGET":     newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_ND_TARGET, 16),
	"NXM_NX_ND_SLL":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_ND_SLL, 6),
	"NXM_NX_ND_TLL":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_ND_TLL, 6),
	"NXM_NX_IP_FRAG":       newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_IP_FRAG, 1),
	"NXM_NX_IPV6_LABEL":    newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_IPV6_LABEL, 1),
	"NXM_NX_IP_ECN":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_IP_ECN, 1),
	"NXM_NX_IP_TTL":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_IP_TTL, 1),
	"NXM_NX_MPLS_TTL":      newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_MPLS_TTL, 1),
	"NXM_NX_TUN_IPV4_SRC":  newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_IPV4_SRC, 4),
	"NXM_NX_TUN_IPV4_DST":  newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_IPV4_DST, 4),
	"NXM_NX_PKT_MARK":      newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_PKT_MARK, 4),
	"NXM_NX_TCP_FLAGS":     newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TCP_FLAGS, 2),
	"NXM_NX_CONJ_ID":       newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CONJ_ID, 4),
	"NXM_NX_TUN_GBP_ID":    newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_GBP_ID, 2),
	"NXM_NX_TUN_GBP_FLAGS": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_GBP_FLAGS, 1),
	"NXM_NX_TUN_FLAGS":     newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_FLAGS, 2),
	"NXM_NX_CT_STATE":      newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_STATE, 4),
	"NXM_NX_CT_ZONE":       newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_ZONE, 2),
	"NXM_NX_CT_MARK":       newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_MARK, 4),
	"NXM_NX_CT_LABEL":      newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_LABEL, 16),
	"NXM_NX_TUN_IPV6_SRC":  newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_IPV6_SRC, 16),
	"NXM_NX_TUN_IPV6_DST":  newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_IPV6_DST, 16),
	"NXM_NX_CT_NW_PROTO":   newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_NW_PROTO, 1),
	"NXM_NX_CT_NW_SRC":     newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_NW_SRC, 4),
	"NXM_NX_CT_NW_DST":     newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_NW_DST, 4),
	"NXM_NX_CT_IPV6_SRC":   newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_IPV6_SRC, 16),
	"NXM_NX_CT_IPV6_DST":   newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_IPV6_DST, 16),
	"NXM_NX_CT_TP_SRC":     newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_TP_SRC, 2),
	"NXM_NX_CT_TP_DST":     newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_CT_TP_DST, 2),
	"NXM_NX_TUN_METADATA0": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_METADATA0, 128),
	"NXM_NX_TUN_METADATA1": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_METADATA1, 128),
	"NXM_NX_TUN_METADATA2": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_METADATA2, 128),
	"NXM_NX_TUN_METADATA3": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_METADATA3, 128),
	"NXM_NX_TUN_METADATA4": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_METADATA4, 128),
	"NXM_NX_TUN_METADATA5": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_METADATA5, 128),
	"NXM_NX_TUN_METADATA6": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_METADATA6, 128),
	"NXM_NX_TUN_METADATA7": newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_TUN_METADATA7, 128),
	"NXM_NX_XXREG0":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_XXREG0, 16),
	"NXM_NX_XXREG1":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_XXREG1, 16),
	"NXM_NX_XXREG2":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_XXREG2, 16),
	"NXM_NX_XXREG3":        newMatchFieldHeader(OXM_CLASS_NXM_1, NXM_NX_XXREG3, 16),

	"OXM_OF_IN_PORT":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IN_PORT, 4),
	"OXM_OF_IN_PHY_PORT":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IN_PHY_PORT, 4),
	"OXM_OF_METADATA":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_METADATA, 8),
	"OXM_OF_ETH_DST":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ETH_DST, 6),
	"OXM_OF_ETH_SRC":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ETH_SRC, 6),
	"OXM_OF_ETH_TYPE":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ETH_TYPE, 2),
	"OXM_OF_VLAN_VID":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_VLAN_VID, 2),
	"OXM_OF_VLAN_PCP":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_VLAN_PCP, 1),
	"OXM_OF_IP_DSCP":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IP_DSCP, 1),
	"OXM_OF_IP_ECN":         newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IP_ECN, 1),
	"OXM_OF_IP_PROTO":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IP_PROTO, 1),
	"OXM_OF_IPV4_SRC":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV4_SRC, 4),
	"OXM_OF_IPV4_DST":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV4_DST, 4),
	"OXM_OF_TCP_SRC":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_TCP_SRC, 2),
	"OXM_OF_TCP_DST":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_TCP_DST, 2),
	"OXM_OF_UDP_SRC":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_UDP_SRC, 2),
	"OXM_OF_UDP_DST":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_UDP_DST, 2),
	"OXM_OF_SCTP_SRC":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_SCTP_SRC, 2),
	"OXM_OF_SCTP_DST":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_SCTP_DST, 2),
	"OXM_OF_ICMPV4_TYPE":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ICMPV4_TYPE, 1),
	"OXM_OF_ICMPV4_CODE":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ICMPV4_CODE, 1),
	"OXM_OF_ARP_OP":         newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ARP_OP, 2),
	"OXM_OF_ARP_SPA":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ARP_SPA, 4),
	"OXM_OF_ARP_TPA":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ARP_TPA, 4),
	"OXM_OF_ARP_SHA":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ARP_SHA, 6),
	"OXM_OF_ARP_THA":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ARP_THA, 6),
	"OXM_OF_IPV6_SRC":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV6_SRC, 16),
	"OXM_OF_IPV6_DST":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV6_DST, 16),
	"OXM_OF_IPV6_FLABEL":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV6_FLABEL, 4),
	"OXM_OF_ICMPV6_TYPE":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ICMPV6_TYPE, 1),
	"OXM_OF_ICMPV6_CODE":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_ICMPV6_CODE, 1),
	"OXM_OF_IPV6_ND_TARGET": newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV6_ND_TARGET, 16),
	"OXM_OF_IPV6_ND_SLL":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV6_ND_SLL, 6),
	"OXM_OF_IPV6_ND_TLL":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV6_ND_TLL, 6),
	"OXM_OF_MPLS_LABEL":     newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_MPLS_LABEL, 4),
	"OXM_OF_MPLS_TC":        newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_MPLS_TC, 1),
	"OXM_OF_MPLS_BOS":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_MPLS_BOS, 1),
	"OXM_OF_PBB_ISID":       newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_PBB_ISID, 3),
	"OXM_OF_TUNNEL_ID":      newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_TUNNEL_ID, 8),
	"OXM_OF_IPV6_EXTHDR":    newMatchFieldHeader(OXM_CLASS_OPENFLOW_BASIC, OXM_FIELD_IPV6_EXTHDR, 2),
}

// FindFieldHeaderByName finds OXM/NXM field by name and mask.
func FindFieldHeaderByName(fieldName string, hasMask bool) (*MatchField, error) {
	fieldKey := strings.ToUpper(fieldName)
	field, found := oxxFieldHeaderMap[fieldKey]
	if !found {
		return nil, fmt.Errorf("failed to find header by name %s", fieldName)
	}
	length := field.Length
	if hasMask {
		length = field.Length * 2
	}
	// Create a new MatchField and return it to the caller, then it could avoid race condition.
	return &MatchField{
		Class:   field.Class,
		Field:   field.Field,
		HasMask: hasMask,
		Length:  length,
	}, nil
}

func FindOxmIdByName(fieldName string, hasMask bool) (*OxmId, error) {
	matchField, err := FindFieldHeaderByName(fieldName, hasMask)
	if err != nil {
		return nil, err
	}
	return &OxmId{
		Class:   matchField.Class,
		Field:   matchField.Field,
		HasMask: matchField.HasMask,
		Length:  matchField.Length,
	}, nil
}

// encodeOfsNbitsStartEnd encodes the range to a uint16 number.
func encodeOfsNbitsStartEnd(start uint16, end uint16) uint16 {
	return (start << 6) + (end - start)
}

// Encode the range to a uint16 number.
// ofs is the start pos, nBits is the count of the range.
func encodeOfsNbits(ofs uint16, nBits uint16) uint16 {
	return ofs<<6 | (nBits - 1)
}

func decodeOfs(ofsNbits uint16) uint16 {
	return ofsNbits >> 6
}

func decodeNbits(ofsNbits uint16) uint16 {
	return (ofsNbits & 0x3f) + 1
}

// NewNXRange creates a NXRange using start and end number.
func NewNXRange(start int, end int) *NXRange {
	return &NXRange{start: start, end: end}
}

// NewNXRangeByOfsNBits creates a NXRange using offshift and bit count.
func NewNXRangeByOfsNBits(ofs int, nBits int) *NXRange {
	return &NXRange{start: ofs, end: ofs + nBits - 1}
}

// ToUint32Mask generates a uint32 number mask from NXRange.
func (n *NXRange) ToUint32Mask() uint32 {
	start := n.start
	maxLength := 32
	var end int
	if n.end != 0 {
		end = n.end
	} else {
		end = maxLength
	}
	mask1 := ^uint32(0)
	mask1 = mask1 >> uint32(maxLength-(end-n.start+1))
	mask1 = mask1 << uint32(start)
	return mask1
}

// ToOfsBits encodes the NXRange to a uint16 number to identify offshift and bits count.
func (n *NXRange) ToOfsBits() uint16 {
	return encodeOfsNbitsStartEnd(uint16(n.start), uint16(n.end))
}

// GetOfs returns the offshift number from NXRange.
func (n *NXRange) GetOfs() uint16 {
	return uint16(n.start)
}

// GetNbits returns the bits count from NXRange.
func (n *NXRange) GetNbits() uint16 {
	return uint16(n.end - n.start + 1)
}
