package ofctrl

import (
	"encoding/json"
	"errors"
	"net"
	"sync"

	log "github.com/Sirupsen/logrus"
	"../openflow13"
	"fmt"
)

const IP_PROTO_TCP = 6
const IP_PROTO_UDP = 17

type FlowMatch struct {
	Priority     uint16            // Priority of the flow
	InputPort    uint32            // Input port number
	MacDa        *net.HardwareAddr // Mac dest
	MacDaMask    *net.HardwareAddr // Mac dest mask
	MacSa        *net.HardwareAddr // Mac source
	MacSaMask    *net.HardwareAddr // Mac source mask
	Ethertype    uint16            // Ethertype
	VlanId       uint16            // vlan id
	ArpOper      uint16            // ARP Oper type
	IpSa         *net.IP           // IPv4 source addr
	IpSaMask     *net.IP           // IPv4 source mask
	IpDa         *net.IP           // IPv4 dest addr
	IpDaMask     *net.IP           // IPv4 dest mask
	Ipv6Sa       *net.IP           // IPv6 source addr
	Ipv6SaMask   *net.IP           // IPv6 source mask
	Ipv6Da       *net.IP           // IPv6 dest addr
	Ipv6DaMask   *net.IP           // IPv6 dest mask
	IpProto      uint8             // IP protocol
	IpDscp       uint8             // DSCP/TOS field
	TcpSrcPort   uint16            // TCP source port
	TcpDstPort   uint16            // TCP dest port
	UdpSrcPort   uint16            // UDP source port
	UdpDstPort   uint16            // UDP dest port
	Metadata     *uint64           // OVS metadata
	MetadataMask *uint64           // Metadata mask
	TunnelId     uint64            // Vxlan Tunnel id i.e. VNI
	TcpFlags     *uint16           // TCP flags
	TcpFlagsMask *uint16           // Mask for TCP flags
}

type FlowAction struct {
	actionType   string           // Type of action "setVlan", "setMetadata", ..etc
	vlanId       uint16           // Vlan Id in case of "setVlan"
	macAddr      net.HardwareAddr // Mac address to set
	ipAddr       net.IP           // IP address to be set
	l4Port       uint16           // Transport port to be set
	tunnelId     uint64           // Tunnel Id (used for setting VNI)
	metadata     uint64           // Metadata in case of "setMetadata"
	metadataMask uint64           // Metadata mask
	dscp         uint8            // DSCP field
	outPort      uint16           // traffic outport
	gotoTblId    uint16           // goto tableId
}

type FlowOutput struct {
	outputType string // Output type: "drop", "toController", "flood", "gotoTable" or "port"
	outPortNo     uint32 // Output port number
	tblId      uint8 // goto table id
}

type Flow struct {
	TableId     uint8         // FLow Table
	Match       FlowMatch     // Fields to be matched
	FlowID      uint64        // Unique ID for the flow
	flowActions []*FlowAction // List of flow actions
	flowOutput  FlowOutput;
	lock        sync.RWMutex  // lock for modifying flow state
}


func NewFlow(tblID uint8) Flow {
	flow := Flow{}
	flow.TableId = tblID
	flow.flowOutput = FlowOutput{}
	flow.flowActions = make([]*FlowAction,0)
	flow.Match = FlowMatch{}
	flow.FlowID = 100 //just change this
	return flow
}


// string key for the flow
func (self *Flow) flowKey() string {
	jsonVal, err := json.Marshal(self.Match)
	if err != nil {
		log.Errorf("Error forming flowkey for %+v. Err: %v", self, err)
		return ""
	}

	return string(jsonVal)
}

// Get all defined match openflow match fields
func (self *Flow) GetMatchFields() openflow13.Match {
	ofMatch := openflow13.NewMatch()

	// Handle input poty
	if self.Match.InputPort != 0 {
		inportField := openflow13.NewInPortField(self.Match.InputPort)
		ofMatch.AddField(*inportField)
	}

	// Handle mac DA field
	if self.Match.MacDa != nil {
		if self.Match.MacDaMask != nil {
			macDaField := openflow13.NewEthDstField(*self.Match.MacDa, self.Match.MacDaMask)
			ofMatch.AddField(*macDaField)
		} else {
			macDaField := openflow13.NewEthDstField(*self.Match.MacDa, nil)
			ofMatch.AddField(*macDaField)
		}
	}

	// Handle MacSa field
	if self.Match.MacSa != nil {
		if self.Match.MacSaMask != nil {
			macSaField := openflow13.NewEthSrcField(*self.Match.MacSa, self.Match.MacSaMask)
			ofMatch.AddField(*macSaField)
		} else {
			macSaField := openflow13.NewEthSrcField(*self.Match.MacSa, nil)
			ofMatch.AddField(*macSaField)
		}
	}

	// Handle ethertype
	if self.Match.Ethertype != 0 {
		etypeField := openflow13.NewEthTypeField(self.Match.Ethertype)
		ofMatch.AddField(*etypeField)
	}

	// Handle Vlan id
	if self.Match.VlanId != 0 {
		vidField := openflow13.NewVlanIdField(self.Match.VlanId, nil)
		ofMatch.AddField(*vidField)
	}

	// Handle ARP Oper type
	if self.Match.ArpOper != 0 {
		arpOperField := openflow13.NewArpOperField(self.Match.ArpOper)
		ofMatch.AddField(*arpOperField)
	}

	// Handle IP Dst
	if self.Match.IpDa != nil {
		if self.Match.IpDaMask != nil {
			ipDaField := openflow13.NewIpv4DstField(*self.Match.IpDa, self.Match.IpDaMask)
			ofMatch.AddField(*ipDaField)
		} else {
			ipDaField := openflow13.NewIpv4DstField(*self.Match.IpDa, nil)
			ofMatch.AddField(*ipDaField)
		}
	}

	// Handle IP Src
	if self.Match.IpSa != nil {
		if self.Match.IpSaMask != nil {
			ipSaField := openflow13.NewIpv4SrcField(*self.Match.IpSa, self.Match.IpSaMask)
			ofMatch.AddField(*ipSaField)
		} else {
			ipSaField := openflow13.NewIpv4SrcField(*self.Match.IpSa, nil)
			ofMatch.AddField(*ipSaField)
		}
	}

	// Handle IPv6 Dst
	if self.Match.Ipv6Da != nil {
		if self.Match.Ipv6DaMask != nil {
			ipv6DaField := openflow13.NewIpv6DstField(*self.Match.Ipv6Da, self.Match.Ipv6DaMask)
			ofMatch.AddField(*ipv6DaField)
		} else {
			ipv6DaField := openflow13.NewIpv6DstField(*self.Match.Ipv6Da, nil)
			ofMatch.AddField(*ipv6DaField)
		}
	}

	// Handle IPv6 Src
	if self.Match.Ipv6Sa != nil {
		if self.Match.Ipv6SaMask != nil {
			ipv6SaField := openflow13.NewIpv6SrcField(*self.Match.Ipv6Sa, self.Match.Ipv6SaMask)
			ofMatch.AddField(*ipv6SaField)
		} else {
			ipv6SaField := openflow13.NewIpv6SrcField(*self.Match.Ipv6Sa, nil)
			ofMatch.AddField(*ipv6SaField)
		}
	}

	// Handle IP protocol
	if self.Match.IpProto != 0 {
		protoField := openflow13.NewIpProtoField(self.Match.IpProto)
		ofMatch.AddField(*protoField)
	}

	// Handle IP dscp
	if self.Match.IpDscp != 0 {
		dscpField := openflow13.NewIpDscpField(self.Match.IpDscp)
		ofMatch.AddField(*dscpField)
	}

	// Handle port numbers
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpSrcPort != 0 {
		portField := openflow13.NewTcpSrcField(self.Match.TcpSrcPort)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpDstPort != 0 {
		portField := openflow13.NewTcpDstField(self.Match.TcpDstPort)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_UDP && self.Match.UdpSrcPort != 0 {
		portField := openflow13.NewUdpSrcField(self.Match.UdpSrcPort)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_UDP && self.Match.UdpDstPort != 0 {
		portField := openflow13.NewUdpDstField(self.Match.UdpDstPort)
		ofMatch.AddField(*portField)
	}

	// Handle tcp flags
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpFlags != nil {
		tcpFlagField := openflow13.NewTcpFlagsField(*self.Match.TcpFlags, self.Match.TcpFlagsMask)
		ofMatch.AddField(*tcpFlagField)
	}

	// Handle metadata
	if self.Match.Metadata != nil {
		if self.Match.MetadataMask != nil {
			metadataField := openflow13.NewMetadataField(*self.Match.Metadata, self.Match.MetadataMask)
			ofMatch.AddField(*metadataField)
		} else {
			metadataField := openflow13.NewMetadataField(*self.Match.Metadata, nil)
			ofMatch.AddField(*metadataField)
		}
	}

	// Handle Vxlan tunnel id
	if self.Match.TunnelId != 0 {
		tunnelIdField := openflow13.NewTunnelIdField(self.Match.TunnelId)
		ofMatch.AddField(*tunnelIdField)
	}

	return *ofMatch
}

var actInstr openflow13.Instruction

func (self *Flow) GetFlowInstructions() openflow13.Instruction {

	switch self.flowOutput.outputType {
	case "gotoCtrl":
		actInstr = openflow13.NewInstrApplyActions()
		outputAct := openflow13.NewActionOutput(openflow13.P_CONTROLLER)
		// Dont buffer the packets being sent to controller
		outputAct.MaxLen = openflow13.OFPCML_NO_BUFFER
		actInstr.AddAction(outputAct, false)
		log.Debugf("flow output type %s", self.flowOutput.outputType)
	case "gotoTbl":
		actInstr = openflow13.NewInstrGotoTable(self.flowOutput.tblId)
		log.Debugf("flow output type %s", self.flowOutput.outputType)
	case "flood":
		actInstr = openflow13.NewInstrApplyActions()
		log.Debugf("flow output type %s", self.flowOutput.outputType)
	case "outPort":
		actInstr = openflow13.NewInstrApplyActions()
		outputAct := openflow13.NewActionOutput(self.flowOutput.outPortNo)
		actInstr.AddAction(outputAct, false)
		log.Debugf("flow output type %s", self.flowOutput.outputType)
	default:
		log.Fatalf("Unknown flow output type %s", self.flowOutput.outputType)
	}

	for _, flowAction := range self.flowActions {
		switch flowAction.actionType {
		case "setVlan":
			// Push Vlan Tag action
			pushVlanAction := openflow13.NewActionPushVlan(0x8100)

			// Set Outer vlan tag field
			vlanField := openflow13.NewVlanIdField(flowAction.vlanId, nil)
			setVlanAction := openflow13.NewActionSetField(*vlanField)

			// Prepend push vlan & setvlan actions to existing instruction
			actInstr.AddAction(setVlanAction, true)
			actInstr.AddAction(pushVlanAction, true)
			log.Debugf("flow install. Added pushvlan action: %+v, setVlan actions: %+v",
				pushVlanAction, setVlanAction)

		case "popVlan":
			// Create pop vln action
			popVlan := openflow13.NewActionPopVlan()

			// Add it to instruction
			actInstr.AddAction(popVlan, true)
			log.Debugf("flow install. Added popVlan action: %+v", popVlan)

		case "setMacDa":
			// Set Outer MacDA field
			macDaField := openflow13.NewEthDstField(flowAction.macAddr, nil)
			setMacDaAction := openflow13.NewActionSetField(*macDaField)

			// Add set macDa action to the instruction
			actInstr.AddAction(setMacDaAction, true)
			log.Debugf("flow install. Added setMacDa action: %+v", setMacDaAction)

		case "setMacSa":
			// Set Outer MacSA field
			macSaField := openflow13.NewEthSrcField(flowAction.macAddr, nil)
			setMacSaAction := openflow13.NewActionSetField(*macSaField)

			// Add set macDa action to the instruction
			actInstr.AddAction(setMacSaAction, true)
			log.Debugf("flow install. Added setMacSa Action: %+v", setMacSaAction)

		case "setTunnelId":
			// Set tunnelId field
			tunnelIdField := openflow13.NewTunnelIdField(flowAction.tunnelId)
			setTunnelAction := openflow13.NewActionSetField(*tunnelIdField)

			// Add set tunnel action to the instruction
			actInstr.AddAction(setTunnelAction, true)
			log.Debugf("flow install. Added setTunnelId Action: %+v", setTunnelAction)

		case "setIPSa":
			// Set IP src
			ipSaField := openflow13.NewIpv4SrcField(flowAction.ipAddr, nil)
			setIPSaAction := openflow13.NewActionSetField(*ipSaField)

			// Add set action to the instruction
			actInstr.AddAction(setIPSaAction, true)
			log.Debugf("flow install. Added setIPSa Action: %+v", setIPSaAction)

		case "setIPDa":
			// Set IP dst
			ipDaField := openflow13.NewIpv4DstField(flowAction.ipAddr, nil)
			setIPDaAction := openflow13.NewActionSetField(*ipDaField)

			// Add set action to the instruction
			actInstr.AddAction(setIPDaAction, true)
			log.Debugf("flow install. Added setIPDa Action: %+v", setIPDaAction)

		case "setDscp":
			// Set DSCP field
			ipDscpField := openflow13.NewIpDscpField(flowAction.dscp)
			setIPDscpAction := openflow13.NewActionSetField(*ipDscpField)

			// Add set action to the instruction
			actInstr.AddAction(setIPDscpAction, true)
			log.Debugf("flow install. Added setDscp Action: %+v", setIPDscpAction)

		case "setTCPSrc":
			// Set TCP src
			tcpSrcField := openflow13.NewTcpSrcField(flowAction.l4Port)
			setTCPSrcAction := openflow13.NewActionSetField(*tcpSrcField)

			// Add set action to the instruction
			actInstr.AddAction(setTCPSrcAction, true)
			log.Debugf("flow install. Added setTCPSrc Action: %+v", setTCPSrcAction)

		case "setTCPDst":
			// Set TCP dst
			tcpDstField := openflow13.NewTcpDstField(flowAction.l4Port)
			setTCPDstAction := openflow13.NewActionSetField(*tcpDstField)

			// Add set action to the instruction
			actInstr.AddAction(setTCPDstAction, true)
			log.Debugf("flow install. Added setTCPDst Action: %+v", setTCPDstAction)

		case "setUDPSrc":
			// Set UDP src
			udpSrcField := openflow13.NewUdpSrcField(flowAction.l4Port)
			setUDPSrcAction := openflow13.NewActionSetField(*udpSrcField)

			// Add set action to the instruction
			actInstr.AddAction(setUDPSrcAction, true)
			log.Debugf("flow install. Added setUDPSrc Action: %+v", setUDPSrcAction)

		case "setUDPDst":
			// Set UDP dst
			udpDstField := openflow13.NewUdpDstField(flowAction.l4Port)
			setUDPDstAction := openflow13.NewActionSetField(*udpDstField)

			// Add set action to the instruction
			actInstr.AddAction(setUDPDstAction, true)
			log.Debugf("flow install. Added setUDPDst Action: %+v", setUDPDstAction)

		default:
			log.Fatalf("Unknown action type %s", flowAction.actionType)
		}
	}
	return actInstr
}

func (self *Flow) GetWriteMetaDataFlowInstruction() (*openflow13.InstrWriteMetadata, error) {
	for _, flowAction := range self.flowActions {
		switch flowAction.actionType {
		case "setMetadata":
			// Set Metadata instruction
			metaDataInstr := openflow13.NewInstrWriteMetadata(flowAction.metadata, flowAction.metadataMask)
			return metaDataInstr, nil
		}
	}
	return nil, fmt.Errorf("No meta-data action to write")
}

func (self *Flow) SetGotoControllerAction() {
	self.flowOutput.outputType = "gotoCtrl"
}

func (self *Flow) SetGotoTableAction(tblID uint8) {
	self.flowOutput.outputType = "gotoTbl"
	self.flowOutput.tblId = tblID
}

func (self *Flow) SetFloodAction() {
	self.flowOutput.outputType = "flood"
}

func (self *Flow) SetOutputPortAction(portNo uint32) {
	self.flowOutput.outputType = "outPort"
	self.flowOutput.outPortNo = portNo
}

// Special actions on the flow to set vlan id
func (self *Flow) SetVlan(vlanId uint16) error {
	action := new(FlowAction)
	action.actionType = "setVlan"
	action.vlanId = vlanId

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) PopVlan() error {
	action := new(FlowAction)
	action.actionType = "popVlan"

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	return nil
}

// Special actions on the flow to set mac dest addr
func (self *Flow) SetMacDa(macDa net.HardwareAddr) error {
	action := new(FlowAction)
	action.actionType = "setMacDa"
	action.macAddr = macDa

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	return nil
}

// Special action on the flow to set mac source addr
func (self *Flow) SetMacSa(macSa net.HardwareAddr) error {
	action := new(FlowAction)
	action.actionType = "setMacSa"
	action.macAddr = macSa

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	return nil
}

// Special action on the flow to set an ip field
func (self *Flow) SetIPField(ip net.IP, field string) error {
	action := new(FlowAction)
	action.ipAddr = ip
	if field == "Src" {
		action.actionType = "setIPSa"
	} else if field == "Dst" {
		action.actionType = "setIPDa"
	} else {
		return errors.New("field not supported")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	return nil
}

// Special action on the flow to set a L4 field
func (self *Flow) SetL4Field(port uint16, field string) error {
	action := new(FlowAction)
	action.l4Port = port

	switch field {
	case "TCPSrc":
		action.actionType = "setTCPSrc"
		break
	case "TCPDst":
		action.actionType = "setTCPDst"
		break
	case "UDPSrc":
		action.actionType = "setUDPSrc"
		break
	case "UDPDst":
		action.actionType = "setUDPDst"
		break
	default:
		return errors.New("field not supported")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	return nil
}

// Special actions on the flow to set metadata
func (self *Flow) SetMetadata(metadata, metadataMask uint64) error {
	action := new(FlowAction)
	action.actionType = "setMetadata"
	action.metadata = metadata
	action.metadataMask = metadataMask

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) SetTunnelId(tunnelId uint64) error {
	action := new(FlowAction)
	action.actionType = "setTunnelId"
	action.tunnelId = tunnelId

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)


	return nil
}

// Special actions on the flow to set dscp field
func (self *Flow) SetDscp(dscp uint8) error {
	action := new(FlowAction)
	action.actionType = "setDscp"
	action.dscp = dscp

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	return nil
}

// unset dscp field
func (self *Flow) UnsetDscp() error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Delete to the action from db
	for idx, act := range self.flowActions {
		if act.actionType == "setDscp" {
			self.flowActions = append(self.flowActions[:idx], self.flowActions[idx+1:]...)
		}
	}

	return nil
}