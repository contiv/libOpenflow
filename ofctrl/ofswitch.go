package ofctrl

import (
	"net"
	"time"

	"../common"
	"../openflow13"
	"../util"

	log "github.com/Sirupsen/logrus"
	"sync"
)

type OFSwitch struct {
	stream *util.MessageStream
	dpid   net.HardwareAddr
	consumer    ConsumerInterface
	flows  map[string]*Flow
	lock    sync.Mutex
	isConnected bool
}

// Builds and populates a Switch struct then starts listening
// for OpenFlow messages on conn.
func NewSwitch(stream *util.MessageStream, dpid net.HardwareAddr, consumer ConsumerInterface) *OFSwitch {
	var s *OFSwitch

	log.Infoln("Openflow Connection for new switch:", dpid)

	s = new(OFSwitch)
	s.consumer = consumer
	s.stream = stream
	s.dpid = dpid
	s.isConnected = false

	// Main receive loop for the switch
	go s.receive()

	// send Switch connected callback
	s.switchConnected()

	// Return the new switch
	return s
}

// Returns the dpid of Switch s.
func (self *OFSwitch) DPID() net.HardwareAddr {
	return self.dpid
}

// Sends an OpenFlow message to the Switch.
func (self *OFSwitch) send(req util.Message) {
	self.stream.Outbound <- req
}

func (self *OFSwitch) Disconnect() {
	self.stream.Shutdown <- true
	self.switchDisconnected()
}

// Handle switch connected event
func (self *OFSwitch) switchConnected() {
	self.consumer.SwitchConnected(self)

	// Send new feature request
	self.send(openflow13.NewFeaturesRequest())

	// FIXME: This is too fragile. Create a periodic timer
	// Start the periodic echo request loop
	self.send(openflow13.NewEchoRequest())
	self.isConnected = true
}

// Handle switch disconnected event
func (self *OFSwitch) switchDisconnected() {
	self.consumer.SwitchDisconnected(self)
	self.isConnected = false
}

// Receive loop for each Switch.
func (self *OFSwitch) receive() {
	for {
		select {
		case msg := <-self.stream.Inbound:
			// New message has been received from message
			// stream.
			self.handleMessages(self.dpid, msg)
		case err := <-self.stream.Error:
			log.Warnf("Received ERROR message from switch %v. Err: %v", self.dpid, err)

			// send Switch disconnected callback
			self.switchDisconnected()
			return
		}
	}
}

// Handle openflow messages from the switch
func (self *OFSwitch) handleMessages(dpid net.HardwareAddr, msg util.Message) {
	log.Debugf("Received message: %+v, on switch: %s", msg, dpid.String())

	switch t := msg.(type) {
	case *common.Header:
		switch t.Header().Type {
		case openflow13.Type_Hello:
			// Send Hello response
			h, err := common.NewHello(4)
			if err != nil {
				log.Errorf("Error creating hello message")
			}
			self.send(h)

		case openflow13.Type_EchoRequest:
			// Send echo reply
			res := openflow13.NewEchoReply()
			self.send(res)

		case openflow13.Type_EchoReply:

			// FIXME: This is too fragile. Create a periodic timer
			// Wait three seconds then send an echo_request message.
			go func() {
				<-time.After(time.Second * 3)

				// Send echo request
				res := openflow13.NewEchoRequest()
				self.send(res)
			}()

		case openflow13.Type_FeaturesRequest:

		case openflow13.Type_GetConfigRequest:

		case openflow13.Type_BarrierRequest:

		case openflow13.Type_BarrierReply:

		}
	case *openflow13.ErrorMsg:
		log.Errorf("Received ofp1.3 error msg: %+v", *t)
	case *openflow13.VendorHeader:

	case *openflow13.SwitchFeatures:

	case *openflow13.SwitchConfig:
		switch t.Header.Type {
		case openflow13.Type_GetConfigReply:

		case openflow13.Type_SetConfig:

		}
	case *openflow13.PacketIn:
		log.Debugf("Received packet(ofctrl): %+v", t)
		// send packet rcvd callback
		self.consumer.PacketRcvd(self, (*openflow13.PacketIn)(t))

	case *openflow13.FlowRemoved:

	case *openflow13.PortStatus:
		// FIXME: This needs to propagated to the app.
	case *openflow13.PacketOut:

	case *openflow13.FlowMod:

	case *openflow13.PortMod:

	case *openflow13.MultipartRequest:

	case *openflow13.MultipartReply:
		log.Debugf("Received MultipartReply")
		// send packet rcvd callback
		self.consumer.MultipartReply(self, (*openflow13.MultipartReply)(t))

	}
}

func (self *OFSwitch) InstallFlow(flow *Flow) {
	self.lock.Lock()
	defer self.lock.Unlock()
	flowMod := openflow13.NewFlowMod()
	flowMod.TableId = flow.TableId
	flowMod.Priority = flow.Match.Priority
	flowMod.Cookie = flow.FlowID
	flowMod.Match = flow.GetMatchFields()
	flowMod.AddInstruction(flow.GetFlowInstructions())

	log.Debugf("Sending ADD flowmod: %+v", flowMod)
	self.send(flowMod)
	self.flows [flow.flowKey()] = flow
}

func (self *OFSwitch) DeleteFlow(flow Flow) {
	self.lock.Lock()
	defer self.lock.Unlock()
	flowMod := openflow13.NewFlowMod()
	flowMod.Command = openflow13.FC_DELETE
	flowMod.TableId = flow.TableId
	flowMod.Priority = flow.Match.Priority
	flowMod.Cookie = flow.FlowID
	flowMod.CookieMask = 0xffffffffffffffff
	flowMod.OutPort = openflow13.P_ANY
	flowMod.OutGroup = openflow13.OFPG_ANY

	log.Debugf("Sending DELETE flowmod: %+v", flowMod)
	self.send(flowMod)
	delete(self.flows, flow.flowKey())
}