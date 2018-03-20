package ofctrl

import(
	"../openflow13"
	log "github.com/Sirupsen/logrus"
)

type OfApp struct {
	Switch *OFSwitch
}

func (o *OfApp) PacketRcvd(sw *OFSwitch, packet *openflow13.PacketIn) {
	log.Printf("App: Received packet: %+v", packet)
}

func (o *OfApp) SwitchConnected(sw *OFSwitch) {
	log.Printf("App: Switch connected: %v", sw.DPID())

	// Store switch for later use
	o.Switch = sw
}

func (o *OfApp) SwitchDisconnected(sw *OFSwitch) {
	log.Printf("App: Switch disconnected: %v", sw.DPID())
}

func (o *OfApp) MultipartReply(sw *OFSwitch, rep *openflow13.MultipartReply) {
	log.Println(rep.Body)
}