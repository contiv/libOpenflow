package ofbase

import "fmt"

const (
	VERSION_1_0 = 1
	VERSION_1_1 = 2
	VERSION_1_2 = 3
	VERSION_1_3 = 4
	VERSION_1_4 = 5
	VERSION_1_5 = 6
)

const (
	OFPTHello        = 0
	OFPTError        = 1
	OFPTEchoRequest  = 2
	OFPTEchoReply    = 3
	OFPTExperimenter = 4
)

type Serializable interface {
	Serialize(encoder *Encoder) error
}

type Deserializable interface {
	Decode(decoder *Decoder) error
}

type Header struct {
	Version uint8
	Type    uint8
	Length  uint16
	Xid     uint32
}

type Message interface {
	Serializable
	GetVersion() uint8
	GetLength() uint16
	MessageType() uint8
	MessageName() string
	GetXid() uint32
	SetXid(xid uint32)
}

type Uint128 struct {
	Hi uint64
	Lo uint64
}

type IOxm interface {
	Serializable
	GetOXMName() string
	GetOXMValue() interface{}
}

type IOxmMasked interface {
	Serializable
	GetOXMName() string
	GetOXMValue() interface{}
	GetOXMValueMask() interface{}
}

type IOxmId interface {
	Serializable
	GetOXMName() string
}

type IAction interface {
	Serializable
	GetType() uint16
	GetLen() uint16
	GetActionName() string
	GetActionFields() map[string]interface{}
}

func (self *Header) Decode(decoder *Decoder) (err error) {
	if decoder.Length() < 8 {
		return fmt.Errorf("Header packet too short: %d < 4", decoder.Length())
	}

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("Error while parsing OpenFlow packet: %+v", r)
			}
		}
	}()

	self.Version = decoder.ReadByte()
	self.Type = decoder.ReadByte()
	self.Length = decoder.ReadUint16()
	self.Xid = decoder.ReadUint32()

	return nil
}
