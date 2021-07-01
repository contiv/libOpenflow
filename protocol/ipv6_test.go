package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"antrea-io/libOpenflow/util"
)

func TestIPv6Option(t *testing.T) {
	testFunc := func(oriMessage *Option) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(Option)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err := testOptionEqual(oriMessage, newMessage); err != nil {
			t.Error(err.Error())
		}
	}
	option := &Option{
		Type:   1,
		Length: 4,
		Data:   []byte{0x00, 0x00, 0x00, 0x00},
	}
	testFunc(option)
}

func testOptionEqual(oriMessage, newMessage *Option) error {
	if oriMessage.Type != newMessage.Type {
		return fmt.Errorf("Option Type not equal")
	}
	if oriMessage.Length != newMessage.Length {
		return fmt.Errorf("Option Length not equal")
	}
	if !bytes.Equal(oriMessage.Data, newMessage.Data) {
		return fmt.Errorf("Option Data not equal")
	}
	return nil
}

func TestHopByHopHeader(t *testing.T) {
	testFunc := func(oriMessage *HopByHopHeader) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(HopByHopHeader)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err := testHopByHopHeaderEqual(oriMessage, newMessage); err != nil {
			t.Errorf(err.Error())
		}
	}
	msg := &HopByHopHeader{
		NextHeader: 59,
		HEL:        0,
		Options: []*Option{
			{
				Type:   1,
				Length: 4,
				Data:   []byte{0x00, 0x00, 0x00, 0x00},
			},
		},
	}

	testFunc(msg)
}

func testHopByHopHeaderEqual(oriMessage, newMessage *HopByHopHeader) error {
	if oriMessage.NextHeader != newMessage.NextHeader {
		return fmt.Errorf("HopByHopHeader NextHeader not equal")
	}
	if oriMessage.HEL != newMessage.HEL {
		return fmt.Errorf("HopByHopHeader HEL not equal")
	}
	if len(oriMessage.Options) != len(newMessage.Options) {
		return fmt.Errorf("HopByHopHeader Options count not equal")
	}
	for i := range oriMessage.Options {
		if err := testOptionEqual(oriMessage.Options[i], newMessage.Options[i]); err != nil {
			return err
		}
	}
	return nil
}

func TestRoutingHeader(t *testing.T) {
	testFunc := func(oriMessage *RoutingHeader) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(RoutingHeader)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err := testRoutingHeaderEqual(oriMessage, newMessage); err != nil {
			t.Errorf(err.Error())
		}
	}
	data := make([]byte, 20)
	binary.BigEndian.PutUint32(data, uint32(0))
	nxtIP := net.ParseIP("2001:db8::3")
	copy(data[4:], nxtIP)
	msg := &RoutingHeader{
		NextHeader:   59,
		HEL:          2,
		RoutingType:  0,
		SegmentsLeft: 1,
		Data:         util.NewBuffer(data),
	}
	testFunc(msg)
}

func testRoutingHeaderEqual(oriMessage *RoutingHeader, newMessage *RoutingHeader) error {
	if oriMessage.NextHeader != newMessage.NextHeader {
		return fmt.Errorf("RoutingHeader NextHeader not equal")
	}
	if oriMessage.HEL != newMessage.HEL {
		return fmt.Errorf("RoutingHeader HEL not equal")
	}
	if oriMessage.RoutingType != newMessage.RoutingType {
		return fmt.Errorf("RoutingHeader RoutingType not equal")
	}
	if oriMessage.SegmentsLeft != newMessage.SegmentsLeft {
		return fmt.Errorf("RoutingHeader SegmentsLeft not equal")
	}
	if (oriMessage.Data != nil && newMessage.Data == nil) || (oriMessage.Data == nil && newMessage.Data != nil) {
		return fmt.Errorf("RoutingHeader Data not equal")
	}
	if (oriMessage.Data != nil && newMessage.Data != nil) && !bytes.Equal(oriMessage.Data.Bytes(), newMessage.Data.Bytes()) {
		return fmt.Errorf("RoutingHeader Data not equal")
	}
	return nil
}

func TestFragmentHeader(t *testing.T) {
	testFunc := func(oriMessage *FragmentHeader) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(FragmentHeader)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err := testFragmentHeaderEqual(oriMessage, newMessage); err != nil {
			t.Errorf(err.Error())
		}
	}

	msg := &FragmentHeader{
		NextHeader:     59,
		Reserved:       0,
		FragmentOffset: 0x1234,
		MoreFragments:  true,
		Identification: 0xabcd,
	}
	testFunc(msg)
}

func testFragmentHeaderEqual(oriMessage *FragmentHeader, newMessage *FragmentHeader) error {
	if oriMessage.NextHeader != newMessage.NextHeader {
		return fmt.Errorf("FragmentHeader NextHeader not equal")
	}
	if oriMessage.Reserved != newMessage.Reserved {
		return fmt.Errorf("FragmentHeader Reserved not equal")
	}
	if oriMessage.FragmentOffset != newMessage.FragmentOffset {
		return fmt.Errorf("FragmentHeader FragmentOffset not equal")
	}
	if oriMessage.MoreFragments != newMessage.MoreFragments {
		return fmt.Errorf("FragmentHeader MoreFragment not equal")
	}
	if oriMessage.Identification != newMessage.Identification {
		return fmt.Errorf("FragmentHeader Identification not equal")
	}
	return nil
}

func TestIPv6(t *testing.T) {
	testFunc := func(oriMessage *IPv6) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(IPv6)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		err = testIPv6Equals(oriMessage, newMessage)
		if err != nil {
			t.Error(err.Error())
		}
	}
	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")
	icmpData := make([]byte, 4)
	binary.BigEndian.PutUint32(icmpData, 0x34567890)
	uplayerData := &ICMP{
		Type:     128,
		Code:     0,
		Checksum: 0x2345,
		Data:     icmpData,
	}

	msg1 := &IPv6{
		Version:      6,
		TrafficClass: 1,
		FlowLabel:    0x12345,
		Length:       8,
		NextHeader:   Type_HBH,
		HopLimit:     64,
		NWSrc:        srcIP,
		NWDst:        dstIP,
	}
	msg1.HbhHeader = &HopByHopHeader{
		NextHeader: Type_IPv6ICMP,
		HEL:        0,
		Options: []*Option{
			{
				Type:   1,
				Length: 4,
				Data:   []byte{0x00, 0x00, 0x00, 0x00},
			},
		},
	}
	msg1.Data = uplayerData
	testFunc(msg1)

	msg2 := &IPv6{
		Version:      6,
		TrafficClass: 1,
		FlowLabel:    0x12345,
		Length:       8,
		NextHeader:   Type_Routing,
		HopLimit:     64,
		NWSrc:        srcIP,
		NWDst:        dstIP,
		Data:         uplayerData,
	}
	data := make([]byte, 20)
	binary.BigEndian.PutUint32(data, uint32(0))
	nxtIP := net.ParseIP("2001:db8::3")
	copy(data[4:], nxtIP)
	msg2.RoutingHeader = &RoutingHeader{
		NextHeader:   Type_Fragment,
		HEL:          2,
		RoutingType:  0,
		SegmentsLeft: 1,
		Data:         util.NewBuffer(data),
	}
	msg2.FragmentHeader = &FragmentHeader{
		NextHeader:     Type_IPv6ICMP,
		Reserved:       0,
		FragmentOffset: 0x1234,
		MoreFragments:  true,
		Identification: 0xabcd,
	}
	testFunc(msg2)
}

func testIPv6Equals(oriMessage, newMessage *IPv6) error {
	if oriMessage.Version != newMessage.Version {
		return fmt.Errorf("IPv6 version not equal")
	}
	if oriMessage.TrafficClass != newMessage.TrafficClass {
		return fmt.Errorf("IPv6 trafficClass not equal")
	}
	if oriMessage.FlowLabel != newMessage.FlowLabel {
		return fmt.Errorf("IPv6 flowLable not equal")
	}
	if oriMessage.Length != newMessage.Length {
		return fmt.Errorf("IPv6 Length not equal")
	}
	if oriMessage.NextHeader != newMessage.NextHeader {
		return fmt.Errorf("IPv6 NextHeader not equal")
	}
	if oriMessage.HopLimit != newMessage.HopLimit {
		return fmt.Errorf("IPv6 HotLimit not equal")
	}
	if !bytes.Equal(oriMessage.NWSrc, newMessage.NWSrc) {
		return fmt.Errorf("IPv6 NWSrc not equal")
	}
	if !bytes.Equal(oriMessage.NWDst, newMessage.NWDst) {
		return fmt.Errorf("IPv6 NWDst not equal")
	}
	oriData, err := oriMessage.Data.MarshalBinary()
	if err != nil {
		return err
	}
	newData, err := newMessage.Data.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(oriData, newData) {
		return fmt.Errorf("IPv6 Data not equal")
	}
	return nil
}
