package openflow13

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
)

func TestNXActionResubmit(t *testing.T) {
	tableID := uint8(10)
	portID := uint16(10)

	action1 := NewNXActionResubmit(portID)
	data1, err := action1.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to invoke NXAST_RESUBMIT.MarshalBinary: %v", err)
	}
	testAction1 := new(NXActionResubmitTable)
	testAction1.UnmarshalBinary(data1)
	if testAction1.InPort != portID {
		t.Errorf("Failed to invoke NXAST_RESUBMIT.UnmarshalBinary, expect: %x, actual: %x", portID, testAction1.InPort)
	}

	action2 := NewNXActionResubmitTableAction(portID, tableID)
	if action2.Length != 16 {
		t.Errorf("Failed to create action2 NXAST_RESUBMIT_TABLE")
	}
	data2, err := action2.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to invoke NXAST_RESUBMIT_TABLE.MarshalBinary: %v", err)
	}
	testAction2 := newNXActionResubmitTable()
	testAction2.UnmarshalBinary(data2)
	if testAction2.TableID != tableID {
		t.Errorf("Failed to invoke NXAST_RESUBMIT_TABLE.UnmarshalBinary, expect: %x, actual: %x", tableID, testAction2.TableID)
	}
	if testAction2.InPort != portID {
		t.Errorf("Failed to invoke NXAST_RESUBMIT_TABLE.UnmarshalBinary, expect: %x, actual: %x", portID, testAction2.InPort)
	}

	action3 := NewNXActionResubmitTableAction(OFPP_IN_PORT, tableID)
	if action3.Length != 16 {
		t.Errorf("Failed to create action2 NXAST_RESUBMIT_TABLE")
	}
	data3, err := action3.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to invoke NXAST_RESUBMIT_TABLE.MarshalBinary: %v", err)
	}
	testAction3 := newNXActionResubmitTable()
	testAction3.UnmarshalBinary(data3)
	if testAction3.TableID != tableID {
		t.Errorf("Failed to invoke NXAST_RESUBMIT_TABLE.UnmarshalBinary, expect: %x, actual: %x", tableID, testAction3.TableID)
	}
	if testAction3.InPort != OFPP_IN_PORT {
		t.Errorf("Failed to invoke NXAST_RESUBMIT_TABLE.UnmarshalBinary, expect: %x, actual: %x", portID, testAction3.InPort)
	}

	action4 := NewNXActionResubmitTableCT(portID, tableID)
	data4, err := action4.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to invoke NXAST_RESUBMIT_TABLE.MarshalBinary: %v", err)
	}
	testAction4 := newNXActionResubmitTableCT()
	testAction4.UnmarshalBinary(data4)
	if !testAction4.IsCT() {
		t.Error("Failed to invoke NXAST_RESUBMIT_TABLE.MarshalBinary")
	}
	if testAction4.TableID != tableID {
		t.Errorf("Failed to invoke NXAST_RESUBMIT_TABLE_CT.UnmarshalBinary, expect: %x, actual: %x", tableID, testAction4.TableID)
	}
	if testAction4.InPort != portID {
		t.Errorf("Failed to invoke NXAST_RESUBMIT_TABLE_CT.UnmarshalBinary, expect: %x, actual: %x", portID, testAction4.InPort)
	}

	action5 := NewNXActionResubmitTableCTNoInPort(tableID)
	data5, err := action5.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to invoke NXAST_RESUBMIT_TABLE.MarshalBinary: %v", err)
	}
	testAction5 := newNXActionResubmitTableCT()
	if !testAction5.IsCT() {
		t.Error("Failed to invoke NXAST_CT_RESUBMIT.MarshalBinary")
	}
	testAction5.UnmarshalBinary(data5)
	if testAction5.TableID != tableID {
		t.Errorf("Failed to invoke NXAST_CT_RESUBMIT.UnmarshalBinary, expect: %x, actual: %x", tableID, testAction5.TableID)
	}
	if testAction5.InPort != OFPP_IN_PORT {
		t.Errorf("Failed to invoke NXAST_CT_RESUBMIT.UnmarshalBinary, expect: %x, actual: %x", portID, testAction5.InPort)
	}
}

func TestNOfs(t *testing.T) {
	var start, ofs, end, nBits uint16
	start = uint16(16)
	ofs = uint16(16)
	nBits = uint16(16)
	end = uint16(31)

	encodeStartEnd := encodeOfsNbitsStartEnd(start, end)
	encodeOfsNbits := encodeOfsNbits(ofs, nBits)
	decodeOfs := decodeOfs(encodeOfsNbits)
	deCodeNbits := decodeNbits(encodeOfsNbits)

	if encodeStartEnd != encodeOfsNbits {
		t.Errorf("Failed to encode from start to end, expect: %d, actual: %d", encodeOfsNbits, encodeStartEnd)
	}
	if ofs != decodeOfs {
		t.Errorf("Failed to decode ofs, expect: %d, actual: %d", ofs, decodeOfs)
	}
	if nBits != deCodeNbits {
		t.Errorf("Failed to decode nBits, expect: %d, actual: %d", nBits, deCodeNbits)
	}
}

func TestUint32Message(t *testing.T) {
	tgtData := uint32(0xff00ff00)
	msg := newUint32Message(tgtData)
	if msg.Len() != 4 {
		t.Errorf("Failed to generate Uint32Message")
	}
	testData, err := msg.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to invoke Uint32Message.MarshalBinary, %v", err)
	}
	var testMsg = new(Uint32Message)
	err = testMsg.UnmarshalBinary(testData)
	if err != nil {
		t.Errorf("Failed to invoke Uint32Message.UnmarshalBinary, %v", err)
	}
	if testMsg.data != tgtData {
		t.Errorf("Failed to retrieve uint32 from Uint32Message, tgt: %d, actual: %d", tgtData, testMsg.data)
	}
}

func TestUint16Message(t *testing.T) {
	tgtData := uint16(0xfe10)
	msg := newUint16Message(tgtData)
	if msg.Len() != 2 {
		t.Errorf("Failed to generate Uint32Message")
	}
	testData, err := msg.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to invoke Uint32Message.MarshalBinary, %v", err)
	}
	var testMsg = new(Uint16Message)
	err = testMsg.UnmarshalBinary(testData)
	if err != nil {
		t.Errorf("Failed to invoke Uint32Message.UnmarshalBinary, %v", err)
	}
	if testMsg.data != tgtData {
		t.Errorf("Failed to retrieve uint32 from Uint32Message, tgt: %d, actual: %d", tgtData, testMsg.data)
	}
}

func TestNewUintXMask(t *testing.T) {
	tgtData32 := uint32(0xff)
	rng1 := &NXRange{start: 0, end: 7}
	testMsg := &Uint32Message{data: rng1.ToUint32Mask()}
	if testMsg.data != tgtData32 {
		t.Errorf("Failed to invoke newUint32Mask, expected: %02x, actual: %02x", tgtData32, testMsg.data)
	}
}

func TestNXMFieldHeader(t *testing.T) {
	for k := range oxxFieldHeaderMap {
		field1, err := FindFieldHeaderByName(k, false)
		if err != nil {
			t.Errorf("Test failed: %v", err)
		}
		testMatchFieldHeaderMarshalUnMarshal(field1, t)
		field2, _ := FindFieldHeaderByName(k, true)
		testMatchFieldHeaderMarshalUnMarshal(field2, t)
	}
}

func TestCTLabel(t *testing.T) {
	var label = [16]byte{}
	testData, err := hex.DecodeString(fmt.Sprintf("%d", 0x12345678))
	copy(label[:], testData)
	field := newCTLabel(label)
	data, err := field.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to MarshalBinary CTLabel: %v", err)
	}
	field2 := new(CTLabel)
	err = field2.UnmarshalBinary(data)
	if err != nil {
		t.Errorf("Failed to UnmarshalBinary message: %v", err)
	}
	if field2.data != label {
		t.Errorf("Unmarshalled CTLabel is incorrect, expect: %d, actual: %d", label, field2.data)
	}

	var mask = [16]byte{}
	binary.BigEndian.PutUint32(mask[:], 0xffffffff)
}

func TestNXActionCTNAT(t *testing.T) {
	act := NewNXActionCTNAT()
	if err := act.SetSNAT(); err != nil {
		t.Errorf("Failed to set SNAT action: %v", err)
	}
	if err := act.SetRandom(); err != nil {
		t.Errorf("Failed to set random action: %v", err)
	}
	ipMin := net.ParseIP("10.0.0.200")
	ipMax := net.ParseIP("10.0.0.240")
	act.SetRangeIPv4Min(ipMin)
	act.SetRangeIPv4Max(ipMax)
	minPort := uint16(2048)
	maxPort := uint16(10240)
	act.SetRangeProtoMin(&minPort)
	act.SetRangeProtoMax(&maxPort)
	data, err := act.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to Marshal NXActionCTNAT: %v", err)
	}
	act2 := new(NXActionCTNAT)
	err = act2.UnmarshalBinary(data)
	if err != nil {
		t.Errorf("Failed to Unmarshal NXActionCTNAT: %v", err)
	}
	if act2.rangeIPv4Min.String() != ipMin.String() {
		t.Errorf("Failed to set RangeIPv4Min, expect: %s, actual: %s", ipMin.String(), act2.rangeIPv4Min.String())
	}
	if act2.rangeIPv4Max.String() != ipMax.String() {
		t.Errorf("Failed to set rangeIPv4Max, expect: %s, actual: %s", ipMax.String(), act2.rangeIPv4Max.String())
	}
	if *act2.rangeProtoMin != minPort {
		t.Errorf("Failed to set SetRangeProtoMin, expect: %d, actual: %d", minPort, *act2.rangeProtoMin)
	}
	if *act2.rangeProtoMax != maxPort {
		t.Errorf("Failed to set SetRangeProtoMax, expect: %d, actual: %d", maxPort, *act2.rangeProtoMax)
	}
}

func TestNXActions(t *testing.T) {
	translateMessages(t, NewNXActionConjunction(uint8(1), uint8(3), uint32(0xffee)), new(NXActionConjunction), nxConjunctionEquals)

	dstField, _ := FindFieldHeaderByName("NXM_NX_REG0", false)
	loadData := uint64(0xf009)
	translateMessages(t, NewNXActionRegLoad(NewNXRange(0, 31).ToOfsBits(), dstField, loadData), new(NXActionRegLoad), nxRegLoadEquals)

	moveSrc, _ := FindFieldHeaderByName("NXM_OF_ETH_SRC", false)
	moveDst, _ := FindFieldHeaderByName("NXM_OF_ETH_DST", false)
	translateMessages(t, NewNXActionRegMove(48, 0, 0, moveSrc, moveDst), new(NXActionRegMove), nxRegMoveEquals)

	outputFiled, _ := FindFieldHeaderByName("NXM_NX_REG1", false)
	translateMessages(t, NewOutputFromField(outputFiled, NewNXRange(0, 31).ToOfsBits()), new(NXActionOutputReg), nxOutputRegEquals)
	translateMessages(t, NewOutputFromFieldWithMaxLen(outputFiled, NewNXRange(0, 31).ToOfsBits(), uint16(0xfffe)), new(NXActionOutputReg), nxOutputRegEquals)

	translateMessages(t, NewNXActionDecTTL(), new(NXActionDecTTL), nxDecTTLEquals)
	translateMessages(t, NewNXActionDecTTLCntIDs(2, uint16(1), uint16(2)), new(NXActionDecTTLCntIDs), nxDecTTLCntIDsEquals)

}

func translateMessages(t *testing.T, act1, act2 Action, compare func(act1, act2 Action, stype uint16) bool) {
	data, err := act1.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal message: %v", err)
	}
	err = act2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to Unmarshal NXActionCTNAT: %v", err)
	}
	if act1.Header().Type != act1.Header().Type || act1.Header().Type != ActionType_Experimenter {
		t.Errorf("Action type is not equal")
	}
	nxHeader1 := new(NXActionHeader)
	if err = nxHeader1.UnmarshalBinary(data); err != nil {
		t.Fatalf("Failed to unMarshal NXHeader")
	}
	result := compare(act1, act2, nxHeader1.Subtype)
	if !result {
		t.Errorf("Unmarshaled object is not equals to original one")
	}
}

func nxConjunctionEquals(o1, o2 Action, subtype uint16) bool {
	if subtype != NXAST_CONJUNCTION {
		return false
	}
	obj1 := o1.(*NXActionConjunction)
	obj2 := o2.(*NXActionConjunction)
	if obj1.ID != obj2.ID {
		return false
	}
	if obj1.NClause != obj2.NClause {
		return false
	}
	if obj1.Clause != obj2.Clause {
		return false
	}
	return true
}

func nxRegLoadEquals(o1, o2 Action, subtype uint16) bool {
	if subtype != NXAST_REG_LOAD {
		return false
	}
	obj1 := o1.(*NXActionRegLoad)
	obj2 := o2.(*NXActionRegLoad)
	if obj1.OfsNbits != obj2.OfsNbits {
		return false
	}
	if obj1.DstReg.Field != obj2.DstReg.Field {
		return false
	}
	if obj1.Value != obj2.Value {
		return false
	}
	return true
}

func nxRegMoveEquals(o1, o2 Action, subtype uint16) bool {
	if subtype != NXAST_REG_MOVE {
		return false
	}
	obj1 := o1.(*NXActionRegMove)
	obj2 := o2.(*NXActionRegMove)
	if obj1.DstField.Field != obj2.DstField.Field {
		return false
	}
	if obj1.SrcField.Field != obj2.SrcField.Field {
		return false
	}
	if obj1.SrcOfs != obj2.SrcOfs {
		return false
	}
	if obj1.DstOfs != obj2.DstOfs {
		return false
	}
	if obj1.Nbits != obj2.Nbits {
		return false
	}
	return true
}

func nxOutputRegEquals(o1, o2 Action, subtype uint16) bool {
	if subtype != NXAST_OUTPUT_REG {
		return false
	}
	obj1 := o1.(*NXActionOutputReg)
	obj2 := o2.(*NXActionOutputReg)
	if obj1.SrcField.Field != obj2.SrcField.Field {
		return false
	}
	if obj1.OfsNbits != obj2.OfsNbits {
		return false
	}
	if obj1.MaxLen != obj2.MaxLen {
		return false
	}
	return true
}

func nxDecTTLEquals(o1 Action, o2 Action, subtype uint16) bool {
	if subtype != NXAST_DEC_TTL {
		return false
	}
	obj1 := o1.(*NXActionDecTTL)
	obj2 := o2.(*NXActionDecTTL)
	if obj1.controllers != obj2.controllers {
		return false
	}
	if obj2.controllers != 0 {
		return false
	}
	return true
}

func nxDecTTLCntIDsEquals(o1 Action, o2 Action, subtype uint16) bool {
	if subtype != NXAST_DEC_TTL_CNT_IDS {
		return false
	}
	obj1 := o1.(*NXActionDecTTLCntIDs)
	obj2 := o2.(*NXActionDecTTLCntIDs)
	if obj1.controllers != obj2.controllers {
		return false
	}
	if len(obj1.cntIDs) != len(obj2.cntIDs) {
		return false
	}
	obj1CntMap := make(map[uint16]bool)
	for _, id := range obj1.cntIDs {
		obj1CntMap[id] = true
	}

	for _, id := range obj2.cntIDs {
		_, exist := obj1CntMap[id]
		if !exist {
			return false
		}
	}
	return true
}

func testMatchFieldHeaderMarshalUnMarshal(tgtField *MatchField, t *testing.T) {
	headerInt := tgtField.MarshalHeader()
	testMFHeader := new(MatchField)
	var data = make([]byte, 4)
	binary.BigEndian.PutUint32(data, headerInt)
	err := testMFHeader.UnmarshalHeader(data)
	if err != nil {
		t.Errorf("Failed to UnmarshalHeader: %v", err)
	}
	if testMFHeader.Class != tgtField.Class {
		t.Errorf("Unmarshalled header has incorrect 'Class' field, expect: %d, actual: %d", testMFHeader.Class, tgtField.Class)
	}
	if testMFHeader.Field != tgtField.Field {
		t.Errorf("Unmarshalled header has incorrect 'Field' field, expect: %d, actual: %d", testMFHeader.Field, tgtField.Field)
	}
	if testMFHeader.HasMask != tgtField.HasMask {
		t.Errorf("Unmarshalled header has incorrect 'HasMask' field, expect: %v, actual: %v", testMFHeader.HasMask, tgtField.HasMask)
	}
	if testMFHeader.Length != tgtField.Length {
		t.Errorf("Unmarshalled header has incorrect 'Length' field, expect: %d, actual: %d", testMFHeader.Length, tgtField.Length)
	}
}
