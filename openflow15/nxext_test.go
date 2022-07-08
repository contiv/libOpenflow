package openflow15

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	if testMsg.Data != tgtData {
		t.Errorf("Failed to retrieve uint32 from Uint32Message, tgt: %d, actual: %d", tgtData, testMsg.Data)
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
	if testMsg.Data != tgtData {
		t.Errorf("Failed to retrieve uint32 from Uint32Message, tgt: %d, actual: %d", tgtData, testMsg.Data)
	}
}

func TestNewUintXMask(t *testing.T) {
	tgtData32 := uint32(0xff)
	rng1 := &NXRange{start: 0, end: 7}
	testMsg := &Uint32Message{Data: rng1.ToUint32Mask()}
	if testMsg.Data != tgtData32 {
		t.Errorf("Failed to invoke newUint32Mask, expected: %02x, actual: %02x", tgtData32, testMsg.Data)
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
	testData, _ := hex.DecodeString(fmt.Sprintf("%d", 0x12345678))
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

func TestNXActionNote(t *testing.T) {
	note := []byte("test-notes")
	oriAction := &NXActionNote{
		NXActionHeader: NewNxActionHeader(NXAST_NOTE),
		Note:           note,
	}
	data, err := oriAction.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal message: %v", err)
	}
	newAction := &NXActionNote{}
	err = newAction.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to UnMarshal message: %v", err)
	}
	oriNoteLength := len(oriAction.Note)
	newNoteLength := len(newAction.Note)
	if newNoteLength < oriNoteLength {
		t.Errorf("Failed to read all note data")
	}
	if !bytes.Equal(oriAction.Note, newAction.Note[:oriNoteLength]) {
		t.Errorf("note not equal")
	}
}

func TestNXLearnSpecHeader(t *testing.T) {
	testFunc := func(oriHeader *NXLearnSpecHeader) {
		data, err := oriHeader.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newHeader := &NXLearnSpecHeader{}
		err = newHeader.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err = nxLearnSpecHeaderEquals(oriHeader, newHeader); err != nil {
			t.Error(err)
		}
	}
	nBits := uint16(48)
	for _, f := range []func(n uint16) *NXLearnSpecHeader{
		NewLearnHeaderMatchFromValue,
		NewLearnHeaderMatchFromField,
		NewLearnHeaderLoadFromValue,
		NewLearnHeaderLoadFromField,
		NewLearnHeaderOutputFromField,
	} {
		testFunc(f(nBits))
	}
}

func TestNXLearnSpec(t *testing.T) {
	testFunc := func(oriSpec *NXLearnSpec) {
		data, err := oriSpec.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newSpec := new(NXLearnSpec)
		err = newSpec.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err = nxLearnSpecEquals(oriSpec, newSpec); err != nil {
			t.Error(err)
		}
	}

	for _, spec := range prepareLearnSpecs() {
		testFunc(spec)
	}
}

func TestNXActionLearn(t *testing.T) {
	testFunc := func(oriAction *NXActionLearn) {
		data, err := oriAction.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newAction := new(NXActionLearn)
		err = newAction.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err = nsLearnEquals(oriAction, newAction); err != nil {
			t.Error(err)
		}
	}

	action := &NXActionLearn{
		NXActionHeader: NewNxActionHeader(NXAST_LEARN),
		IdleTimeout:    10,
		HardTimeout:    20,
		Priority:       80,
		Cookie:         0x123456789abcdef0,
		TableID:        2,
		FinIdleTimeout: 2,
		FinHardTimeout: 4,
		LearnSpecs:     prepareLearnSpecs(),
	}
	testFunc(action)
}

func TestNewNXActionRegLoad2(t *testing.T) {
	testFunc := func(oriAction *NXActionRegLoad2) {
		data, err := oriAction.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newAction := new(NXActionRegLoad2)
		err = newAction.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		oriField := oriAction.DstField
		newField := newAction.DstField
		if oriField.Class != newField.Class {
			t.Error("MatchField class not equal")
		}
		if oriField.Field != newField.Field {
			t.Error("MatchField field not equal")
		}
		if oriField.Length != newField.Length {
			t.Error("MatchField length not equal")
		}
		if oriField.HasMask != newField.HasMask {
			t.Error("MatchFiedl mask not equal")
		}
		oriData, _ := oriField.Value.MarshalBinary()
		newData, err := newField.Value.MarshalBinary()
		if err != nil {
			t.Errorf("Failed to Marshal MatchField value: %v", err)
		}
		if !bytes.Equal(oriData, newData) {
			t.Error("Field data not equal")
		}
	}

	dstField, _ := FindFieldHeaderByName("NXM_NX_CT_MARK", false)
	dstField.Value = newUint32Message(uint32(0x1234))
	load2 := NewNXActionRegLoad2(dstField)
	testFunc(load2)
}

func TestNXActionController(t *testing.T) {
	testFunc := func(oriAction *NXActionController) {
		data, err := oriAction.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newAction := new(NXActionController)
		err = newAction.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if oriAction.ControllerID != newAction.ControllerID {
			t.Error("ControllerID not equal")
		}
		if oriAction.MaxLen != newAction.MaxLen {
			t.Error("MaxLen not equal")
		}
		if oriAction.Reason != newAction.Reason {
			t.Error("Reason not equal")
		}
	}

	nxController := NewNXActionController(uint16(1001))
	nxController.Reason = uint8(0)
	nxController.MaxLen = uint16(128)
	testFunc(nxController)
}

func TestSetControllerID(t *testing.T) {
	testFunc := func(oriMessage *VendorHeader) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(VendorHeader)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		newControllerID, ok := newMessage.VendorData.(*ControllerID)
		if !ok {
			t.Fatalf("Failed to cast ControllerID from result")
		}
		oriControllerID, _ := oriMessage.VendorData.(*ControllerID)
		if newControllerID.ID != oriControllerID.ID {
			t.Error("Controller ID not equal")
		}
	}

	controllerID := uint16(102)
	message := NewSetControllerID(controllerID)
	testFunc(message)
}

func TestTLVTableMap(t *testing.T) {
	testFunc := func(oriMessage *TLVTableMap) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMesage := new(TLVTableMap)
		err = newMesage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err = tlvMapEquals(oriMessage, newMesage); err != nil {
			t.Error(err.Error())
		}
	}

	tlvMap := &TLVTableMap{
		OptClass:  0xffff,
		OptType:   0,
		OptLength: 16,
		Index:     0,
	}
	testFunc(tlvMap)
}

func TestTLVTableMod(t *testing.T) {
	testFunc := func(oriMessage *TLVTableMod) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(TLVTableMod)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err = tlvMapModEqual(oriMessage, newMessage); err != nil {
			t.Error(err.Error())
		}
	}

	tlvMod := prepareTLVTableMod()
	testFunc(tlvMod)
}

func TestTLTableModMessage(t *testing.T) {
	testFunc := func(oriMessage *VendorHeader) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(VendorHeader)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		oriTLVMod := oriMessage.VendorData.(*TLVTableMod)
		newTLVMod, ok := newMessage.VendorData.(*TLVTableMod)
		if !ok {
			t.Fatalf("Failed to cast TLVTableMod from result")
		}
		if err = tlvMapModEqual(oriTLVMod, newTLVMod); err != nil {
			t.Error(err.Error())
		}
	}

	tlvModMessage := NewTLVTableModMessage(prepareTLVTableMod())
	testFunc(tlvModMessage)
}

func TestTLVTableReply(t *testing.T) {
	testFunc := func(oriMessage *TLVTableReply) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(TLVTableReply)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		if err = tlvTableReplyEqual(oriMessage, newMessage); err != nil {
			t.Error(err)
		}
	}

	reply := &TLVTableReply{
		MaxSpace:  248,
		MaxFields: 62,
		TlvMaps:   prepareTLVTableMaps(),
	}
	testFunc(reply)
}

func TestTLVTableReplyMessage(t *testing.T) {
	testFunc := func(oriMessage *VendorHeader) {
		data, err := oriMessage.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to Marshal message: %v", err)
		}
		newMessage := new(VendorHeader)
		err = newMessage.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Failed to UnMarshal message: %v", err)
		}
		oriTLVReply := oriMessage.VendorData.(*TLVTableReply)
		newTLVReply, ok := newMessage.VendorData.(*TLVTableReply)
		if !ok {
			t.Fatalf("Failed to cast TLVTableReply from result")
		}
		if err = tlvTableReplyEqual(oriTLVReply, newTLVReply); err != nil {
			t.Error(err.Error())
		}
	}

	reply := &TLVTableReply{
		MaxSpace:  248,
		MaxFields: 62,
		TlvMaps:   prepareTLVTableMaps(),
	}
	tlvReplyMessage := NewNXTVendorHeader(Type_TlvTableReply)
	tlvReplyMessage.VendorData = reply
	testFunc(tlvReplyMessage)
}

func tlvTableReplyEqual(oriMessage, newMessage *TLVTableReply) error {
	if oriMessage.MaxSpace != newMessage.MaxSpace {
		return errors.New("Max space not equal")
	}
	if oriMessage.MaxFields != newMessage.MaxFields {
		return errors.New("Max field not equal")
	}
	for i := range oriMessage.TlvMaps {
		if err := tlvMapEquals(oriMessage.TlvMaps[i], newMessage.TlvMaps[i]); err != nil {
			return err
		}
	}
	return nil
}

func tlvMapModEqual(oriMessage *TLVTableMod, newMessage *TLVTableMod) error {
	if oriMessage.Command != newMessage.Command {
		return errors.New("message command not equal")
	}
	for i := range oriMessage.TlvMaps {
		if err := tlvMapEquals(oriMessage.TlvMaps[i], newMessage.TlvMaps[i]); err != nil {
			return err
		}
	}
	return nil
}

func prepareTLVTableMaps() []*TLVTableMap {
	tlvMap1 := &TLVTableMap{
		OptClass:  0xffff,
		OptType:   0,
		OptLength: 16,
		Index:     0,
	}
	tlvMap2 := &TLVTableMap{
		OptClass:  0xffff,
		OptType:   1,
		OptLength: 16,
		Index:     1,
	}
	return []*TLVTableMap{tlvMap1, tlvMap2}
}

func prepareTLVTableMod() *TLVTableMod {

	tlvMapMod := &TLVTableMod{
		Command: NXTTMC_ADD,
		TlvMaps: prepareTLVTableMaps(),
	}
	return tlvMapMod
}
func tlvMapEquals(oriTlvMap, newTlvMap *TLVTableMap) error {
	if oriTlvMap.OptClass != newTlvMap.OptClass {
		return errors.New("TLVTableMap option: Class not equal")
	}
	if oriTlvMap.OptLength != newTlvMap.OptLength {
		return errors.New("TLVTableMap option: Length not equal")
	}
	if oriTlvMap.OptType != newTlvMap.OptType {
		return errors.New("TLVTableMap option: Type not equal")
	}
	if oriTlvMap.Index != newTlvMap.Index {
		return errors.New("TLVTableMap option: Index not equal")
	}
	return nil
}

func prepareLearnSpecs() []*NXLearnSpec {
	srcValue1 := make([]byte, 2)
	binary.BigEndian.PutUint16(srcValue1, 99)
	dstField1, _ := FindFieldHeaderByName("NXM_OF_IN_PORT", false)
	dstSpecField1 := &NXLearnSpecField{dstField1, 0}
	srcField2, _ := FindFieldHeaderByName("NXM_OF_ETH_SRC", false)
	srcSpecField2 := &NXLearnSpecField{srcField2, 0}
	dstField2, _ := FindFieldHeaderByName("NXM_OF_ETH_DST", false)
	dstSpecField2 := &NXLearnSpecField{dstField2, 0}
	srcField3, _ := FindFieldHeaderByName("NXM_OF_IN_PORT", false)
	srcSpecField3 := &NXLearnSpecField{srcField3, 0}
	dstField3, _ := FindFieldHeaderByName("NXM_NX_REG1", false)
	dstSpecField3 := &NXLearnSpecField{dstField3, 16}
	srcValue4, _ := hex.DecodeString("aabbccddeeff")
	dstField4, _ := FindFieldHeaderByName("NXM_OF_ETH_SRC", false)
	dstSpecField4 := &NXLearnSpecField{dstField4, 0}
	srcField5, _ := FindFieldHeaderByName("NXM_OF_IN_PORT", false)
	srcSpecField5 := &NXLearnSpecField{srcField5, 0}
	return []*NXLearnSpec{
		{Header: NewLearnHeaderMatchFromValue(16), SrcValue: srcValue1, DstField: dstSpecField1},
		{Header: NewLearnHeaderMatchFromField(48), SrcField: srcSpecField2, DstField: dstSpecField2},
		{Header: NewLearnHeaderLoadFromField(16), SrcField: srcSpecField3, DstField: dstSpecField3},
		{Header: NewLearnHeaderLoadFromValue(48), SrcValue: srcValue4, DstField: dstSpecField4},
		{Header: NewLearnHeaderOutputFromField(16), SrcField: srcSpecField5},
	}
}

func nsLearnEquals(oriAction, newAction *NXActionLearn) error {
	if oriAction.IdleTimeout != newAction.IdleTimeout {
		return errors.New("learn idleTimeout not equal")
	}
	if oriAction.HardTimeout != newAction.HardTimeout {
		return errors.New("learn hardTimeout not equal")
	}
	if oriAction.Priority != newAction.Priority {
		return errors.New("learn priority not equal")
	}
	if oriAction.Flags != newAction.Flags {
		return errors.New("learn cookie not equal")
	}
	if oriAction.Cookie != newAction.Cookie {
		return errors.New("learn cookie not equal")
	}
	if oriAction.TableID != newAction.TableID {
		return errors.New("learn table not equal")
	}
	if oriAction.FinIdleTimeout != newAction.FinIdleTimeout {
		return errors.New("learn finIdleTimeout not equal")
	}
	if oriAction.FinHardTimeout != newAction.FinHardTimeout {
		return errors.New("learn finHardTimeout not equal")
	}
	if len(oriAction.LearnSpecs) != len(newAction.LearnSpecs) {
		return errors.New("learn spec count not equal")
	}
	for idx := range oriAction.LearnSpecs {
		oriSpec := oriAction.LearnSpecs[idx]
		newSpec := newAction.LearnSpecs[idx]
		if err := nxLearnSpecEquals(oriSpec, newSpec); err != nil {
			return err
		}
	}

	return nil
}

func nxLearnSpecEquals(oriSpec, newSpec *NXLearnSpec) error {
	if err := nxLearnSpecHeaderEquals(oriSpec.Header, newSpec.Header); err != nil {
		return err
	}
	if err := nxLearnSpecFieldEquals(oriSpec.SrcField, newSpec.SrcField); err != nil {
		return err
	}
	if err := nxLearnSpecFieldEquals(oriSpec.DstField, newSpec.DstField); err != nil {
		return err
	}
	if !bytes.Equal(oriSpec.SrcValue, newSpec.SrcValue) {
		return errors.New("spec src value not equal")
	}
	return nil
}

func nxLearnSpecFieldEquals(oriField, newField *NXLearnSpecField) error {
	if (oriField != nil && newField == nil) || (oriField == nil && newField != nil) {
		return errors.New("spec field not equal")
	}
	if oriField != nil && newField != nil {
		if oriField.Ofs != newField.Ofs {
			return errors.New("spec ofs not equal")
		}
		oriFieldHeader := oriField.Field.MarshalHeader()
		newFieldHeader := newField.Field.MarshalHeader()
		if oriFieldHeader != newFieldHeader {
			return errors.New("spec field header not equal")
		}
	}
	return nil
}

func nxLearnSpecHeaderEquals(oriHeader, newHeader *NXLearnSpecHeader) error {
	if oriHeader.length != newHeader.length {
		return errors.New("header length not equal")
	}
	if oriHeader.src != newHeader.src {
		return errors.New("header src not equal")
	}
	if oriHeader.dst != newHeader.dst {
		return errors.New("header dst not equal")
	}
	if oriHeader.nBits != newHeader.nBits {
		return errors.New("header nBits not equal")
	}
	if oriHeader.output != newHeader.output {
		return errors.New("header output not equal")
	}
	return nil
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
	if act1.Header().Type != act2.Header().Type || act1.Header().Type != ActionType_Experimenter {
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
