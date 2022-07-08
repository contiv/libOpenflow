package openflow15

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBundleControl(t *testing.T) {
	bundleCtrl := &BundleControl{
		BundleID: uint32(100),
		Type:     OFPBCT_OPEN_REQUEST,
		Flags:    OFPBCT_ATOMIC,
	}
	data, err := bundleCtrl.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal BundleControl message: %v", err)
	}
	bundleCtrl2 := new(BundleControl)
	err = bundleCtrl2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to Unmarshal BundleControl message: %v", err)
	}
	if err := bundleCtrlEqual(bundleCtrl, bundleCtrl2); err != nil {
		t.Errorf(err.Error())
	}
}

func TestBundleAdd(t *testing.T) {
	bundleAdd := &BundleAdd{
		BundleID: uint32(100),
		Flags:    OFPBCT_ATOMIC,
		Message:  NewFlowMod(),
	}

	data, err := bundleAdd.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal BundleAdd message: %v", err)
	}
	bundleAdd2 := new(BundleAdd)
	err = bundleAdd2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to Unmarshal BundleAdd message: %v", err)
	}
	if err := bundleAddEqual(bundleAdd, bundleAdd2); err != nil {
		t.Error(err.Error())
	}
}

func TestBundleError(t *testing.T) {
	bundleError := NewBundleError()
	bundleError.Code = BEC_TIMEOUT
	data, err := bundleError.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal VendorError message: %v", err)
	}
	var bundleErr2 VendorError
	err = bundleErr2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to Unmarshal VendorError message: %v", err)
	}
	assert.Equal(t, bundleError.Type, bundleErr2.Type)
	assert.Equal(t, bundleError.Code, bundleErr2.Code)
	assert.Equal(t, bundleError.ExperimenterID, bundleErr2.ExperimenterID)
	assert.Equal(t, bundleError.Header.Type, bundleErr2.Header.Type)
}

func TestVendorHeader(t *testing.T) {
	vh1 := new(VendorHeader)
	vh1.Header.Type = Type_Experimenter
	vh1.Header.Length = vh1.Len()
	vh1.Vendor = uint32(1000)
	vh1.ExperimenterType = uint32(2000)
	data, err := vh1.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal VendorHeader message: %v", err)
	}
	var vh2 VendorHeader
	err = vh2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to Unmarshal VendorHeader message: %v", err)
	}
	assert.Equal(t, vh1.Header.Type, vh2.Header.Type)
	assert.Equal(t, vh1.Vendor, vh2.Vendor)
	assert.Equal(t, vh1.ExperimenterType, vh2.ExperimenterType)
}

func TestBundleControlMessage(t *testing.T) {
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
		bundleCtrl := oriMessage.VendorData.(*BundleControl)
		bundleCtrl2, ok := newMessage.VendorData.(*BundleControl)
		if !ok {
			t.Fatalf("Failed to cast BundleControl from result")
		}
		if err = bundleCtrlEqual(bundleCtrl, bundleCtrl2); err != nil {
			t.Error(err.Error())
		}
	}

	bundleCtrl := &BundleControl{
		BundleID: uint32(100),
		Type:     OFPBCT_OPEN_REQUEST,
		Flags:    OFPBCT_ATOMIC,
	}
	msg := NewBundleControl(bundleCtrl)
	testFunc(msg)
}

func TestBundleAddMessage(t *testing.T) {
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
		bundleAdd := oriMessage.VendorData.(*BundleAdd)
		bundleAdd2, ok := newMessage.VendorData.(*BundleAdd)
		if !ok {
			t.Fatalf("Failed to cast BundleControl from result")
		}
		if err = bundleAddEqual(bundleAdd, bundleAdd2); err != nil {
			t.Error(err.Error())
		}
	}

	bundleAdd := &BundleAdd{
		BundleID: uint32(100),
		Flags:    OFPBCT_ATOMIC,
		Message:  NewFlowMod(),
	}
	msg := NewBundleAdd(bundleAdd)
	testFunc(msg)
}

func bundleCtrlEqual(bundleCtrl, bundleCtrl2 *BundleControl) error {
	if bundleCtrl.BundleID != bundleCtrl2.BundleID {
		return errors.New("bundle ID not equal")
	}
	if bundleCtrl.Type != bundleCtrl2.Type {
		return errors.New("bundle Type not equal")
	}
	if bundleCtrl.Flags != bundleCtrl2.Flags {
		return errors.New("bundle Flags not equal")
	}
	return nil
}

func bundleAddEqual(bundleAdd, bundleAdd2 *BundleAdd) error {
	if bundleAdd.BundleID != bundleAdd2.BundleID {
		return errors.New("bundle ID not equal")
	}
	if bundleAdd.Flags != bundleAdd2.Flags {
		return errors.New("bundle Flags not equal")
	}
	msgData, _ := bundleAdd.Message.MarshalBinary()
	msgData2, err := bundleAdd2.Message.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(msgData, msgData2) {
		return errors.New("bundle message not equal")
	}
	return nil
}
