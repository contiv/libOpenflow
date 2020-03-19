package openflow13

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBundleControl(t *testing.T) {
	bundleCtrl := NewBundleControl()
	bundleID := uint32(100)
	bundleType := OFPBCT_OPEN_REQUEST
	bundleCtrl.BundleID = bundleID
	bundleCtrl.Type = bundleType
	bundleCtrl.Flags = OFPBCT_ATOMIC
	data, err := bundleCtrl.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal BundleControl message: %v", err)
	}
	var bundleCtrl2 BundleControl
	err = bundleCtrl2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to Unmarshal BundleControl message: %v", err)
	}
	assert.Equal(t, bundleCtrl.BundleID, bundleCtrl2.BundleID)
	assert.Equal(t, bundleCtrl.Type, bundleCtrl2.Type)
	assert.Equal(t, bundleCtrl.Flags, bundleCtrl2.Flags)
	assert.Equal(t, bundleCtrl.Length, bundleCtrl2.Length)
}

func TestBundleAdd(t *testing.T) {
	bundleAdd := NewBundleAdd()
	bundleID := uint32(100)
	bundleAdd.BundleID = bundleID
	bundleAdd.Flags = OFPBCT_ATOMIC
	bundleAdd.Message = NewFlowMod()
	data, err := bundleAdd.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal BundleAdd message: %v", err)
	}
	var bundleAdd2 BundleAdd
	err = bundleAdd2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to Unmarshal BundleAdd message: %v", err)
	}
	assert.Equal(t, bundleAdd.BundleID, bundleAdd2.BundleID)
	assert.Equal(t, bundleAdd.Type, bundleAdd2.Type)
	assert.Equal(t, bundleAdd.Flags, bundleAdd2.Flags)
	assert.Equal(t, bundleAdd.Length, bundleAdd2.Length)
}

func TestBundleError(t *testing.T) {
	bundleError := NewBundleError()
	bundleError.Code = BEC_TIMEOUT
	data, err := bundleError.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to Marshal BundleError message: %v", err)
	}
	var bundleErr2 BundleError
	err = bundleErr2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("Failed to Unmarshal BundleError message: %v", err)
	}
	assert.Equal(t, bundleError.Type, bundleErr2.Type)
	assert.Equal(t, bundleError.Code, bundleErr2.Code)
	assert.Equal(t, bundleError.ExperimenterID, bundleErr2.ExperimenterID)
	assert.Equal(t, bundleError.Header.Type, bundleErr2.Header.Type)
}

func TestVendorHeader(t *testing.T) {
	vh1 := new(VendorHeader)
	vh1.Header.Type = Type_Experimenter
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
