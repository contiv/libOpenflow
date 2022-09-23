package openflow15

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/util"
)

// Bundle control types
const (
	OFPBCT_OPEN_REQUEST uint16 = iota
	OFPBCT_OPEN_REPLY
	OFPBCT_CLOSE_REQUEST
	OFPBCT_CLOSE_REPLY
	OFPBCT_COMMIT_REQUEST
	OFPBCT_COMMIT_REPLY
	OFPBCT_DISCARD_REQUEST
	OFPBCT_DISCARD_REPLY
)

// Bundle message types
const (
	Type_BundleCtrl uint32 = 2300
	Type_BundleAdd  uint32 = 2301
)

// Bundle control flags
const (
	OFPBCT_ATOMIC  = uint16(1 << 0)
	OFPBCT_ORDERED = uint16(1 << 1)
)

// Bundle property types
const (
	OFPBPT_EXPERIMENTER = 0xFFFF
)

// Bundle error code.
const (
	BEC_UNKNOWN           uint16 = 2300 /* Unspecified error. */
	BEC_ERERM             uint16 = 2301 /* Permissions error. */
	BEC_BAD_ID            uint16 = 2302 /* Bundle ID doesn't exist. */
	BEC_BUNDLE_EXIST      uint16 = 2303 /* Bundle ID already exist. */
	BEC_BUNDLE_CLOSED     uint16 = 2304 /* Bundle ID is closed. */
	BEC_OUT_OF_BUNDLE     uint16 = 2305 /* Too many bundle IDs. */
	BEC_BAD_TYPE          uint16 = 2306 /* Unsupported or unknown message control type. */
	BEC_BAD_FLAGS         uint16 = 2307 /* Unsupported, unknown or inconsistent flags. */
	BEC_MSG_BAD_LEN       uint16 = 2308 /* Length problem in included message. */
	BEC_MSG_BAD_XID       uint16 = 2309 /* Inconsistent or duplicate XID. */
	BEC_MSG_UNSUP         uint16 = 2310 /* Unsupported message in this bundle. */
	BEC_MSG_CONFLICT      uint16 = 2311 /* Unsupported message combination in this bundle. */
	BEC_MSG_TOO_MANY      uint16 = 2312 /* Can't handle this many messages in bundle. */
	BEC_MSG_FAILD         uint16 = 2313 /* One message in bundle failed. */
	BEC_TIMEOUT           uint16 = 2314 /* Bundle is taking too long. */
	BEC_BUNDLE_IN_PROCESS uint16 = 2315 /* Bundle is locking the resource. */
)

// BundleControl is a message to control the bundle.
type BundleControl struct {
	BundleID uint32
	Type     uint16
	Flags    uint16
}

func (b *BundleControl) Len() (n uint16) {
	return uint16(unsafe.Sizeof(b.BundleID) + unsafe.Sizeof(b.Type) + unsafe.Sizeof(b.Flags))
}

func (b *BundleControl) MarshalBinary() (data []byte, err error) {
	data = make([]byte, b.Len())
	n := 0
	binary.BigEndian.PutUint32(data[n:], b.BundleID)
	n += 4
	binary.BigEndian.PutUint16(data[n:], b.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], b.Flags)
	n += 2
	return
}

func (b *BundleControl) UnmarshalBinary(data []byte) error {
	if len(data) < int(b.Len()) {
		return errors.New("the []byte is too short to unmarshal a full BundleControl message")
	}
	n := 0
	b.BundleID = binary.BigEndian.Uint32(data[n:])
	n += 4
	b.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	b.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	return nil
}

func NewBundleControl(bundleControl *BundleControl) *VendorHeader {
	h := NewOfp15Header()
	h.Type = Type_Experimenter
	return &VendorHeader{
		Header:           h,
		Vendor:           ONF_EXPERIMENTER_ID,
		ExperimenterType: Type_BundleCtrl,
		VendorData:       bundleControl,
	}
}

type BundlePropertyExperimenter struct {
	Type             uint16
	Length           uint16
	ExperimenterID   uint32
	ExperimenterType uint32
	data             []byte
}

func (p *BundlePropertyExperimenter) Len() uint16 {
	length := uint16(unsafe.Sizeof(p.Type) + unsafe.Sizeof(p.Length) + unsafe.Sizeof(p.ExperimenterID) + unsafe.Sizeof(p.ExperimenterType))
	return length + uint16(len(p.data))
}

func (p *BundlePropertyExperimenter) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 0)
	n := 0
	binary.BigEndian.PutUint16(data[n:], p.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], p.Length)
	n += 2
	binary.BigEndian.PutUint32(data[n:], p.ExperimenterID)
	n += 4
	binary.BigEndian.PutUint32(data[n:], p.ExperimenterType)
	n += 4
	if p.data != nil {
		data = append(data, p.data...)
	}
	return
}

func (p *BundlePropertyExperimenter) UnmarshalBinary(data []byte) error {
	if len(data) < int(p.Len()) {
		return errors.New("the []byte is too short to unmarshal a full BundlePropertyExperimenter message")
	}
	n := 0
	p.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	p.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	p.ExperimenterID = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.ExperimenterType = binary.BigEndian.Uint32(data[n:])
	n += 4
	if len(data) < int(p.Length) {
		p.data = data[n:]
	}
	return nil
}

func NewBundlePropertyExperimenter() *BundlePropertyExperimenter {
	p := new(BundlePropertyExperimenter)
	p.Type = OFPBPT_EXPERIMENTER
	return p
}

// BundleAdd is a message to add supported message in the opened bundle. After all required messages are added,
// close the bundle and commit it. The Switch will realized added messages in the bundle. Discard the bundle after close
// it, if the added messages are not wanted to realize on the switch.
type BundleAdd struct {
	BundleID   uint32
	pad        [2]byte
	Flags      uint16
	Message    util.Message
	Properties []BundlePropertyExperimenter
}

func (b *BundleAdd) Len() (n uint16) {
	length := uint16(unsafe.Sizeof(b.BundleID) + unsafe.Sizeof(b.Flags))
	length += uint16(len(b.pad))
	length += b.Message.Len()
	if b.Properties != nil {
		for _, p := range b.Properties {
			length += p.Len()
		}
	}
	return length
}

func (b *BundleAdd) MarshalBinary() (data []byte, err error) {
	data = make([]byte, b.Len())
	n := 0
	binary.BigEndian.PutUint32(data[n:], b.BundleID)
	n += 4
	// skip padding headerBytes
	n += 2
	binary.BigEndian.PutUint16(data[n:], b.Flags)
	n += 2
	msgBytes, err := b.Message.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], msgBytes)
	n += len(msgBytes)
	if b.Properties != nil {
		for _, property := range b.Properties {
			propertyData, err := property.MarshalBinary()
			if err != nil {
				return data, err
			}
			copy(data[n:], propertyData)
			n += len(propertyData)
		}
	}

	return
}

func (b *BundleAdd) UnmarshalBinary(data []byte) error {
	var err error
	n := 0
	b.BundleID = binary.BigEndian.Uint32(data[n:])
	n += 4
	// skip padding bytes
	n += 2
	b.Flags = binary.BigEndian.Uint16(data[n:])
	n += 2
	b.Message, err = Parse(data[n:])
	if err != nil {
		return fmt.Errorf("failed to parse BundleAdd's Message: %v", err)
	}
	n += int(b.Message.Len())
	if n < len(data) {
		b.Properties = make([]BundlePropertyExperimenter, 0)
		for n < len(data) {
			var property BundlePropertyExperimenter
			err = property.UnmarshalBinary(data[n:])
			if err != nil {
				klog.ErrorS(err, "Failed to unmarshal BundlePropertyExperimenter", "data", data)
				return err
			}
			b.Properties = append(b.Properties, property)
			n += int(property.Len())
		}
	}
	return err
}

func NewBundleAdd(bundleAdd *BundleAdd) *VendorHeader {
	h := NewOfp15Header()
	h.Type = Type_Experimenter
	return &VendorHeader{
		Header:           h,
		Vendor:           ONF_EXPERIMENTER_ID,
		ExperimenterType: Type_BundleAdd,
		VendorData:       bundleAdd,
	}
}

type VendorError struct {
	*ErrorMsg
	ExperimenterID uint32
}

func (e *VendorError) Len() uint16 {
	return e.ErrorMsg.Len() + uint16(unsafe.Sizeof(e.ExperimenterID))
}

func (e *VendorError) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(e.Len()))
	n := 0

	headerBytes, err := e.Header.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], headerBytes)
	n += len(headerBytes)
	binary.BigEndian.PutUint16(data[n:], e.Type)
	n += 2
	binary.BigEndian.PutUint16(data[n:], e.Code)
	n += 2
	binary.BigEndian.PutUint32(data[n:], e.ExperimenterID)
	n += 4
	headerBytes, err = e.Data.MarshalBinary()
	if err != nil {
		return
	}
	copy(data[n:], headerBytes)
	n += len(headerBytes)
	return
}

func (e *VendorError) UnmarshalBinary(data []byte) error {
	n := 0
	e.ErrorMsg = new(ErrorMsg)
	err := e.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	n += int(e.Header.Len())
	e.Type = binary.BigEndian.Uint16(data[n:])
	n += 2
	e.Code = binary.BigEndian.Uint16(data[n:])
	n += 2
	e.ExperimenterID = binary.BigEndian.Uint32(data[n:])
	n += 4
	err = e.Data.UnmarshalBinary(data[n:])
	if err != nil {
		klog.ErrorS(err, "Failed to unmarshal VendorError's Data", "data", data)
		return err
	}
	n += int(e.Data.Len())
	return nil
}

func NewBundleError() *VendorError {
	e := new(VendorError)
	e.ErrorMsg = NewErrorMsg()
	e.Header = NewOfp15Header()
	e.Type = ET_EXPERIMENTER
	e.ExperimenterID = ONF_EXPERIMENTER_ID
	return e
}

// ParseBundleError returns error according to bundle error code.
func ParseBundleError(errCode uint16) error {
	switch errCode {
	case BEC_UNKNOWN:
		return errors.New("unknown bundle error")
	case BEC_ERERM:
		return errors.New("permissions error")
	case BEC_BAD_ID:
		return errors.New("bundle ID doesn't exist")
	case BEC_BUNDLE_EXIST:
		return errors.New("bundle ID already exists")
	case BEC_BUNDLE_CLOSED:
		return errors.New("bundle ID is closed")
	case BEC_OUT_OF_BUNDLE:
		return errors.New("too many bundle IDs")
	case BEC_BAD_TYPE:
		return errors.New("unsupported or unknown message control type")
	case BEC_BAD_FLAGS:
		return errors.New("unsupported, unknown or inconsistent flags")
	case BEC_MSG_BAD_LEN:
		return errors.New("length problem in included message")
	case BEC_MSG_BAD_XID:
		return errors.New("inconsistent or duplicate XID")
	case BEC_MSG_UNSUP:
		return errors.New("unsupported message in this bundle")
	case BEC_MSG_CONFLICT:
		return errors.New("unsupported message combination in this bundle")
	case BEC_MSG_TOO_MANY:
		return errors.New("can't handle this many messages in bundle")
	case BEC_MSG_FAILD:
		return errors.New("one message in bundle failed")
	case BEC_TIMEOUT:
		return errors.New("bundle is taking too long")
	case BEC_BUNDLE_IN_PROCESS:
		return errors.New("bundle is locking the resource")
	}
	return nil
}
