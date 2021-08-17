package openflow13

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/util"
)

func TestMultipartMessage(t *testing.T) {
	feature := newTableFeatures()
	mpartRequest := &MultipartRequest{
		Header: NewOfp13Header(),
		Type:   MultipartType_TableFeatures,
		Flags:  0,
		Body:   []util.Message{feature},
	}
	reqBytes, err := mpartRequest.MarshalBinary()
	require.Nil(t, err)
	deReq := new(MultipartRequest)
	err = deReq.UnmarshalBinary(reqBytes)
	require.Nil(t, err)
	assert.True(t, mpartRequestEquals(mpartRequest, deReq), "Original MultipartRequest not equal to the decoded object")
}

func mpartRequestEquals(oriReq, deReq *MultipartRequest) bool {
	if !headerEquals(oriReq.Header, deReq.Header) {
		return false
	}
	if oriReq.Type != deReq.Type {
		return false
	}
	if oriReq.Flags != deReq.Flags {
		return false
	}
	if oriReq.Body != nil && deReq.Body == nil || oriReq.Body == nil && deReq.Body != nil {
		return false
	}
	if oriReq.Body != nil {
		switch oriReq.Type {
		case MultipartType_TableFeatures:
			if len(oriReq.Body) != len(deReq.Body) {
				return false
			}
			for i := range oriReq.Body {
				if !ofPTableFeaturesEquals(oriReq.Body[i].(*OFPTableFeatures), deReq.Body[i].(*OFPTableFeatures)) {
					return false
				}
			}
		}
	}
	return true
}

func headerEquals(oriHeader, newHeader common.Header) bool {
	if oriHeader.Version != newHeader.Version {
		return false
	}
	if oriHeader.Xid != newHeader.Xid {
		return false
	}
	if oriHeader.Length != newHeader.Length {
		return false
	}
	if oriHeader.Type != newHeader.Type {
		return false
	}
	return true
}

func TestOFPTableFeatures(t *testing.T) {
	feature := newTableFeatures()

	fbytes, err := feature.MarshalBinary()
	require.Nil(t, err)
	deFeature := new(OFPTableFeatures)
	err = deFeature.UnmarshalBinary(fbytes)
	require.Nil(t, err)
	assert.True(t, ofPTableFeaturesEquals(feature, deFeature))
}

func newTableFeatures() *OFPTableFeatures {
	nameBytes := []byte("table-10")
	feature := &OFPTableFeatures{
		Length:     64,
		TableID:    10,
		Command:    0,
		Name:       [32]byte{},
		MaxEntries: 100000,
	}
	copy(feature.Name[0:], nameBytes)
	return feature
}

func ofPTableFeaturesEquals(f, df *OFPTableFeatures) bool {
	if f.Length != df.Length {
		return false
	}
	if f.TableID != df.TableID {
		return false
	}
	if f.Command != df.Command {
		return false
	}
	if f.Name != df.Name {
		return false
	}
	if f.Capabilities != df.Capabilities {
		return false
	}
	if f.MetadataMatch != df.MetadataMatch {
		return false
	}
	if f.MetadataWrite != df.MetadataWrite {
		return false
	}
	if f.MaxEntries != df.MaxEntries {
		return false
	}
	if len(f.Properties) != len(df.Properties) {
		return false
	}
	if len(f.Properties) > 0 {
		for i, p := range f.Properties {
			dfP := df.Properties[i]
			pd, _ := p.MarshalBinary()
			dfpd, _ := dfP.MarshalBinary()
			if !bytes.Equal(pd, dfpd) {
				return false
			}
		}
	}
	return true
}
