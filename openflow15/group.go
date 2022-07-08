package openflow15

// This file has all group related defs

import (
	"encoding/binary"
	"errors"

	log "github.com/sirupsen/logrus"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/util"
)

const (
	OFPG_MAX = 0xffffff00 /* Last usable group number. */
	/* Fake groups. */
	OFPG_ALL = 0xfffffffc /* Represents all groups for group delete commands. */
	OFPG_ANY = 0xffffffff /* Wildcard group used only for flow stats requests. Selects all flows regardless of group (including flows with no group).
	 */
)

const (
	OFPGC_ADD           = 0 /* New group. */
	OFPGC_MODIFY        = 1 /* Modify all matching groups. */
	OFPGC_DELETE        = 2 /* Delete all matching groups. */
	OFPGC_INSERT_BUCKET = 3 /* Insert action buckets to the already available
	list of action buckets in a matching group */
	/* OFPGC_??? = 4, */ /* Reserved for future use. */
	OFPGC_REMOVE_BUCKET  = 5 /* Remove all action buckets or any specific action
	bucket from matching group */
)

const (
	GT_ALL      = 0 /* All (multicast/broadcast) group. */
	GT_SELECT   = 1 /* Select group. */
	GT_INDIRECT = 2 /* Indirect group. */
	GT_FF       = 3 /* Fast failover group. */
)

// GroupMod message
type GroupMod struct {
	common.Header
	Command         uint16 /* One of OFPGC_*. */
	Type            uint8  /* One of OFPGT_*. */
	pad             uint8  /* Pad to 64 bits. */
	GroupId         uint32 /* Group identifier. */
	BucketArrayLen  uint16 /* Length of action buckets data. */
	Pad             uint16
	CommandBucketId uint32 /* Bucket Id used as part of
	OFPGC_INSERT_BUCKET and OFPGC_REMOVE_BUCKET commands execution.*/
	Buckets    []Bucket /* List of buckets */
	Properties []util.Message
}

// Create a new group mod message
func NewGroupMod() *GroupMod {
	g := new(GroupMod)
	g.Header = NewOfp15Header()
	g.Header.Type = Type_GroupMod

	g.Command = OFPGC_ADD
	g.Type = GT_ALL
	g.GroupId = 0
	g.Buckets = make([]Bucket, 0)
	return g
}

// Add a bucket to group mod
func (g *GroupMod) AddBucket(bkt Bucket) {
	g.Buckets = append(g.Buckets, bkt)
	g.BucketArrayLen += bkt.Len()
}

func (g *GroupMod) Len() (n uint16) {
	n = g.Header.Len()
	n += 16

	for _, b := range g.Buckets {
		n += b.Len()
	}

	for _, p := range g.Properties {
		n += p.Len()
	}
	return
}

func (g *GroupMod) MarshalBinary() (data []byte, err error) {
	g.Header.Length = g.Len()
	data, err = g.Header.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 16)
	var n uint16
	binary.BigEndian.PutUint16(bytes[n:], g.Command)
	n += 2
	bytes[n] = g.Type
	n += 1
	n++ // Pad
	binary.BigEndian.PutUint32(bytes[n:], g.GroupId)
	n += 4
	binary.BigEndian.PutUint16(bytes[n:], g.BucketArrayLen)
	n += 2
	n += 2 // Pad
	if g.Command == OFPGC_ADD || g.Command == OFPGC_MODIFY || g.Command == OFPGC_DELETE {
		g.CommandBucketId = 0xffffffff
	}
	binary.BigEndian.PutUint32(bytes[n:], g.CommandBucketId)
	data = append(data, bytes...)

	for _, bkt := range g.Buckets {
		bytes, err = bkt.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
		g.BucketArrayLen += bkt.Len()
		log.Debugf("Groupmod bucket: %v", bytes)
	}

	for _, p := range g.Properties {
		bytes, err = p.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}
	log.Debugf("GroupMod(%d): %v", len(data), data)

	return
}

func (g *GroupMod) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = g.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n += g.Header.Len()

	g.Command = binary.BigEndian.Uint16(data[n:])
	n += 2
	g.Type = data[n]
	n += 1
	g.pad = data[n]
	n += 1
	g.GroupId = binary.BigEndian.Uint32(data[n:])
	n += 4
	g.BucketArrayLen = binary.BigEndian.Uint16(data[n:])
	n += 2
	n += 2 // Pad
	g.CommandBucketId = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < g.Header.Length {
		bkt := new(Bucket)
		err = bkt.UnmarshalBinary(data[n:])
		if err != nil {
			return
		}
		g.Buckets = append(g.Buckets, *bkt)
		n += bkt.Len()
	}

	for n < g.Header.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case GPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			return err
		}
		n += p.Len()
		g.Properties = append(g.Properties, p)
	}

	return nil
}

// ofp_group_prop_type
const (
	GPT_EXPERIMENTER = 0xFFFF /* Experimenter defined. */
)

// ofp_bucket
type Bucket struct {
	Length         uint16   /* Length the bucket in bytes, including this header and any padding to make it 64-bit aligned. */
	ActionArrayLen uint16   /* Length of all actions in bytes. */
	BucketId       uint32   /* Bucket Id used to identify bucket*/
	Actions        []Action /* zero or more actions */
	Properties     []util.Message
}

// ofp_group_bucket_prop_type
const (
	GBPT_WEIGHT       = 0      /* Select groups only. */
	GBPT_WATCH_PORT   = 1      /* Fast failover groups only. */
	GBPT_WATCH_GROUP  = 2      /* Fast failover groups only. */
	GBPT_EXPERIMENTER = 0xFFFF /* Experimenter defined. */
)

// Create a new Bucket
func NewBucket(id uint32) *Bucket {
	bkt := new(Bucket)

	bkt.Actions = make([]Action, 0)
	bkt.Length = bkt.Len()
	bkt.BucketId = id

	return bkt
}

// Add an action to the bucket
func (b *Bucket) AddAction(act Action) {
	b.Actions = append(b.Actions, act)
	b.ActionArrayLen += act.Len()
}

func (b *Bucket) AddProperty(prop util.Message) {
	b.Properties = append(b.Properties, prop)
}

func (b *Bucket) Len() (n uint16) {
	n = 8

	for _, a := range b.Actions {
		n += a.Len()
	}

	for _, p := range b.Properties {
		n += p.Len()
	}
	// Round it to closest multiple of 8
	n = ((n + 7) / 8) * 8
	return
}

func (b *Bucket) MarshalBinary() (data []byte, err error) {
	bytes := make([]byte, 8)
	n := 0
	b.Length = b.Len() // Calculate length first
	binary.BigEndian.PutUint16(bytes[n:], b.Length)
	n += 2
	binary.BigEndian.PutUint16(bytes[n:], b.ActionArrayLen)
	n += 2
	binary.BigEndian.PutUint32(bytes[n:], b.BucketId)
	n += 4
	data = append(data, bytes...)

	for _, a := range b.Actions {
		bytes, err = a.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
		b.ActionArrayLen += a.Len()
	}

	for _, p := range b.Properties {
		bytes, err = p.MarshalBinary()
		if err != nil {
			return
		}
		data = append(data, bytes...)
	}
	return
}

func (b *Bucket) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	b.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	b.ActionArrayLen = binary.BigEndian.Uint16(data[n:])
	n += 2
	b.BucketId = binary.BigEndian.Uint32(data[n:])
	n += 4

	for n < 8+b.ActionArrayLen {
		a, err := DecodeAction(data[n:])
		if err != nil {
			return err
		}
		b.Actions = append(b.Actions, a)
		n += a.Len()
	}

	for n < b.Length {
		var p util.Message
		switch binary.BigEndian.Uint16(data[n:]) {
		case GBPT_WEIGHT:
			p = new(GroupBucketPropWeight)
		case GBPT_WATCH_PORT:
			p = new(GroupBucketPropWatchPort)
		case GBPT_WATCH_GROUP:
			p = new(GroupBucketPropWatchGroup)
		case GBPT_EXPERIMENTER:
			p = new(PropExperimenter)
		default:
			err = errors.New("An unknown property type was received")
			return
		}
		err = p.UnmarshalBinary(data[n:])
		if err != nil {
			return err
		}
		n += p.Len()
		b.Properties = append(b.Properties, p)
	}
	return nil
}

// ofp_group_bucket_prop_weight
type GroupBucketPropWeight struct {
	Header PropHeader
	Weight uint16
	Pad    uint16
}

func NewGroupBucketPropWeight(weight uint16) *GroupBucketPropWeight {
	p := new(GroupBucketPropWeight)
	p.Header.Type = GBPT_WEIGHT
	p.Weight = weight
	return p
}

func (prop *GroupBucketPropWeight) Len() uint16 {
	n := prop.Header.Len()
	n += 4
	return n
}

func (prop *GroupBucketPropWeight) MarshalBinary() (data []byte, err error) {
	prop.Header.Length = prop.Len()

	data, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 4)
	binary.BigEndian.PutUint16(bytes[0:], prop.Weight)
	data = append(data, bytes...)

	return
}

func (prop *GroupBucketPropWeight) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = prop.Header.Len()

	prop.Weight = binary.BigEndian.Uint16(data[n:])

	return
}

// ofp_group_bucket_prop_watch
type GroupBucketPropWatch struct {
	Header PropHeader
	Watch  uint32
}

type GroupBucketPropWatchPort = GroupBucketPropWatch  //nolint
type GroupBucketPropWatchGroup = GroupBucketPropWatch //nolint

func NewGroupBucketPropWatchPort(watch uint32) *GroupBucketPropWatchPort {
	p := new(GroupBucketPropWatchPort)
	p.Header.Type = GBPT_WATCH_PORT
	p.Watch = watch
	return p
}

func NewGroupBucketPropWatchGroup(watch uint32) *GroupBucketPropWatchGroup {
	p := new(GroupBucketPropWatchGroup)
	p.Header.Type = GBPT_WATCH_GROUP
	p.Watch = watch
	return p
}

func (prop *GroupBucketPropWatch) Len() uint16 {
	n := prop.Header.Len()
	n += 4
	return n
}

func (prop *GroupBucketPropWatch) MarshalBinary() (data []byte, err error) {
	prop.Header.Length = prop.Len()

	data, err = prop.Header.MarshalBinary()
	if err != nil {
		return
	}

	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes[0:], prop.Watch)
	data = append(data, bytes...)

	return
}

func (prop *GroupBucketPropWatch) UnmarshalBinary(data []byte) (err error) {
	var n uint16
	err = prop.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return
	}
	n = prop.Header.Len()

	prop.Watch = binary.BigEndian.Uint32(data[n:])

	return
}
