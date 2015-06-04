package openflow13

// This file has all group related defs

const (
    OFPG_MAX = 0xffffff00  /* Last usable group number. */
    /* Fake groups. */
    OFPG_ALL = 0xfffffffc /* Represents all groups for group delete commands. */
    OFPG_ANY = 0xffffffff /* Wildcard group used only for flow stats requests. Selects all flows regardless of group (including flows with no group).
    */
)

// FIXME: Add all the group constructs here
