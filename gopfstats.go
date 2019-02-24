package pfstats

type Stats interface {
	// Enabled returns true if the firewall is enabled, otherwise false.
	Enabled() bool

	StateCount() int
	StateSearches() int
	StateInserts() int
	StateRemovals() int

	// IfStats returns statistics from the pf loginterface.
	// If the loginterface is unset, IfStats returns nil.
	// IfStats() *IfStats
}

// DIOCGETSTATUS struct pf_status *s
//              Get the internal packet filter statistics.
//
//              struct pf_status {
//                      u_int64_t       counters[PFRES_MAX];
//                      u_int64_t       lcounters[LCNT_MAX];
//                      u_int64_t       fcounters[FCNT_MAX];
//                      u_int64_t       scounters[SCNT_MAX];
//                      u_int64_t       pcounters[2][2][3];
//                      u_int64_t       bcounters[2][2];
//                      u_int32_t       running;
//                      u_int32_t       states;
//                      u_int32_t       src_nodes;
//                      u_int32_t       since;
//                      u_int32_t       debug;
//                      u_int32_t       hostid;
//                      char            ifname[IFNAMSIZ];
//                      u_int8_t        pf_chksum[MD5_DIGEST_LENGTH];
//              };

// Pf is a handle to the firewall loaded in the kernel.
type Pf interface {
	Stats() (Stats, error)
	// Anchors() ([]string, error)
	// Anchor(anchor string) (Anchor, error)
	// Queues() ([]Queue, error)
	Close() error
}
