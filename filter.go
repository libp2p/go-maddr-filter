package filter

import (
	"net"
	"sync"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

type filterEntry struct {
	f      *net.IPNet
	reject bool
}

// Filters is a structure representing a collection of allow/deny
// net.IPNet filters, together with the RejectByDefault flag, which
// represents the default filter policy.
//
// Note that the last policy added to the Filters is authoritative.
type Filters struct {
	RejectByDefault bool

	mu      sync.RWMutex
	filters []*filterEntry
}

// NewFilters constructs and returns a new set of net.IPNet filters.
// By default, the new filter rejects no addresses.
func NewFilters() *Filters {
	return &Filters{
		RejectByDefault: false,
		filters:         make([]*filterEntry, 0),
	}
}

func (fs *Filters) find(ff *net.IPNet) int {
	ffs := ff.String()
	for idx, ft := range fs.filters {
		if ft.f.String() == ffs {
			return idx
		}
	}

	return -1
}

// AddDialFilter adds a reject rule to the given Filters.  Hosts
// matching the given net.IPNet filter will be rejected, unless
// another rule is added which states that they should be accepted.
//
// No effort is made to prevent duplication of filters, or to simplify
// the filters list.
func (fs *Filters) AddDialFilter(f *net.IPNet) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	idx := fs.find(f)
	if idx != -1 {
		fs.filters[idx].reject = true
	} else {
		fs.filters = append(fs.filters, &filterEntry{f: f, reject: true})
	}
}

// AddDenyFilter is an alias of AddDialFilter (which is preserved to prevent
// an immediate breaking change.)
func (fs *Filters) AddDenyFilter(f *net.IPNet) {
	fs.AddDialFilter(f)
}

// AddAllowFilter adds an accept rule to the given Filters. Hosts
// matching the given net.IPNet filter will be accepted, unless
// another policy is added which states that they should be rejected.
//
// No effort is made to prevent duplication of filters, or to simplify
// the filters list.
func (fs *Filters) AddAllowFilter(f *net.IPNet) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	idx := fs.find(f)
	if idx != -1 {
		fs.filters[idx].reject = false
	} else {
		fs.filters = append(fs.filters, &filterEntry{f: f, reject: false})
	}
}

// Remove removes all net.IPNet's accept/reject rule(s) from the
// Filters, if there are matching rules.
//
// Makes no distinction between whether the rule is an allow or a
// deny.
func (fs *Filters) Remove(ff *net.IPNet) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	idx := fs.find(ff)
	if idx != -1 {
		fs.filters = append(fs.filters[:idx], fs.filters[idx+1:]...)
	}
}

// AddrBlocked parses a ma.Multiaddr and, if it can get a valid netip
// back, applies the Filters returning true if the given address
// should be rejected, and false if the given address is allowed.
//
// If a parsing error occurs, or no filter matches, the Filters
// default is returned.
func (fs *Filters) AddrBlocked(a ma.Multiaddr) bool {
	maddr := ma.Split(a)
	if len(maddr) == 0 {
		return fs.RejectByDefault
	}
	netaddr, err := manet.ToNetAddr(maddr[0])
	if err != nil {
		// if we cant parse it, its probably not blocked
		return fs.RejectByDefault
	}
	netip := net.ParseIP(netaddr.String())
	if netip == nil {
		return fs.RejectByDefault
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	reject := fs.RejectByDefault

	for _, ft := range fs.filters {
		if ft.f.Contains(netip) {
			reject = ft.reject
		}
	}

	return reject
}

// Filters returns the list of DENY net.IPNet masks
func (fs *Filters) Filters() []*net.IPNet {
	var out []*net.IPNet
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	for _, ff := range fs.filters {
		if ff.reject {
			out = append(out, ff.f)
		}
	}
	return out
}

// RejectFilters is a more semantically meaningful alias for Filters
func (fs *Filters) RejectFilters() []*net.IPNet {
	return fs.Filters()
}

// AllowFilters returns the list of ALLOW net.IPNet masks
func (fs *Filters) AllowFilters() []*net.IPNet {
	var out []*net.IPNet
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	for _, ff := range fs.filters {
		if !ff.reject {
			out = append(out, ff.f)
		}
	}
	return out
}
