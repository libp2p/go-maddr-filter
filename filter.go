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
	mu              sync.RWMutex
	RejectByDefault bool
	filters         []*filterEntry
}

// NewFilters constructs and returns a new set of net.IPNet filters.
// By default, the new filter rejects no addresses.
func NewFilters() *Filters {
	return &Filters{
		RejectByDefault: false,
		filters:         make([]*filterEntry, 0),
	}
}

func (f *Filters) find(ff *net.IPNet) int {
	ffs := ff.String()
	for idx, ft := range f.filters {
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
func (f *Filters) Remove(ff *net.IPNet) {
	f.mu.Lock()
	defer f.mu.Unlock()

	idx := f.find(ff)
	if idx != -1 {
		f.filters = append(f.filters[:idx], f.filters[idx+1:]...)
	}
}

// AddrBlocked parses a ma.Multiaddr and, if it can get a valid netip
// back, applies the Filters returning true if the given address
// should be rejected, and false if the given address is allowed.
//
// If a parsing error occurs, or no filter matches, the Filters
// default is returned.
func (f *Filters) AddrBlocked(a ma.Multiaddr) bool {
	maddr := ma.Split(a)
	if len(maddr) == 0 {
		return f.RejectByDefault
	}
	netaddr, err := manet.ToNetAddr(maddr[0])
	if err != nil {
		// if we cant parse it, its probably not blocked
		return f.RejectByDefault
	}
	netip := net.ParseIP(netaddr.String())
	if netip == nil {
		return f.RejectByDefault
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	var reject bool = f.RejectByDefault

	for _, ft := range f.filters {
		if ft.f.Contains(netip) {
			reject = ft.reject
		}
	}

	return reject
}

// Filters returns the list of DENY net.IPNet masks
func (f *Filters) Filters() []*net.IPNet {
	var out []*net.IPNet
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, ff := range f.filters {
		if ff.reject {
			out = append(out, ff.f)
		}
	}
	return out
}

// AllowFilters returns the list of ALLOW net.IPNet masks
func (f *Filters) AllowFilters() []*net.IPNet {
	var out []*net.IPNet
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, ff := range f.filters {
		if !ff.reject {
			out = append(out, ff.f)
		}
	}
	return out
}
