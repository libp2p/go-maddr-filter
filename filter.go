package filter

import (
	"net"
	"sync"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

type FilterEntry struct {
	f      *net.IPNet
	reject bool
}

type Filters struct {
	mu            sync.RWMutex
	filterDefault bool
	filters       []*FilterEntry
}

func NewFilters() *Filters {
	return &Filters{
		filterDefault: false,
		filters:       make([]*FilterEntry, 0),
	}
}

func (fs *Filters) AddDialFilter(f *net.IPNet) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.filters = append(fs.filters, &FilterEntry{f: f, reject: true})
}

func (fs *Filters) AddAllowFilter(f *net.IPNet) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.filters = append(fs.filters, &FilterEntry{f: f, reject: false})
}

func (f *Filters) AddrBlocked(a ma.Multiaddr) bool {
	maddr := ma.Split(a)
	if len(maddr) == 0 {
		return false
	}
	netaddr, err := manet.ToNetAddr(maddr[0])
	if err != nil {
		// if we cant parse it, its probably not blocked
		return false
	}
	netip := net.ParseIP(netaddr.String())
	if netip == nil {
		return false
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	var reject bool = f.filterDefault

	for _, ft := range f.filters {
		if ft.f.Contains(netip) {
			reject = ft.reject
		}
	}

	return reject
}

func (f *Filters) Filters() []*net.IPNet {
	var out []*net.IPNet
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, ff := range f.filters {
		out = append(out, ff.f)
	}
	return out
}

func (f *Filters) Find(ff *net.IPNet) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	ffs := ff.String()

	for idx, ft := range f.filters {
		if ft.f.String() == ffs {
			return idx
		}
	}

	return -1
}

func (f *Filters) Remove(ff *net.IPNet) {
	f.mu.Lock()
	defer f.mu.Unlock()

	idx := f.Find(ff)
	if idx != -1 {
		f.filters = append(f.filters[:idx], f.filters[idx+1:]...)
	}
}
