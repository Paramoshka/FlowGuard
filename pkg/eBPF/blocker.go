package eBPF

import (
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"net"
	"sync"
)

// IPSet represents a thread-safe set of IPs
type IPSet struct {
	mu  sync.RWMutex
	ips map[string]struct{}
}

// NewIPSet creates a new instance of IPSet
func NewIPSet() *IPSet {
	return &IPSet{
		ips: make(map[string]struct{}),
	}
}

// Add adds an IP to the set
func (s *IPSet) Add(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ips[ip] = struct{}{}
}

// Remove removes an IP from the set
func (s *IPSet) Remove(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ips, ip)
}

// Contains checks if an IP is in the set
func (s *IPSet) Contains(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.ips[ip]
	return exists
}

// AllowDenyManager manages allow and deny lists for eBPF
type AllowDenyManager struct {
	AllowList *IPSet
	DenyList  *IPSet
	Map       *ebpf.Map
}

// NewAllowDenyManager creates a new AllowDenyManager
func NewAllowDenyManager(mapName string) (*AllowDenyManager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	m := ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    16, // Size for IPv6 address, also supports IPv4
		ValueSize:  1,
		MaxEntries: 1024,
	}

	bpfMap, err := ebpf.NewMap(&m)
	if err != nil {
		return nil, err
	}

	return &AllowDenyManager{
		AllowList: NewIPSet(),
		DenyList:  NewIPSet(),
		Map:       bpfMap,
	}, nil
}

// IsAllowed checks if an IP is allowed based on the allow and deny lists
func (m *AllowDenyManager) IsAllowed(ip string) (bool, error) {
	if m.DenyList.Contains(ip) {
		return false, nil
	}
	if m.AllowList.Contains(ip) {
		return true, nil
	}
	return false, errors.New("IP is not explicitly allowed or denied")
}

// AddToAllowList adds an IP to the allow list and updates the eBPF map
func (m *AllowDenyManager) AddToAllowList(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return errors.New("invalid IP address")
	}
	m.AllowList.Add(ip)
	return m.Map.Put(parsedIP.To16(), []byte{1})
}

// RemoveFromAllowList removes an IP from the allow list and updates the eBPF map
func (m *AllowDenyManager) RemoveFromAllowList(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return errors.New("invalid IP address")
	}
	m.AllowList.Remove(ip)
	return m.Map.Delete(parsedIP.To16())
}

// AddToDenyList adds an IP to the deny list and updates the eBPF map
func (m *AllowDenyManager) AddToDenyList(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return errors.New("invalid IP address")
	}
	m.DenyList.Add(ip)
	return m.Map.Put(parsedIP.To16(), []byte{0})
}

// RemoveFromDenyList removes an IP from the deny list and updates the eBPF map
func (m *AllowDenyManager) RemoveFromDenyList(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return errors.New("invalid IP address")
	}
	m.DenyList.Remove(ip)
	return m.Map.Delete(parsedIP.To16())
}
