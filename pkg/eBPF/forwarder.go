package eBPF

import (
	"FlowGuard/pkg/config"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Forwarder struct {
	coll            *ebpf.Collection
	egressLink      link.Link
	ingressLink     link.Link
	cfg             *config.Config
	stopChan        chan os.Signal
	srcLookupMap    *ebpf.Map
	forwardingRules *ebpf.Map
	connTrackMap    *ebpf.Map
}

func NewForwarder(cfg *config.Config) (*Forwarder, error) {
	// Убираем ограничения на память
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %v", err)
	}

	// Загружаем eBPF-объект
	collSpec, err := ebpf.LoadCollectionSpec("./build/forwader.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(collSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF collection: %v", err)
	}

	// Получаем программы
	egressProg := coll.Programs["forward_traffic_egress"]
	if egressProg == nil {
		return nil, fmt.Errorf("eBPF program 'forward_traffic_egress' not found")
	}
	ingressProg := coll.Programs["forward_traffic_ingress"]
	if ingressProg == nil {
		return nil, fmt.Errorf("eBPF program 'forward_traffic_ingress' not found")
	}

	// Получаем карты
	srcLookupMap := coll.Maps["src_lookup_map"]
	if srcLookupMap == nil {
		return nil, fmt.Errorf("eBPF map 'src_lookup_map' not found")
	}
	forwardingRules := coll.Maps["forwarding_rules"]
	if forwardingRules == nil {
		return nil, fmt.Errorf("eBPF map 'forwarding_rules' not found")
	}
	connTrackMap := coll.Maps["conn_track_map"]
	if connTrackMap == nil {
		return nil, fmt.Errorf("eBPF map 'conn_track_map' not found")
	}

	// Получаем интерфейс
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %v", cfg.Interface, err)
	}

	// Привязываем egress-программу
	egressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   egressProg,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach egress program to %s: %v", cfg.Interface, err)
	}

	// Привязываем ingress-программу
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   ingressProg,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		egressLink.Close()
		return nil, fmt.Errorf("failed to attach ingress program to %s: %v", cfg.Interface, err)
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	return &Forwarder{
		coll:            coll,
		egressLink:      egressLink,
		ingressLink:     ingressLink,
		cfg:             cfg,
		stopChan:        stopChan,
		srcLookupMap:    srcLookupMap,
		forwardingRules: forwardingRules,
		connTrackMap:    connTrackMap,
	}, nil
}

func (f *Forwarder) ServeTraffic() error {
	log.Println("Serving traffic...")

	// Заполняем карты из конфига (только forwarding, allow/deny пока не используются)
	for _, rule := range f.cfg.Forwarding {
		if err := f.addForwardingRule(rule); err != nil {
			log.Printf("Failed to add forwarding rule %+v: %v", rule, err)
		}
	}

	// Ждем сигнала остановки
	<-f.stopChan
	log.Println("Stopping ServeTraffic Forwarder...")
	return nil
}

func (f *Forwarder) Close() {
	log.Println("Closing eBPF forwarder...")

	if f.egressLink != nil {
		f.egressLink.Close()
	}
	if f.ingressLink != nil {
		f.ingressLink.Close()
	}
	if f.coll != nil {
		f.coll.Close()
	}

	log.Println("eBPF forwarder closed.")
}

// Вспомогательные структуры для работы с картами
type ipv4LPMKey struct {
	PrefixLen uint32
	Addr      uint32 // Big-endian
}

type forwardingKey struct {
	SrcIP   uint32 // 4 байта
	DstPort uint16 // 2 байта
	Padding uint16 // 2 байта для выравнивания до 8 байт
}

type forwardingRule struct {
	ForwardIP   uint32 // 4 байта
	ForwardPort uint16 // 2 байта
	Padding     uint16 // 2 байта для выравнивания до 8 байт
}

func (f *Forwarder) addForwardingRule(rule config.ForwardingRule) error {
	// Парсим IP и маску
	ip, ipNet, err := net.ParseCIDR(rule.SourceIP)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %v", rule.SourceIP, err)
	}
	prefixLen, _ := ipNet.Mask.Size()
	srcIP := IpToUint32(ip)

	// Парсим порты из строк
	dstPort, err := strconv.ParseUint(rule.DestinationPort, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid destination port %s: %v", rule.DestinationPort, err)
	}
	fwdPort, err := strconv.ParseUint(rule.ForwardPort, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid forward port %s: %v", rule.ForwardPort, err)
	}

	// Заполняем src_lookup_map
	lpmKey := ipv4LPMKey{
		PrefixLen: uint32(prefixLen),
		Addr:      srcIP,
	}
	value := uint32(1) // Флаг существования правила
	if err := f.srcLookupMap.Put(lpmKey, value); err != nil {
		return fmt.Errorf("failed to update src_lookup_map: %v", err)
	}

	// Заполняем forwarding_rules
	fwdKey := forwardingKey{
		SrcIP:   srcIP,
		DstPort: uint16(dstPort),
	}
	fwdIP := IpToUint32(net.ParseIP(rule.ForwardIP))
	if fwdIP == 0 {
		return fmt.Errorf("invalid forward IP %s", rule.ForwardIP)
	}
	fwdRule := forwardingRule{
		ForwardIP:   fwdIP,
		ForwardPort: uint16(fwdPort),
	}
	if err := f.forwardingRules.Put(fwdKey, fwdRule); err != nil {
		return fmt.Errorf("failed to update forwarding_rules: %v", err)
	}

	return nil
}
