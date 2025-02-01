package FlowGuard

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -type allowed_ip -type blocked_ip bpf ./bpf/blocker.c
