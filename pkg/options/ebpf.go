package options

import "github.com/cilium/ebpf"

type Options struct {
	Specs             []func(*ebpf.CollectionSpec)
	Objs              []func(*ebpf.Collection)
	CollectionOptions []func(options *ebpf.CollectionOptions)
}
