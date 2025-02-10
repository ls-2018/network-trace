package main

import (
	"context"
	_ "ebpf-nftrace/pkg/iptables"
	"ebpf-nftrace/pkg/nftables"
	"ebpf-nftrace/pkg/options"
	"ebpf-nftrace/pkg/tcp"
	"flag"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(errors.WithMessage(err, "failed to remove memory limit for process"))
	}
	//go iptables.Run(ctx)
	//go xdp.Run(ctx)

	//specChan := make(chan *ebpf.MapSpec)
	//mapChan := make(chan *ebpf.Map)

	go tcp.Run(ctx, options.Options{
		//Specs: []func(*ebpf.CollectionSpec){
		//	func(spec *ebpf.CollectionSpec) {
		//		specChan <- spec.Maps["sock_link_type"]
		//	},
		//},
		Objs: []func(*ebpf.Collection){
			//func(spec *ebpf.Collection) {
			//	mapChan <- spec.Maps["sock_link_type"]
			//},
		},
	})

	go nftables.Run(ctx, options.Options{
		Specs: []func(*ebpf.CollectionSpec){
			//func(spec *ebpf.CollectionSpec) {
			//	x := <-specChan
			//	spec.Maps["link_type_map"].InnerMap = x
			//},
		},
		CollectionOptions: []func(options *ebpf.CollectionOptions){
			//func(options *ebpf.CollectionOptions) {
			//	if options.MapReplacements == nil {
			//		options.MapReplacements = make(map[string]*ebpf.Map)
			//	}
			//	options.MapReplacements["sock_link_type"] = <-mapChan
			//},
		},
	})

	<-ctx.Done()
}
