package main

import (
	"context"
	_ "ebpf-nftrace/pkg/iptables"
	"ebpf-nftrace/pkg/nft"
	"ebpf-nftrace/pkg/nftables"
	"flag"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	flag.Parse()
	nft.Add()
	defer nft.Remove()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(errors.WithMessage(err, "failed to remove memory limit for process"))
	}
	go nftables.Run(ctx)
	//iptables.Run(ctx)

	<-ctx.Done()
}
