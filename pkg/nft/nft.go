package nft

import (
	"context"
	"fmt"
	"sigs.k8s.io/knftables"
)

const (
	nfTraceTable = "Retis_Table"
	nfTraceChain = "Retis_Chain"
)

func Add() error {
	trace := []string{"meta", "nftrace", "set", "1"}

	nft, err := knftables.New(knftables.InetFamily, nfTraceTable)
	if err != nil && !knftables.IsNotFound(err) {
		return fmt.Errorf("no nftables support: %v", err)

	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{
		//Comment: ptr.To("table for nftrace"),
	})

	tx.Flush(&knftables.Table{})

	tx.Add(&knftables.Chain{
		Name: nfTraceChain,
		//Comment: knftables.PtrTo("nftrace chain"),
		//Type:     ptr.To(knftables.FilterType),
		//Hook:     ptr.To(knftables.PreroutingHook),
		//Priority: ptr.To(knftables.FilterPriority + "-10"),
	})
	tx.Flush(&knftables.Chain{
		Name: nfTraceChain,
	})

	tx.Add(&knftables.Rule{
		Chain: nfTraceChain,
		Rule:  knftables.Concat(trace),
	})

	return nft.Run(context.Background(), tx)
}

func Remove() error {
	nft, err := knftables.New(knftables.InetFamily, nfTraceTable)
	if err != nil {
		return fmt.Errorf("no nftables support: %v", err)
	}
	tx := nft.NewTransaction()
	tx.Delete(&knftables.Table{})
	return nft.Run(context.TODO(), tx)
}

// nft monitor trace
