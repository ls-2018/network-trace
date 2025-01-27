package nft

import (
	"context"
	"ebpf-nftrace/utils/nft"
	"encoding/json"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"os/exec"
	"sync"
	"time"
)

var info = Info{
	lock: &sync.RWMutex{},
}

func Run(interval time.Duration, ctx context.Context) {
	ticker := time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-ticker.C:
				logic()
				ticker.Reset(interval)
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	<-ctx.Done()
}

func GetNftInfo(f func(_ Info)) {
	info.lock.RLock()
	defer info.lock.RUnlock()
	f(info)
}

type ChainInfo struct {
	*nft.Chain
	RulesHandle map[int]*nft.Rule
}

type TableInfo struct {
	*nft.Table
	Chains       map[string]ChainInfo
	ChainsHandle map[int]ChainInfo
}

type Info struct {
	tableNames sets.String
	Tables     map[string]*TableInfo
	lock       *sync.RWMutex
}

func (i *Info) Reset() {
	i.lock.Lock()
	defer i.lock.Unlock()
	i.tableNames = sets.NewString()
	i.Tables = make(map[string]*TableInfo)
}

func logic() {
	output, err := exec.Command("nft", "--json", "list").Output()
	if err != nil {
		klog.Error(err)
		return
	}
	var allRules nft.All
	err = json.Unmarshal(output, &allRules)
	if err != nil {
		klog.Error(err)
		return
	}
	info.Reset()
	for _, item := range allRules.Info {
		if item.Table != nil {
			info.tableNames.Insert(item.Table.Name)
			info.Tables[item.Table.Name] = &TableInfo{
				Table:        item.Table,
				Chains:       map[string]ChainInfo{},
				ChainsHandle: map[int]ChainInfo{},
			}
		}

		if item.Chain != nil {
			info.Tables[item.Chain.Table].Chains[item.Chain.Name] = ChainInfo{
				Chain: item.Chain,
			}
			info.Tables[item.Chain.Table].ChainsHandle[item.Chain.Handle] = ChainInfo{
				Chain: item.Chain,
			}
		}

		if item.Rule != nil {
			table := info.Tables[item.Rule.Table]
			chain := table.Chains[item.Chain.Name]
			if chain.RulesHandle == nil {
				chain.RulesHandle = map[int]*nft.Rule{}
			}
			chain.RulesHandle[item.Rule.Handle] = item.Rule
		}

	}

	return
}
