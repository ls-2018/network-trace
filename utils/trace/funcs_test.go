package trace

import (
	"github.com/cilium/ebpf/btf"
	"testing"
)

func TestGetFuncs(t *testing.T) {

	f := func(params []btf.FuncParam) bool {
		if len(params) != 2 {
			return false
		}
		// static int generic_xdp_install(struct net_device *dev, struct netdev_bpf *xdp)
		if checkFuncParam(params[0], "net_device") && checkFuncParam(params[1], "netdev_bpf") {
			return true
		}
		return false
	}

	GetFuncs(f)
}
