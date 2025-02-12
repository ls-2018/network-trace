package a

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"hash/fnv"
	"strconv"
)

var (
	linksMetrics = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "caretta_links_observed",
		Help: "total bytes_sent value of links observed by caretta since its launch",
	}, []string{
		"link_id", "client_id", "client_name", "client_namespace", "client_kind", "server_id", "server_name", "server_namespace", "server_kind", "server_port", "role",
	})
)

// simple fnvHash function from string to uint32
func fnvHash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

type Workload struct {
	Name      string
	Namespace string
	Kind      string
}

type NetworkLink struct {
	Client     Workload
	Server     Workload
	ServerPort uint16
	Role       uint32
}

func main() {

	linksMetrics.With(prometheus.Labels{
		"link_id":          strconv.Itoa(int(fnvHash(link.Client.Name+link.Client.Namespace+link.Server.Name+link.Server.Namespace) + link.Role)),
		"client_id":        strconv.Itoa(int(fnvHash(link.Client.Name + link.Client.Namespace))),
		"client_name":      link.Client.Name,
		"client_namespace": link.Client.Namespace,
		"client_kind":      link.Client.Kind,
		"server_id":        strconv.Itoa(int(fnvHash(link.Server.Name + link.Server.Namespace))),
		"server_name":      link.Server.Name,
		"server_namespace": link.Server.Namespace,
		"server_kind":      link.Server.Kind,
		"server_port":      strconv.Itoa(int(link.ServerPort)),
		"role":             strconv.Itoa(int(link.Role)),
	}).Set(float64(throughput))
}
