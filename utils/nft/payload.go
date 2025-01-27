package nft

import "encoding/json"

type Protocol string

const (
	Ip     Protocol = "ip"
	Ip6    Protocol = "ip6"
	Inet   Protocol = "inet"
	Arp    Protocol = "arp"
	Bridge Protocol = "bridge"
	Netdev Protocol = "netdev"
)

type Payload struct {
	Protocol Protocol `json:"protocol"`
	Field    string   `json:"field"`
}

func (p *Payload) Validate() error {
	return nil
}

func (p *Payload) ReallyValue() interface{} {
	return map[string]interface{}{
		"protocol": p.Protocol,
		"field":    p.Field,
	}
}
func (p *Payload) TypeName() string {
	return "payload"
}
func (p *Payload) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ReallyValue())
}
func (p *Payload) UnmarshalJSON(data []byte) error {
	type InnerPayload *Payload
	if err := json.Unmarshal(data, InnerPayload(p)); err != nil {
		return err
	}
	return nil
}

var _ Any = &Payload{}
