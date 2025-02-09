package dump

type Agent uint8

const (
	LinkRoleUnknown Agent = iota
	LinkRoleClient
	LinkRoleServer
)

func (a Agent) String() string {
	switch a {
	case LinkRoleUnknown:
		return "UNKNOWN"
	case LinkRoleClient:
		return "CLIENT"
	case LinkRoleServer:
		return "SERVER"
	default:
		return ""
	}
}
