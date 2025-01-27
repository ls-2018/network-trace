package nft

type Any interface {
	TypeName() string
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
	ReallyValue() interface{}
	Validate() error
}
