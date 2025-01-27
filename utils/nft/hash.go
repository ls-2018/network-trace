package nft

import "golang.org/x/sys/unix"

type HashType uint32

const (
	HashTypeJenkins HashType = unix.NFT_HASH_JENKINS
	HashTypeSym     HashType = unix.NFT_HASH_SYM
)

type Hash struct {
	SourceRegister uint32
	DestRegister   uint32
	Length         uint32
	Modulus        uint32
	Seed           uint32
	Offset         uint32
	Type           HashType
}

//var _ Any = &Hash{}
