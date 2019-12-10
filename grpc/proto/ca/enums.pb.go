// Code generated by protoc-gen-go. DO NOT EDIT.
// source: grpc/proto/ca/enums.proto

package ca

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type OrgType int32

const (
	OrgType_Order OrgType = 0
	OrgType_Peer  OrgType = 1
)

var OrgType_name = map[int32]string{
	0: "Order",
	1: "Peer",
}

var OrgType_value = map[string]int32{
	"Order": 0,
	"Peer":  1,
}

func (x OrgType) String() string {
	return proto.EnumName(OrgType_name, int32(x))
}

func (OrgType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_9961c52642bb6491, []int{0}
}

// CryptoType 密钥生成类型：ECDSA=0；RSA=1
type CryptoType int32

const (
	CryptoType_ECDSA CryptoType = 0
	CryptoType_RSA   CryptoType = 1
)

var CryptoType_name = map[int32]string{
	0: "ECDSA",
	1: "RSA",
}

var CryptoType_value = map[string]int32{
	"ECDSA": 0,
	"RSA":   1,
}

func (x CryptoType) String() string {
	return proto.EnumName(CryptoType_name, int32(x))
}

func (CryptoType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_9961c52642bb6491, []int{1}
}

// EccAlgorithm ECDSA密钥长度
type EccAlgorithm int32

const (
	EccAlgorithm_p256 EccAlgorithm = 0
	EccAlgorithm_p384 EccAlgorithm = 1
	EccAlgorithm_p521 EccAlgorithm = 2
)

var EccAlgorithm_name = map[int32]string{
	0: "p256",
	1: "p384",
	2: "p521",
}

var EccAlgorithm_value = map[string]int32{
	"p256": 0,
	"p384": 1,
	"p521": 2,
}

func (x EccAlgorithm) String() string {
	return proto.EnumName(EccAlgorithm_name, int32(x))
}

func (EccAlgorithm) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_9961c52642bb6491, []int{2}
}

// RsaAlgorithm RSA密钥长度
type RsaAlgorithm int32

const (
	RsaAlgorithm_r2048 RsaAlgorithm = 0
	RsaAlgorithm_r4096 RsaAlgorithm = 1
)

var RsaAlgorithm_name = map[int32]string{
	0: "r2048",
	1: "r4096",
}

var RsaAlgorithm_value = map[string]int32{
	"r2048": 0,
	"r4096": 1,
}

func (x RsaAlgorithm) String() string {
	return proto.EnumName(RsaAlgorithm_name, int32(x))
}

func (RsaAlgorithm) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_9961c52642bb6491, []int{3}
}

// SignAlgorithm 传输签名算法
type SignAlgorithm int32

const (
	SignAlgorithm_SHA256WithRSA   SignAlgorithm = 0
	SignAlgorithm_SHA512WithRSA   SignAlgorithm = 1
	SignAlgorithm_ECDSAWithSHA256 SignAlgorithm = 2
	SignAlgorithm_ECDSAWithSHA384 SignAlgorithm = 3
	SignAlgorithm_ECDSAWithSHA512 SignAlgorithm = 4
)

var SignAlgorithm_name = map[int32]string{
	0: "SHA256WithRSA",
	1: "SHA512WithRSA",
	2: "ECDSAWithSHA256",
	3: "ECDSAWithSHA384",
	4: "ECDSAWithSHA512",
}

var SignAlgorithm_value = map[string]int32{
	"SHA256WithRSA":   0,
	"SHA512WithRSA":   1,
	"ECDSAWithSHA256": 2,
	"ECDSAWithSHA384": 3,
	"ECDSAWithSHA512": 4,
}

func (x SignAlgorithm) String() string {
	return proto.EnumName(SignAlgorithm_name, int32(x))
}

func (SignAlgorithm) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_9961c52642bb6491, []int{4}
}

func init() {
	proto.RegisterEnum("ca.OrgType", OrgType_name, OrgType_value)
	proto.RegisterEnum("ca.CryptoType", CryptoType_name, CryptoType_value)
	proto.RegisterEnum("ca.EccAlgorithm", EccAlgorithm_name, EccAlgorithm_value)
	proto.RegisterEnum("ca.RsaAlgorithm", RsaAlgorithm_name, RsaAlgorithm_value)
	proto.RegisterEnum("ca.SignAlgorithm", SignAlgorithm_name, SignAlgorithm_value)
}

func init() { proto.RegisterFile("grpc/proto/ca/enums.proto", fileDescriptor_9961c52642bb6491) }

var fileDescriptor_9961c52642bb6491 = []byte{
	// 275 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x90, 0xc1, 0x4f, 0x83, 0x30,
	0x18, 0xc5, 0x81, 0x6d, 0xce, 0x7d, 0x19, 0xb1, 0xe2, 0xc9, 0x8b, 0xf1, 0xa0, 0x17, 0xa2, 0x30,
	0x3a, 0x20, 0xf3, 0x08, 0x93, 0xc4, 0xdb, 0x16, 0x30, 0x31, 0xf1, 0x56, 0x6a, 0x65, 0x4d, 0x36,
	0x68, 0xba, 0x7a, 0xd8, 0x7f, 0x6f, 0x5a, 0xb2, 0x2c, 0xdb, 0xed, 0x7d, 0xbf, 0xbc, 0x36, 0x2f,
	0x3f, 0xb8, 0x6f, 0xa4, 0xa0, 0xa1, 0x90, 0x9d, 0xea, 0x42, 0x4a, 0x42, 0xd6, 0xfe, 0xed, 0xf6,
	0x81, 0x39, 0x3d, 0x87, 0x12, 0xff, 0x01, 0xc6, 0x2b, 0xd9, 0x7c, 0x1e, 0x04, 0xf3, 0x26, 0x30,
	0x5a, 0xc9, 0x1f, 0x26, 0x91, 0xe5, 0x5d, 0xc3, 0x70, 0xcd, 0x98, 0x44, 0xb6, 0xff, 0x08, 0xb0,
	0x94, 0x07, 0xa1, 0xba, 0x63, 0xa5, 0x58, 0xbe, 0x57, 0x19, 0xb2, 0xbc, 0x31, 0x0c, 0xca, 0x2a,
	0x43, 0xb6, 0xff, 0x02, 0xd3, 0x82, 0xd2, 0x6c, 0xdb, 0x74, 0x92, 0xab, 0xcd, 0x4e, 0xbf, 0x15,
	0x38, 0x49, 0xfb, 0x5f, 0xc4, 0x7c, 0x11, 0x23, 0xdb, 0xa4, 0x04, 0x47, 0xc8, 0xf1, 0x9f, 0x60,
	0x5a, 0xee, 0xc9, 0xa9, 0x3d, 0x81, 0x91, 0xc4, 0xb3, 0x78, 0x81, 0x2c, 0x13, 0xe3, 0xd9, 0x5b,
	0x8a, 0x6c, 0x5f, 0x81, 0x5b, 0xf1, 0xa6, 0x3d, 0xd5, 0x6e, 0xc1, 0xad, 0x3e, 0x32, 0x9c, 0xa4,
	0x5f, 0x5c, 0x6d, 0x4a, 0x33, 0xa0, 0x47, 0x49, 0x84, 0x8f, 0xc8, 0xf6, 0xee, 0xe0, 0xc6, 0xcc,
	0xd3, 0xa4, 0xaf, 0x23, 0xe7, 0x12, 0xea, 0x41, 0x83, 0x4b, 0x98, 0x44, 0x18, 0x0d, 0xf3, 0x1c,
	0x9e, 0x69, 0x1b, 0x90, 0x9a, 0x49, 0x4e, 0x83, 0x5f, 0x52, 0x4b, 0x4e, 0x5f, 0xe9, 0x96, 0xb3,
	0x56, 0x05, 0x5a, 0x62, 0x6f, 0x2d, 0xa0, 0x24, 0x87, 0x42, 0x5b, 0x5c, 0xeb, 0xf3, 0xdb, 0x3d,
	0xf3, 0x5b, 0x5f, 0x99, 0x34, 0xff, 0x0f, 0x00, 0x00, 0xff, 0xff, 0x31, 0x10, 0x4a, 0x0a, 0x77,
	0x01, 0x00, 0x00,
}