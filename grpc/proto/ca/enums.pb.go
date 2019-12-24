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
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Code int32

const (
	Code_Success Code = 0
	Code_Fail    Code = 1
)

var Code_name = map[int32]string{
	0: "Success",
	1: "Fail",
}

var Code_value = map[string]int32{
	"Success": 0,
	"Fail":    1,
}

func (x Code) String() string {
	return proto.EnumName(Code_name, int32(x))
}

func (Code) EnumDescriptor() ([]byte, []int) {
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
	proto.RegisterEnum("ca.Code", Code_name, Code_value)
	proto.RegisterEnum("ca.CryptoType", CryptoType_name, CryptoType_value)
	proto.RegisterEnum("ca.EccAlgorithm", EccAlgorithm_name, EccAlgorithm_value)
	proto.RegisterEnum("ca.RsaAlgorithm", RsaAlgorithm_name, RsaAlgorithm_value)
	proto.RegisterEnum("ca.SignAlgorithm", SignAlgorithm_name, SignAlgorithm_value)
}

func init() { proto.RegisterFile("grpc/proto/ca/enums.proto", fileDescriptor_9961c52642bb6491) }

var fileDescriptor_9961c52642bb6491 = []byte{
	// 279 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x90, 0xcf, 0x4b, 0xc3, 0x30,
	0x18, 0x86, 0xd7, 0xfd, 0x70, 0xee, 0x73, 0xc3, 0x18, 0x4f, 0x1e, 0x04, 0x0f, 0x7a, 0x29, 0xda,
	0x6d, 0xd9, 0x3a, 0xe6, 0xb1, 0xab, 0x15, 0x8f, 0xd2, 0x0a, 0x82, 0xb7, 0xf4, 0x33, 0x76, 0x81,
	0xae, 0x0d, 0x69, 0x76, 0xd8, 0x7f, 0x2f, 0x49, 0x91, 0xe1, 0x6e, 0xef, 0xf7, 0xf0, 0x26, 0xbc,
	0x3c, 0x70, 0x53, 0x68, 0x85, 0x53, 0xa5, 0x6b, 0x53, 0x4f, 0x91, 0x4f, 0x45, 0xb5, 0xdf, 0x35,
	0x81, 0x3b, 0x69, 0x17, 0xb9, 0x7f, 0x0b, 0xfd, 0xb8, 0xfe, 0x16, 0xf4, 0x02, 0x86, 0xd9, 0x1e,
	0x51, 0x34, 0x0d, 0xe9, 0xd0, 0x73, 0xe8, 0xbf, 0x72, 0x59, 0x12, 0xcf, 0xbf, 0x03, 0x88, 0xf5,
	0x41, 0x99, 0xfa, 0xe3, 0xa0, 0x04, 0x1d, 0xc1, 0x20, 0x89, 0x5f, 0xb2, 0x88, 0x74, 0xe8, 0x10,
	0x7a, 0x69, 0x16, 0x11, 0xcf, 0x7f, 0x84, 0x71, 0x82, 0x18, 0x95, 0x45, 0xad, 0xa5, 0xd9, 0xee,
	0xec, 0x5b, 0xc5, 0xc2, 0x55, 0xfb, 0x8b, 0x5a, 0xac, 0x97, 0xc4, 0x73, 0x29, 0x64, 0x73, 0xd2,
	0xf5, 0xef, 0x61, 0x9c, 0x36, 0xfc, 0xd8, 0x1e, 0xc1, 0x40, 0xb3, 0xd9, 0x72, 0x4d, 0x3a, 0x2e,
	0x2e, 0x67, 0xcf, 0x2b, 0xe2, 0xf9, 0x06, 0x26, 0x99, 0x2c, 0xaa, 0x63, 0xed, 0x0a, 0x26, 0xd9,
	0x5b, 0xc4, 0xc2, 0xd5, 0xa7, 0x34, 0xdb, 0xd4, 0x0d, 0x68, 0x51, 0x38, 0x67, 0x7f, 0xc8, 0xa3,
	0xd7, 0x70, 0xe9, 0xe6, 0x59, 0xd2, 0xd6, 0x49, 0xf7, 0x14, 0xda, 0x41, 0xbd, 0x53, 0x18, 0xce,
	0x19, 0xe9, 0x6f, 0x36, 0xf0, 0x80, 0x55, 0xc0, 0x73, 0xa1, 0x25, 0x06, 0x3f, 0x3c, 0xd7, 0x12,
	0x9f, 0xb0, 0x94, 0xa2, 0x32, 0x81, 0x75, 0xd8, 0x4a, 0x0b, 0x90, 0x6f, 0x20, 0xb1, 0x12, 0xdf,
	0xed, 0xf9, 0x35, 0xf9, 0xa7, 0x37, 0x3f, 0x73, 0x69, 0xf1, 0x1b, 0x00, 0x00, 0xff, 0xff, 0x3b,
	0x0d, 0xe6, 0x9d, 0x76, 0x01, 0x00, 0x00,
}
