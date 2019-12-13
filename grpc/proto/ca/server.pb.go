// Code generated by protoc-gen-go. DO NOT EDIT.
// source: grpc/proto/ca/server.proto

package ca

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
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

func init() { proto.RegisterFile("grpc/proto/ca/server.proto", fileDescriptor_e7149eeb85e0e507) }

var fileDescriptor_e7149eeb85e0e507 = []byte{
	// 117 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x4a, 0x2f, 0x2a, 0x48,
	0xd6, 0x2f, 0x28, 0xca, 0x2f, 0xc9, 0xd7, 0x4f, 0x4e, 0xd4, 0x2f, 0x4e, 0x2d, 0x2a, 0x4b, 0x2d,
	0xd2, 0x03, 0xf3, 0x85, 0x98, 0x92, 0x13, 0x8d, 0xb8, 0xb8, 0x38, 0xdc, 0x53, 0xf3, 0x52, 0x8b,
	0x12, 0x4b, 0x52, 0x9d, 0x9c, 0xb9, 0x54, 0x93, 0xf3, 0xf4, 0x12, 0x93, 0x52, 0x8b, 0x32, 0x93,
	0xf5, 0xd2, 0x12, 0x93, 0x8a, 0x32, 0x93, 0x75, 0x93, 0x73, 0x32, 0x53, 0xf3, 0x4a, 0xf4, 0x40,
	0xa6, 0x40, 0x74, 0xe9, 0x25, 0x27, 0x3a, 0x71, 0x07, 0x83, 0x8d, 0x09, 0x00, 0xf1, 0xa3, 0x78,
	0x51, 0x6c, 0x48, 0x62, 0x03, 0xb3, 0x8c, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xc2, 0x2f, 0x96,
	0x44, 0x79, 0x00, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// GenerateClient is the client API for Generate service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type GenerateClient interface {
}

type generateClient struct {
	cc *grpc.ClientConn
}

func NewGenerateClient(cc *grpc.ClientConn) GenerateClient {
	return &generateClient{cc}
}

// GenerateServer is the server API for Generate service.
type GenerateServer interface {
}

func RegisterGenerateServer(s *grpc.Server, srv GenerateServer) {
	s.RegisterService(&_Generate_serviceDesc, srv)
}

var _Generate_serviceDesc = grpc.ServiceDesc{
	ServiceName: "ca.Generate",
	HandlerType: (*GenerateServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams:     []grpc.StreamDesc{},
	Metadata:    "grpc/proto/ca/server.proto",
}
