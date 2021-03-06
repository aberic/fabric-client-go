// Code generated by protoc-gen-go. DO NOT EDIT.
// source: grpc/proto/config/server.proto

package config

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

func init() { proto.RegisterFile("grpc/proto/config/server.proto", fileDescriptor_6ef6e8e359ab8613) }

var fileDescriptor_6ef6e8e359ab8613 = []byte{
	// 219 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x4b, 0x2f, 0x2a, 0x48,
	0xd6, 0x2f, 0x28, 0xca, 0x2f, 0xc9, 0xd7, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0x2f, 0x4e,
	0x2d, 0x2a, 0x4b, 0x2d, 0xd2, 0x03, 0x8b, 0x09, 0xb1, 0x41, 0x04, 0xa5, 0xb0, 0xa8, 0x83, 0x50,
	0x10, 0x75, 0x46, 0xbd, 0x4c, 0x5c, 0x6c, 0xce, 0x60, 0x01, 0x21, 0x2b, 0x2e, 0x4e, 0x08, 0x2b,
	0x38, 0xb5, 0x44, 0x48, 0x44, 0x0f, 0xaa, 0x2c, 0x28, 0xb5, 0x10, 0x2e, 0x2a, 0x25, 0x8a, 0x10,
	0x2d, 0x2e, 0x80, 0x0b, 0x2b, 0x31, 0x08, 0x39, 0x73, 0xf1, 0x40, 0xb8, 0xfe, 0x49, 0x25, 0x89,
	0x99, 0x79, 0x42, 0xe2, 0x18, 0xda, 0x21, 0x12, 0x52, 0x12, 0x98, 0x26, 0x40, 0x64, 0x94, 0x18,
	0x84, 0x6c, 0xb9, 0xb8, 0x20, 0x22, 0x3e, 0x99, 0xc5, 0x25, 0x42, 0xa2, 0x18, 0x46, 0x80, 0x84,
	0xa5, 0xc4, 0x30, 0x0d, 0x00, 0x89, 0x23, 0xbb, 0xc1, 0x25, 0x35, 0x27, 0xb5, 0x24, 0x15, 0x8b,
	0x1b, 0x20, 0x12, 0xd8, 0xdc, 0x00, 0x91, 0x51, 0x62, 0x70, 0xf2, 0xe6, 0xd2, 0x4c, 0xce, 0xd3,
	0x4b, 0x4c, 0x4a, 0x2d, 0xca, 0x4c, 0xd6, 0x4b, 0x4b, 0x4c, 0x2a, 0xca, 0x4c, 0xd6, 0x4d, 0xce,
	0xc9, 0x4c, 0xcd, 0x2b, 0xd1, 0x03, 0x85, 0x24, 0x24, 0xd4, 0xa0, 0xfa, 0x9d, 0xb8, 0x83, 0xc1,
	0x41, 0x1e, 0x00, 0x12, 0x8b, 0x12, 0xc4, 0x08, 0xe9, 0x24, 0x36, 0x30, 0xcf, 0x18, 0x10, 0x00,
	0x00, 0xff, 0xff, 0xca, 0xaf, 0xac, 0x4a, 0xad, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ConfigClient is the client API for Config service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ConfigClient interface {
	// 设置新的组织配置信息，用于访问fabric网络
	ConfigSet(ctx context.Context, in *ReqConfigSet, opts ...grpc.CallOption) (*RespConfigSet, error)
	// 获取组织配置信息详情
	ConfigObtain(ctx context.Context, in *ReqConfigObtain, opts ...grpc.CallOption) (*RespConfigObtain, error)
	// 列出已有组织信息集合
	ConfigList(ctx context.Context, in *ReqConfigList, opts ...grpc.CallOption) (*RespConfigList, error)
	// 删除指定组织配置信息
	ConfigDelete(ctx context.Context, in *ReqConfigDelete, opts ...grpc.CallOption) (*RespConfigDelete, error)
}

type configClient struct {
	cc *grpc.ClientConn
}

func NewConfigClient(cc *grpc.ClientConn) ConfigClient {
	return &configClient{cc}
}

func (c *configClient) ConfigSet(ctx context.Context, in *ReqConfigSet, opts ...grpc.CallOption) (*RespConfigSet, error) {
	out := new(RespConfigSet)
	err := c.cc.Invoke(ctx, "/config.Config/ConfigSet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *configClient) ConfigObtain(ctx context.Context, in *ReqConfigObtain, opts ...grpc.CallOption) (*RespConfigObtain, error) {
	out := new(RespConfigObtain)
	err := c.cc.Invoke(ctx, "/config.Config/ConfigObtain", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *configClient) ConfigList(ctx context.Context, in *ReqConfigList, opts ...grpc.CallOption) (*RespConfigList, error) {
	out := new(RespConfigList)
	err := c.cc.Invoke(ctx, "/config.Config/ConfigList", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *configClient) ConfigDelete(ctx context.Context, in *ReqConfigDelete, opts ...grpc.CallOption) (*RespConfigDelete, error) {
	out := new(RespConfigDelete)
	err := c.cc.Invoke(ctx, "/config.Config/ConfigDelete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConfigServer is the server API for Config service.
type ConfigServer interface {
	// 设置新的组织配置信息，用于访问fabric网络
	ConfigSet(context.Context, *ReqConfigSet) (*RespConfigSet, error)
	// 获取组织配置信息详情
	ConfigObtain(context.Context, *ReqConfigObtain) (*RespConfigObtain, error)
	// 列出已有组织信息集合
	ConfigList(context.Context, *ReqConfigList) (*RespConfigList, error)
	// 删除指定组织配置信息
	ConfigDelete(context.Context, *ReqConfigDelete) (*RespConfigDelete, error)
}

func RegisterConfigServer(s *grpc.Server, srv ConfigServer) {
	s.RegisterService(&_Config_serviceDesc, srv)
}

func _Config_ConfigSet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReqConfigSet)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigServer).ConfigSet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/config.Config/ConfigSet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigServer).ConfigSet(ctx, req.(*ReqConfigSet))
	}
	return interceptor(ctx, in, info, handler)
}

func _Config_ConfigObtain_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReqConfigObtain)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigServer).ConfigObtain(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/config.Config/ConfigObtain",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigServer).ConfigObtain(ctx, req.(*ReqConfigObtain))
	}
	return interceptor(ctx, in, info, handler)
}

func _Config_ConfigList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReqConfigList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigServer).ConfigList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/config.Config/ConfigList",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigServer).ConfigList(ctx, req.(*ReqConfigList))
	}
	return interceptor(ctx, in, info, handler)
}

func _Config_ConfigDelete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReqConfigDelete)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigServer).ConfigDelete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/config.Config/ConfigDelete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigServer).ConfigDelete(ctx, req.(*ReqConfigDelete))
	}
	return interceptor(ctx, in, info, handler)
}

var _Config_serviceDesc = grpc.ServiceDesc{
	ServiceName: "config.Config",
	HandlerType: (*ConfigServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ConfigSet",
			Handler:    _Config_ConfigSet_Handler,
		},
		{
			MethodName: "ConfigObtain",
			Handler:    _Config_ConfigObtain_Handler,
		},
		{
			MethodName: "ConfigList",
			Handler:    _Config_ConfigList_Handler,
		},
		{
			MethodName: "ConfigDelete",
			Handler:    _Config_ConfigDelete_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "grpc/proto/config/server.proto",
}
