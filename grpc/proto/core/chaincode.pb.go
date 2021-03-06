// Code generated by protoc-gen-go. DO NOT EDIT.
// source: grpc/proto/core/chaincode.proto

package core

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

type ChainCodeInfo struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Version              string   `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
	Path                 string   `protobuf:"bytes,3,opt,name=path,proto3" json:"path,omitempty"`
	Input                string   `protobuf:"bytes,4,opt,name=input,proto3" json:"input,omitempty"`
	Escc                 string   `protobuf:"bytes,5,opt,name=escc,proto3" json:"escc,omitempty"`
	Vscc                 string   `protobuf:"bytes,6,opt,name=vscc,proto3" json:"vscc,omitempty"`
	Id                   []byte   `protobuf:"bytes,7,opt,name=id,proto3" json:"id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ChainCodeInfo) Reset()         { *m = ChainCodeInfo{} }
func (m *ChainCodeInfo) String() string { return proto.CompactTextString(m) }
func (*ChainCodeInfo) ProtoMessage()    {}
func (*ChainCodeInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{0}
}

func (m *ChainCodeInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ChainCodeInfo.Unmarshal(m, b)
}
func (m *ChainCodeInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ChainCodeInfo.Marshal(b, m, deterministic)
}
func (m *ChainCodeInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ChainCodeInfo.Merge(m, src)
}
func (m *ChainCodeInfo) XXX_Size() int {
	return xxx_messageInfo_ChainCodeInfo.Size(m)
}
func (m *ChainCodeInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_ChainCodeInfo.DiscardUnknown(m)
}

var xxx_messageInfo_ChainCodeInfo proto.InternalMessageInfo

func (m *ChainCodeInfo) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ChainCodeInfo) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *ChainCodeInfo) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *ChainCodeInfo) GetInput() string {
	if m != nil {
		return m.Input
	}
	return ""
}

func (m *ChainCodeInfo) GetEscc() string {
	if m != nil {
		return m.Escc
	}
	return ""
}

func (m *ChainCodeInfo) GetVscc() string {
	if m != nil {
		return m.Vscc
	}
	return ""
}

func (m *ChainCodeInfo) GetId() []byte {
	if m != nil {
		return m.Id
	}
	return nil
}

type ReqChainCodeInstall struct {
	// 联盟根域名，如：example.com
	LeagueDomain string `protobuf:"bytes,1,opt,name=leagueDomain,proto3" json:"leagueDomain,omitempty"`
	// 组织域名，如org.com
	OrgDomain string `protobuf:"bytes,2,opt,name=orgDomain,proto3" json:"orgDomain,omitempty"`
	// 组织名称，如org0
	OrgName string `protobuf:"bytes,3,opt,name=orgName,proto3" json:"orgName,omitempty"`
	// 组织用户名称，如Admin
	OrgUser  string `protobuf:"bytes,4,opt,name=orgUser,proto3" json:"orgUser,omitempty"`
	PeerName string `protobuf:"bytes,5,opt,name=peerName,proto3" json:"peerName,omitempty"`
	// 链码名称
	CcName string `protobuf:"bytes,6,opt,name=ccName,proto3" json:"ccName,omitempty"`
	// 链码go环境目录
	GoPath string `protobuf:"bytes,7,opt,name=goPath,proto3" json:"goPath,omitempty"`
	// 链码合约路径
	CcPath string `protobuf:"bytes,8,opt,name=ccPath,proto3" json:"ccPath,omitempty"`
	// 链码名称
	Version              string   `protobuf:"bytes,9,opt,name=version,proto3" json:"version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ReqChainCodeInstall) Reset()         { *m = ReqChainCodeInstall{} }
func (m *ReqChainCodeInstall) String() string { return proto.CompactTextString(m) }
func (*ReqChainCodeInstall) ProtoMessage()    {}
func (*ReqChainCodeInstall) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{1}
}

func (m *ReqChainCodeInstall) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReqChainCodeInstall.Unmarshal(m, b)
}
func (m *ReqChainCodeInstall) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReqChainCodeInstall.Marshal(b, m, deterministic)
}
func (m *ReqChainCodeInstall) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReqChainCodeInstall.Merge(m, src)
}
func (m *ReqChainCodeInstall) XXX_Size() int {
	return xxx_messageInfo_ReqChainCodeInstall.Size(m)
}
func (m *ReqChainCodeInstall) XXX_DiscardUnknown() {
	xxx_messageInfo_ReqChainCodeInstall.DiscardUnknown(m)
}

var xxx_messageInfo_ReqChainCodeInstall proto.InternalMessageInfo

func (m *ReqChainCodeInstall) GetLeagueDomain() string {
	if m != nil {
		return m.LeagueDomain
	}
	return ""
}

func (m *ReqChainCodeInstall) GetOrgDomain() string {
	if m != nil {
		return m.OrgDomain
	}
	return ""
}

func (m *ReqChainCodeInstall) GetOrgName() string {
	if m != nil {
		return m.OrgName
	}
	return ""
}

func (m *ReqChainCodeInstall) GetOrgUser() string {
	if m != nil {
		return m.OrgUser
	}
	return ""
}

func (m *ReqChainCodeInstall) GetPeerName() string {
	if m != nil {
		return m.PeerName
	}
	return ""
}

func (m *ReqChainCodeInstall) GetCcName() string {
	if m != nil {
		return m.CcName
	}
	return ""
}

func (m *ReqChainCodeInstall) GetGoPath() string {
	if m != nil {
		return m.GoPath
	}
	return ""
}

func (m *ReqChainCodeInstall) GetCcPath() string {
	if m != nil {
		return m.CcPath
	}
	return ""
}

func (m *ReqChainCodeInstall) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

type RespChainCodeInstall struct {
	// 请求返回结果：success=0；fail=1
	Code Code `protobuf:"varint,1,opt,name=code,proto3,enum=core.Code" json:"code,omitempty"`
	// 当且仅当返回码为1时，此处包含错误信息
	ErrMsg               string       `protobuf:"bytes,2,opt,name=errMsg,proto3" json:"errMsg,omitempty"`
	Data                 *InstallData `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *RespChainCodeInstall) Reset()         { *m = RespChainCodeInstall{} }
func (m *RespChainCodeInstall) String() string { return proto.CompactTextString(m) }
func (*RespChainCodeInstall) ProtoMessage()    {}
func (*RespChainCodeInstall) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{2}
}

func (m *RespChainCodeInstall) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespChainCodeInstall.Unmarshal(m, b)
}
func (m *RespChainCodeInstall) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespChainCodeInstall.Marshal(b, m, deterministic)
}
func (m *RespChainCodeInstall) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespChainCodeInstall.Merge(m, src)
}
func (m *RespChainCodeInstall) XXX_Size() int {
	return xxx_messageInfo_RespChainCodeInstall.Size(m)
}
func (m *RespChainCodeInstall) XXX_DiscardUnknown() {
	xxx_messageInfo_RespChainCodeInstall.DiscardUnknown(m)
}

var xxx_messageInfo_RespChainCodeInstall proto.InternalMessageInfo

func (m *RespChainCodeInstall) GetCode() Code {
	if m != nil {
		return m.Code
	}
	return Code_Success
}

func (m *RespChainCodeInstall) GetErrMsg() string {
	if m != nil {
		return m.ErrMsg
	}
	return ""
}

func (m *RespChainCodeInstall) GetData() *InstallData {
	if m != nil {
		return m.Data
	}
	return nil
}

type InstallData struct {
	Target               string   `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"`
	Info                 string   `protobuf:"bytes,2,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *InstallData) Reset()         { *m = InstallData{} }
func (m *InstallData) String() string { return proto.CompactTextString(m) }
func (*InstallData) ProtoMessage()    {}
func (*InstallData) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{3}
}

func (m *InstallData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_InstallData.Unmarshal(m, b)
}
func (m *InstallData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_InstallData.Marshal(b, m, deterministic)
}
func (m *InstallData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_InstallData.Merge(m, src)
}
func (m *InstallData) XXX_Size() int {
	return xxx_messageInfo_InstallData.Size(m)
}
func (m *InstallData) XXX_DiscardUnknown() {
	xxx_messageInfo_InstallData.DiscardUnknown(m)
}

var xxx_messageInfo_InstallData proto.InternalMessageInfo

func (m *InstallData) GetTarget() string {
	if m != nil {
		return m.Target
	}
	return ""
}

func (m *InstallData) GetInfo() string {
	if m != nil {
		return m.Info
	}
	return ""
}

type ReqChainCodeInstantiate struct {
	// 联盟根域名，如：example.com
	LeagueDomain string `protobuf:"bytes,1,opt,name=leagueDomain,proto3" json:"leagueDomain,omitempty"`
	// 排序服务名称，如order0，可选
	OrdererName string `protobuf:"bytes,2,opt,name=ordererName,proto3" json:"ordererName,omitempty"`
	// 组织域名，如org.com
	OrgDomain string `protobuf:"bytes,3,opt,name=orgDomain,proto3" json:"orgDomain,omitempty"`
	// 组织名称，如org0
	OrgName string `protobuf:"bytes,4,opt,name=orgName,proto3" json:"orgName,omitempty"`
	// 组织用户名称，如Admin
	OrgUser string `protobuf:"bytes,5,opt,name=orgUser,proto3" json:"orgUser,omitempty"`
	// 节点名称，如peer0
	PeerName  string `protobuf:"bytes,6,opt,name=peerName,proto3" json:"peerName,omitempty"`
	ChannelID string `protobuf:"bytes,7,opt,name=channelID,proto3" json:"channelID,omitempty"`
	// 链码名称
	CcName string `protobuf:"bytes,8,opt,name=ccName,proto3" json:"ccName,omitempty"`
	// 链码合约路径
	CcPath string `protobuf:"bytes,9,opt,name=ccPath,proto3" json:"ccPath,omitempty"`
	// 链码名称
	Version              string   `protobuf:"bytes,10,opt,name=version,proto3" json:"version,omitempty"`
	OrgPolicies          []string `protobuf:"bytes,11,rep,name=orgPolicies,proto3" json:"orgPolicies,omitempty"`
	Args                 [][]byte `protobuf:"bytes,12,rep,name=args,proto3" json:"args,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ReqChainCodeInstantiate) Reset()         { *m = ReqChainCodeInstantiate{} }
func (m *ReqChainCodeInstantiate) String() string { return proto.CompactTextString(m) }
func (*ReqChainCodeInstantiate) ProtoMessage()    {}
func (*ReqChainCodeInstantiate) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{4}
}

func (m *ReqChainCodeInstantiate) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReqChainCodeInstantiate.Unmarshal(m, b)
}
func (m *ReqChainCodeInstantiate) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReqChainCodeInstantiate.Marshal(b, m, deterministic)
}
func (m *ReqChainCodeInstantiate) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReqChainCodeInstantiate.Merge(m, src)
}
func (m *ReqChainCodeInstantiate) XXX_Size() int {
	return xxx_messageInfo_ReqChainCodeInstantiate.Size(m)
}
func (m *ReqChainCodeInstantiate) XXX_DiscardUnknown() {
	xxx_messageInfo_ReqChainCodeInstantiate.DiscardUnknown(m)
}

var xxx_messageInfo_ReqChainCodeInstantiate proto.InternalMessageInfo

func (m *ReqChainCodeInstantiate) GetLeagueDomain() string {
	if m != nil {
		return m.LeagueDomain
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetOrdererName() string {
	if m != nil {
		return m.OrdererName
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetOrgDomain() string {
	if m != nil {
		return m.OrgDomain
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetOrgName() string {
	if m != nil {
		return m.OrgName
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetOrgUser() string {
	if m != nil {
		return m.OrgUser
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetPeerName() string {
	if m != nil {
		return m.PeerName
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetChannelID() string {
	if m != nil {
		return m.ChannelID
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetCcName() string {
	if m != nil {
		return m.CcName
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetCcPath() string {
	if m != nil {
		return m.CcPath
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *ReqChainCodeInstantiate) GetOrgPolicies() []string {
	if m != nil {
		return m.OrgPolicies
	}
	return nil
}

func (m *ReqChainCodeInstantiate) GetArgs() [][]byte {
	if m != nil {
		return m.Args
	}
	return nil
}

type RespChainCodeInstantiate struct {
	// 请求返回结果：success=0；fail=1
	Code Code `protobuf:"varint,1,opt,name=code,proto3,enum=core.Code" json:"code,omitempty"`
	// 当且仅当返回码为1时，此处包含错误信息
	ErrMsg               string   `protobuf:"bytes,2,opt,name=errMsg,proto3" json:"errMsg,omitempty"`
	TxId                 string   `protobuf:"bytes,3,opt,name=txId,proto3" json:"txId,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RespChainCodeInstantiate) Reset()         { *m = RespChainCodeInstantiate{} }
func (m *RespChainCodeInstantiate) String() string { return proto.CompactTextString(m) }
func (*RespChainCodeInstantiate) ProtoMessage()    {}
func (*RespChainCodeInstantiate) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{5}
}

func (m *RespChainCodeInstantiate) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespChainCodeInstantiate.Unmarshal(m, b)
}
func (m *RespChainCodeInstantiate) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespChainCodeInstantiate.Marshal(b, m, deterministic)
}
func (m *RespChainCodeInstantiate) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespChainCodeInstantiate.Merge(m, src)
}
func (m *RespChainCodeInstantiate) XXX_Size() int {
	return xxx_messageInfo_RespChainCodeInstantiate.Size(m)
}
func (m *RespChainCodeInstantiate) XXX_DiscardUnknown() {
	xxx_messageInfo_RespChainCodeInstantiate.DiscardUnknown(m)
}

var xxx_messageInfo_RespChainCodeInstantiate proto.InternalMessageInfo

func (m *RespChainCodeInstantiate) GetCode() Code {
	if m != nil {
		return m.Code
	}
	return Code_Success
}

func (m *RespChainCodeInstantiate) GetErrMsg() string {
	if m != nil {
		return m.ErrMsg
	}
	return ""
}

func (m *RespChainCodeInstantiate) GetTxId() string {
	if m != nil {
		return m.TxId
	}
	return ""
}

type ReqChainCodeUpgrade struct {
	// 联盟根域名，如：example.com
	LeagueDomain string `protobuf:"bytes,1,opt,name=leagueDomain,proto3" json:"leagueDomain,omitempty"`
	// 排序服务名称，如order0，可选
	OrdererName string `protobuf:"bytes,2,opt,name=ordererName,proto3" json:"ordererName,omitempty"`
	// 组织域名，如org.com
	OrgDomain string `protobuf:"bytes,3,opt,name=orgDomain,proto3" json:"orgDomain,omitempty"`
	// 组织名称，如org0
	OrgName string `protobuf:"bytes,4,opt,name=orgName,proto3" json:"orgName,omitempty"`
	// 组织用户名称，如Admin
	OrgUser   string `protobuf:"bytes,5,opt,name=orgUser,proto3" json:"orgUser,omitempty"`
	PeerName  string `protobuf:"bytes,6,opt,name=peerName,proto3" json:"peerName,omitempty"`
	ChannelID string `protobuf:"bytes,7,opt,name=channelID,proto3" json:"channelID,omitempty"`
	// 链码名称
	CcName string `protobuf:"bytes,8,opt,name=ccName,proto3" json:"ccName,omitempty"`
	// 链码合约路径
	CcPath string `protobuf:"bytes,9,opt,name=ccPath,proto3" json:"ccPath,omitempty"`
	// 链码名称
	Version              string   `protobuf:"bytes,10,opt,name=version,proto3" json:"version,omitempty"`
	OrgPolicies          []string `protobuf:"bytes,11,rep,name=orgPolicies,proto3" json:"orgPolicies,omitempty"`
	Args                 [][]byte `protobuf:"bytes,12,rep,name=args,proto3" json:"args,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ReqChainCodeUpgrade) Reset()         { *m = ReqChainCodeUpgrade{} }
func (m *ReqChainCodeUpgrade) String() string { return proto.CompactTextString(m) }
func (*ReqChainCodeUpgrade) ProtoMessage()    {}
func (*ReqChainCodeUpgrade) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{6}
}

func (m *ReqChainCodeUpgrade) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReqChainCodeUpgrade.Unmarshal(m, b)
}
func (m *ReqChainCodeUpgrade) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReqChainCodeUpgrade.Marshal(b, m, deterministic)
}
func (m *ReqChainCodeUpgrade) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReqChainCodeUpgrade.Merge(m, src)
}
func (m *ReqChainCodeUpgrade) XXX_Size() int {
	return xxx_messageInfo_ReqChainCodeUpgrade.Size(m)
}
func (m *ReqChainCodeUpgrade) XXX_DiscardUnknown() {
	xxx_messageInfo_ReqChainCodeUpgrade.DiscardUnknown(m)
}

var xxx_messageInfo_ReqChainCodeUpgrade proto.InternalMessageInfo

func (m *ReqChainCodeUpgrade) GetLeagueDomain() string {
	if m != nil {
		return m.LeagueDomain
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetOrdererName() string {
	if m != nil {
		return m.OrdererName
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetOrgDomain() string {
	if m != nil {
		return m.OrgDomain
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetOrgName() string {
	if m != nil {
		return m.OrgName
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetOrgUser() string {
	if m != nil {
		return m.OrgUser
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetPeerName() string {
	if m != nil {
		return m.PeerName
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetChannelID() string {
	if m != nil {
		return m.ChannelID
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetCcName() string {
	if m != nil {
		return m.CcName
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetCcPath() string {
	if m != nil {
		return m.CcPath
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *ReqChainCodeUpgrade) GetOrgPolicies() []string {
	if m != nil {
		return m.OrgPolicies
	}
	return nil
}

func (m *ReqChainCodeUpgrade) GetArgs() [][]byte {
	if m != nil {
		return m.Args
	}
	return nil
}

type RespChainCodeUpgrade struct {
	// 请求返回结果：success=0；fail=1
	Code Code `protobuf:"varint,1,opt,name=code,proto3,enum=core.Code" json:"code,omitempty"`
	// 当且仅当返回码为1时，此处包含错误信息
	ErrMsg               string   `protobuf:"bytes,2,opt,name=errMsg,proto3" json:"errMsg,omitempty"`
	TxId                 string   `protobuf:"bytes,3,opt,name=txId,proto3" json:"txId,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RespChainCodeUpgrade) Reset()         { *m = RespChainCodeUpgrade{} }
func (m *RespChainCodeUpgrade) String() string { return proto.CompactTextString(m) }
func (*RespChainCodeUpgrade) ProtoMessage()    {}
func (*RespChainCodeUpgrade) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{7}
}

func (m *RespChainCodeUpgrade) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespChainCodeUpgrade.Unmarshal(m, b)
}
func (m *RespChainCodeUpgrade) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespChainCodeUpgrade.Marshal(b, m, deterministic)
}
func (m *RespChainCodeUpgrade) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespChainCodeUpgrade.Merge(m, src)
}
func (m *RespChainCodeUpgrade) XXX_Size() int {
	return xxx_messageInfo_RespChainCodeUpgrade.Size(m)
}
func (m *RespChainCodeUpgrade) XXX_DiscardUnknown() {
	xxx_messageInfo_RespChainCodeUpgrade.DiscardUnknown(m)
}

var xxx_messageInfo_RespChainCodeUpgrade proto.InternalMessageInfo

func (m *RespChainCodeUpgrade) GetCode() Code {
	if m != nil {
		return m.Code
	}
	return Code_Success
}

func (m *RespChainCodeUpgrade) GetErrMsg() string {
	if m != nil {
		return m.ErrMsg
	}
	return ""
}

func (m *RespChainCodeUpgrade) GetTxId() string {
	if m != nil {
		return m.TxId
	}
	return ""
}

type ReqChainCodeInvoke struct {
	// 联盟根域名，如：example.com
	LeagueDomain string `protobuf:"bytes,1,opt,name=leagueDomain,proto3" json:"leagueDomain,omitempty"`
	// 组织域名，如org.com
	OrgDomain string `protobuf:"bytes,2,opt,name=orgDomain,proto3" json:"orgDomain,omitempty"`
	// 组织名称，如org0
	OrgName string `protobuf:"bytes,3,opt,name=orgName,proto3" json:"orgName,omitempty"`
	// 组织用户名称，如Admin
	OrgUser   string `protobuf:"bytes,4,opt,name=orgUser,proto3" json:"orgUser,omitempty"`
	PeerName  string `protobuf:"bytes,5,opt,name=peerName,proto3" json:"peerName,omitempty"`
	ChannelID string `protobuf:"bytes,6,opt,name=channelID,proto3" json:"channelID,omitempty"`
	// 链码名称
	CcName string `protobuf:"bytes,7,opt,name=ccName,proto3" json:"ccName,omitempty"`
	// 链码合约路径
	Fcn                  string   `protobuf:"bytes,8,opt,name=fcn,proto3" json:"fcn,omitempty"`
	Args                 [][]byte `protobuf:"bytes,11,rep,name=args,proto3" json:"args,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ReqChainCodeInvoke) Reset()         { *m = ReqChainCodeInvoke{} }
func (m *ReqChainCodeInvoke) String() string { return proto.CompactTextString(m) }
func (*ReqChainCodeInvoke) ProtoMessage()    {}
func (*ReqChainCodeInvoke) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{8}
}

func (m *ReqChainCodeInvoke) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReqChainCodeInvoke.Unmarshal(m, b)
}
func (m *ReqChainCodeInvoke) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReqChainCodeInvoke.Marshal(b, m, deterministic)
}
func (m *ReqChainCodeInvoke) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReqChainCodeInvoke.Merge(m, src)
}
func (m *ReqChainCodeInvoke) XXX_Size() int {
	return xxx_messageInfo_ReqChainCodeInvoke.Size(m)
}
func (m *ReqChainCodeInvoke) XXX_DiscardUnknown() {
	xxx_messageInfo_ReqChainCodeInvoke.DiscardUnknown(m)
}

var xxx_messageInfo_ReqChainCodeInvoke proto.InternalMessageInfo

func (m *ReqChainCodeInvoke) GetLeagueDomain() string {
	if m != nil {
		return m.LeagueDomain
	}
	return ""
}

func (m *ReqChainCodeInvoke) GetOrgDomain() string {
	if m != nil {
		return m.OrgDomain
	}
	return ""
}

func (m *ReqChainCodeInvoke) GetOrgName() string {
	if m != nil {
		return m.OrgName
	}
	return ""
}

func (m *ReqChainCodeInvoke) GetOrgUser() string {
	if m != nil {
		return m.OrgUser
	}
	return ""
}

func (m *ReqChainCodeInvoke) GetPeerName() string {
	if m != nil {
		return m.PeerName
	}
	return ""
}

func (m *ReqChainCodeInvoke) GetChannelID() string {
	if m != nil {
		return m.ChannelID
	}
	return ""
}

func (m *ReqChainCodeInvoke) GetCcName() string {
	if m != nil {
		return m.CcName
	}
	return ""
}

func (m *ReqChainCodeInvoke) GetFcn() string {
	if m != nil {
		return m.Fcn
	}
	return ""
}

func (m *ReqChainCodeInvoke) GetArgs() [][]byte {
	if m != nil {
		return m.Args
	}
	return nil
}

type RespChainCodeInvoke struct {
	// 请求返回结果：success=0；fail=1
	Code Code `protobuf:"varint,1,opt,name=code,proto3,enum=core.Code" json:"code,omitempty"`
	// 当且仅当返回码为1时，此处包含错误信息
	ErrMsg               string   `protobuf:"bytes,2,opt,name=errMsg,proto3" json:"errMsg,omitempty"`
	Data                 *CCData  `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RespChainCodeInvoke) Reset()         { *m = RespChainCodeInvoke{} }
func (m *RespChainCodeInvoke) String() string { return proto.CompactTextString(m) }
func (*RespChainCodeInvoke) ProtoMessage()    {}
func (*RespChainCodeInvoke) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{9}
}

func (m *RespChainCodeInvoke) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespChainCodeInvoke.Unmarshal(m, b)
}
func (m *RespChainCodeInvoke) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespChainCodeInvoke.Marshal(b, m, deterministic)
}
func (m *RespChainCodeInvoke) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespChainCodeInvoke.Merge(m, src)
}
func (m *RespChainCodeInvoke) XXX_Size() int {
	return xxx_messageInfo_RespChainCodeInvoke.Size(m)
}
func (m *RespChainCodeInvoke) XXX_DiscardUnknown() {
	xxx_messageInfo_RespChainCodeInvoke.DiscardUnknown(m)
}

var xxx_messageInfo_RespChainCodeInvoke proto.InternalMessageInfo

func (m *RespChainCodeInvoke) GetCode() Code {
	if m != nil {
		return m.Code
	}
	return Code_Success
}

func (m *RespChainCodeInvoke) GetErrMsg() string {
	if m != nil {
		return m.ErrMsg
	}
	return ""
}

func (m *RespChainCodeInvoke) GetData() *CCData {
	if m != nil {
		return m.Data
	}
	return nil
}

type ReqChainCodeQuery struct {
	// 联盟根域名，如：example.com
	LeagueDomain string `protobuf:"bytes,1,opt,name=leagueDomain,proto3" json:"leagueDomain,omitempty"`
	// 组织域名，如org.com
	OrgDomain string `protobuf:"bytes,2,opt,name=orgDomain,proto3" json:"orgDomain,omitempty"`
	// 组织名称，如org0
	OrgName string `protobuf:"bytes,3,opt,name=orgName,proto3" json:"orgName,omitempty"`
	// 组织用户名称，如Admin
	OrgUser   string `protobuf:"bytes,4,opt,name=orgUser,proto3" json:"orgUser,omitempty"`
	PeerName  string `protobuf:"bytes,5,opt,name=peerName,proto3" json:"peerName,omitempty"`
	ChannelID string `protobuf:"bytes,6,opt,name=channelID,proto3" json:"channelID,omitempty"`
	// 链码名称
	CcID string `protobuf:"bytes,7,opt,name=ccID,proto3" json:"ccID,omitempty"`
	// 链码执行方法名
	Fcn                  string   `protobuf:"bytes,8,opt,name=fcn,proto3" json:"fcn,omitempty"`
	Args                 [][]byte `protobuf:"bytes,11,rep,name=args,proto3" json:"args,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ReqChainCodeQuery) Reset()         { *m = ReqChainCodeQuery{} }
func (m *ReqChainCodeQuery) String() string { return proto.CompactTextString(m) }
func (*ReqChainCodeQuery) ProtoMessage()    {}
func (*ReqChainCodeQuery) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{10}
}

func (m *ReqChainCodeQuery) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReqChainCodeQuery.Unmarshal(m, b)
}
func (m *ReqChainCodeQuery) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReqChainCodeQuery.Marshal(b, m, deterministic)
}
func (m *ReqChainCodeQuery) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReqChainCodeQuery.Merge(m, src)
}
func (m *ReqChainCodeQuery) XXX_Size() int {
	return xxx_messageInfo_ReqChainCodeQuery.Size(m)
}
func (m *ReqChainCodeQuery) XXX_DiscardUnknown() {
	xxx_messageInfo_ReqChainCodeQuery.DiscardUnknown(m)
}

var xxx_messageInfo_ReqChainCodeQuery proto.InternalMessageInfo

func (m *ReqChainCodeQuery) GetLeagueDomain() string {
	if m != nil {
		return m.LeagueDomain
	}
	return ""
}

func (m *ReqChainCodeQuery) GetOrgDomain() string {
	if m != nil {
		return m.OrgDomain
	}
	return ""
}

func (m *ReqChainCodeQuery) GetOrgName() string {
	if m != nil {
		return m.OrgName
	}
	return ""
}

func (m *ReqChainCodeQuery) GetOrgUser() string {
	if m != nil {
		return m.OrgUser
	}
	return ""
}

func (m *ReqChainCodeQuery) GetPeerName() string {
	if m != nil {
		return m.PeerName
	}
	return ""
}

func (m *ReqChainCodeQuery) GetChannelID() string {
	if m != nil {
		return m.ChannelID
	}
	return ""
}

func (m *ReqChainCodeQuery) GetCcID() string {
	if m != nil {
		return m.CcID
	}
	return ""
}

func (m *ReqChainCodeQuery) GetFcn() string {
	if m != nil {
		return m.Fcn
	}
	return ""
}

func (m *ReqChainCodeQuery) GetArgs() [][]byte {
	if m != nil {
		return m.Args
	}
	return nil
}

type RespChainCodeQuery struct {
	// 请求返回结果：success=0；fail=1
	Code Code `protobuf:"varint,1,opt,name=code,proto3,enum=core.Code" json:"code,omitempty"`
	// 当且仅当返回码为1时，此处包含错误信息
	ErrMsg               string   `protobuf:"bytes,2,opt,name=errMsg,proto3" json:"errMsg,omitempty"`
	Data                 *CCData  `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RespChainCodeQuery) Reset()         { *m = RespChainCodeQuery{} }
func (m *RespChainCodeQuery) String() string { return proto.CompactTextString(m) }
func (*RespChainCodeQuery) ProtoMessage()    {}
func (*RespChainCodeQuery) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{11}
}

func (m *RespChainCodeQuery) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespChainCodeQuery.Unmarshal(m, b)
}
func (m *RespChainCodeQuery) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespChainCodeQuery.Marshal(b, m, deterministic)
}
func (m *RespChainCodeQuery) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespChainCodeQuery.Merge(m, src)
}
func (m *RespChainCodeQuery) XXX_Size() int {
	return xxx_messageInfo_RespChainCodeQuery.Size(m)
}
func (m *RespChainCodeQuery) XXX_DiscardUnknown() {
	xxx_messageInfo_RespChainCodeQuery.DiscardUnknown(m)
}

var xxx_messageInfo_RespChainCodeQuery proto.InternalMessageInfo

func (m *RespChainCodeQuery) GetCode() Code {
	if m != nil {
		return m.Code
	}
	return Code_Success
}

func (m *RespChainCodeQuery) GetErrMsg() string {
	if m != nil {
		return m.ErrMsg
	}
	return ""
}

func (m *RespChainCodeQuery) GetData() *CCData {
	if m != nil {
		return m.Data
	}
	return nil
}

type CCData struct {
	Payload              string   `protobuf:"bytes,1,opt,name=payload,proto3" json:"payload,omitempty"`
	TxId                 string   `protobuf:"bytes,2,opt,name=txId,proto3" json:"txId,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CCData) Reset()         { *m = CCData{} }
func (m *CCData) String() string { return proto.CompactTextString(m) }
func (*CCData) ProtoMessage()    {}
func (*CCData) Descriptor() ([]byte, []int) {
	return fileDescriptor_fcc74c0d4aae47df, []int{12}
}

func (m *CCData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CCData.Unmarshal(m, b)
}
func (m *CCData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CCData.Marshal(b, m, deterministic)
}
func (m *CCData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CCData.Merge(m, src)
}
func (m *CCData) XXX_Size() int {
	return xxx_messageInfo_CCData.Size(m)
}
func (m *CCData) XXX_DiscardUnknown() {
	xxx_messageInfo_CCData.DiscardUnknown(m)
}

var xxx_messageInfo_CCData proto.InternalMessageInfo

func (m *CCData) GetPayload() string {
	if m != nil {
		return m.Payload
	}
	return ""
}

func (m *CCData) GetTxId() string {
	if m != nil {
		return m.TxId
	}
	return ""
}

func init() {
	proto.RegisterType((*ChainCodeInfo)(nil), "core.ChainCodeInfo")
	proto.RegisterType((*ReqChainCodeInstall)(nil), "core.ReqChainCodeInstall")
	proto.RegisterType((*RespChainCodeInstall)(nil), "core.RespChainCodeInstall")
	proto.RegisterType((*InstallData)(nil), "core.InstallData")
	proto.RegisterType((*ReqChainCodeInstantiate)(nil), "core.ReqChainCodeInstantiate")
	proto.RegisterType((*RespChainCodeInstantiate)(nil), "core.RespChainCodeInstantiate")
	proto.RegisterType((*ReqChainCodeUpgrade)(nil), "core.ReqChainCodeUpgrade")
	proto.RegisterType((*RespChainCodeUpgrade)(nil), "core.RespChainCodeUpgrade")
	proto.RegisterType((*ReqChainCodeInvoke)(nil), "core.ReqChainCodeInvoke")
	proto.RegisterType((*RespChainCodeInvoke)(nil), "core.RespChainCodeInvoke")
	proto.RegisterType((*ReqChainCodeQuery)(nil), "core.ReqChainCodeQuery")
	proto.RegisterType((*RespChainCodeQuery)(nil), "core.RespChainCodeQuery")
	proto.RegisterType((*CCData)(nil), "core.CCData")
}

func init() { proto.RegisterFile("grpc/proto/core/chaincode.proto", fileDescriptor_fcc74c0d4aae47df) }

var fileDescriptor_fcc74c0d4aae47df = []byte{
	// 672 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xec, 0x56, 0x41, 0x6b, 0x14, 0x4d,
	0x10, 0x65, 0x67, 0x27, 0xbb, 0xd9, 0xda, 0xfd, 0xf2, 0x99, 0x36, 0xe8, 0x10, 0x83, 0x2e, 0x03,
	0x62, 0x2e, 0x6e, 0x20, 0x82, 0xe0, 0x35, 0xc9, 0x25, 0x82, 0x12, 0x07, 0x72, 0xf1, 0xd6, 0xdb,
	0x53, 0x3b, 0x69, 0x9c, 0x74, 0x8f, 0x3d, 0xb3, 0xc1, 0x5c, 0xbd, 0xf9, 0x2b, 0xfc, 0x79, 0x1e,
	0xfc, 0x0d, 0x82, 0x54, 0x77, 0xcf, 0x66, 0x66, 0xc3, 0x4a, 0x08, 0x11, 0x14, 0xbc, 0xd5, 0x7b,
	0x53, 0x3d, 0xdd, 0xf5, 0x5e, 0x55, 0xd3, 0xf0, 0x24, 0x33, 0x85, 0xd8, 0x2b, 0x8c, 0xae, 0xf4,
	0x9e, 0xd0, 0x06, 0xf7, 0xc4, 0x19, 0x97, 0x4a, 0xe8, 0x14, 0x27, 0x96, 0x64, 0x21, 0xb1, 0xdb,
	0x8f, 0x96, 0xd3, 0x50, 0xcd, 0xcf, 0x4b, 0x97, 0x12, 0x7f, 0xed, 0xc0, 0x7f, 0x87, 0xb4, 0xec,
	0x50, 0xa7, 0x78, 0xac, 0x66, 0x9a, 0x31, 0x08, 0x15, 0x3f, 0xc7, 0xa8, 0x33, 0xee, 0xec, 0x0e,
	0x12, 0x1b, 0xb3, 0x08, 0xfa, 0x17, 0x68, 0x4a, 0xa9, 0x55, 0x14, 0x58, 0xba, 0x86, 0x94, 0x5d,
	0xf0, 0xea, 0x2c, 0xea, 0xba, 0x6c, 0x8a, 0xd9, 0x16, 0xac, 0x49, 0x55, 0xcc, 0xab, 0x28, 0xb4,
	0xa4, 0x03, 0x94, 0x89, 0xa5, 0x10, 0xd1, 0x9a, 0xcb, 0xa4, 0x98, 0xb8, 0x0b, 0xe2, 0x7a, 0x8e,
	0xa3, 0x98, 0x6d, 0x40, 0x20, 0xd3, 0xa8, 0x3f, 0xee, 0xec, 0x8e, 0x92, 0x40, 0xa6, 0xf1, 0x97,
	0x00, 0xee, 0x27, 0xf8, 0xb1, 0x71, 0xc8, 0xb2, 0xe2, 0x79, 0xce, 0x62, 0x18, 0xe5, 0xc8, 0xb3,
	0x39, 0x1e, 0xe9, 0x73, 0x2e, 0x95, 0x3f, 0x6f, 0x8b, 0x63, 0x3b, 0x30, 0xd0, 0x26, 0xf3, 0x09,
	0xee, 0xe4, 0x57, 0x04, 0x55, 0xa5, 0x4d, 0xf6, 0x96, 0x8a, 0x75, 0xc7, 0xaf, 0xa1, 0xff, 0x72,
	0x5a, 0xa2, 0xf1, 0x35, 0xd4, 0x90, 0x6d, 0xc3, 0x7a, 0x81, 0x68, 0xec, 0x22, 0x57, 0xc9, 0x02,
	0xb3, 0x07, 0xd0, 0x13, 0xc2, 0x7e, 0x71, 0xf5, 0x78, 0x44, 0x7c, 0xa6, 0x4f, 0x48, 0xa5, 0xbe,
	0xe3, 0x1d, 0x72, 0xf9, 0x96, 0x5f, 0xaf, 0xf3, 0x2d, 0xdf, 0x50, 0x7b, 0xd0, 0x52, 0x3b, 0x9e,
	0xc3, 0x56, 0x82, 0x65, 0x71, 0x4d, 0x8b, 0xc7, 0x10, 0x92, 0xed, 0x56, 0x83, 0x8d, 0x7d, 0x98,
	0x90, 0xcd, 0x13, 0x4a, 0x48, 0x2c, 0x4f, 0x3b, 0xa1, 0x31, 0x6f, 0xca, 0xcc, 0x8b, 0xe0, 0x11,
	0x7b, 0x0a, 0x61, 0xca, 0x2b, 0x6e, 0xcb, 0x1f, 0xee, 0x6f, 0xba, 0x75, 0xfe, 0xa7, 0x47, 0xbc,
	0xe2, 0x89, 0xfd, 0x1c, 0xbf, 0x82, 0x61, 0x83, 0xa4, 0xbf, 0x55, 0xdc, 0x64, 0x58, 0x79, 0xcd,
	0x3d, 0x22, 0x37, 0xa5, 0x9a, 0x69, 0xbf, 0x87, 0x8d, 0xe3, 0xef, 0x01, 0x3c, 0xbc, 0xe6, 0x9e,
	0xaa, 0x24, 0xaf, 0xf0, 0x46, 0x0e, 0x8e, 0x61, 0xa8, 0x4d, 0x8a, 0xc6, 0x4b, 0xee, 0x7e, 0xdd,
	0xa4, 0xda, 0x1e, 0x77, 0x7f, 0xe1, 0x71, 0xb8, 0xd2, 0xe3, 0xb5, 0xd5, 0x1e, 0xf7, 0x96, 0x3c,
	0xde, 0x81, 0x81, 0x38, 0xe3, 0x4a, 0x61, 0x7e, 0x7c, 0xe4, 0xed, 0xbc, 0x22, 0x1a, 0x1d, 0xb0,
	0xbe, 0xdc, 0x01, 0xde, 0xe9, 0xc1, 0x2a, 0xa7, 0xa1, 0x3d, 0x57, 0xb6, 0xee, 0xec, 0x44, 0xe7,
	0x52, 0x48, 0x2c, 0xa3, 0xe1, 0xb8, 0xeb, 0xea, 0x5e, 0x50, 0xa4, 0x36, 0x37, 0x59, 0x19, 0x8d,
	0xc6, 0xdd, 0xdd, 0x51, 0x62, 0xe3, 0x78, 0x06, 0xd1, 0xf5, 0xfe, 0xf0, 0x6a, 0xdf, 0xb6, 0x47,
	0x18, 0x84, 0xd5, 0xa7, 0xe3, 0xb4, 0x9e, 0x70, 0x8a, 0xe3, 0x6f, 0x4b, 0x33, 0x79, 0x5a, 0x64,
	0x86, 0xa7, 0xff, 0x1c, 0xbd, 0x7b, 0x47, 0xa7, 0x4b, 0x13, 0x5f, 0x2b, 0x7d, 0x97, 0x6e, 0x7e,
	0x0e, 0x80, 0xb5, 0x67, 0xf4, 0x42, 0x7f, 0xc0, 0x3f, 0xf0, 0x82, 0x6d, 0x59, 0xd5, 0x5b, 0x6d,
	0x55, 0xbf, 0x65, 0xd5, 0x3d, 0xe8, 0xce, 0x84, 0xf2, 0xfe, 0x51, 0xb8, 0x10, 0x7a, 0xd8, 0x10,
	0x5a, 0x53, 0x47, 0xb7, 0x46, 0xc7, 0x8a, 0x70, 0x5b, 0x9d, 0xc7, 0xad, 0x9b, 0x75, 0xe4, 0xd7,
	0x1d, 0x36, 0x2e, 0xd5, 0x1f, 0x1d, 0xd8, 0x6c, 0xaa, 0xfe, 0x6e, 0x8e, 0xe6, 0xf2, 0xaf, 0x13,
	0x9d, 0x41, 0x28, 0xc4, 0x62, 0x70, 0x6c, 0x7c, 0x43, 0xc1, 0x15, 0x35, 0x5d, 0x43, 0x70, 0x57,
	0xff, 0xef, 0xd3, 0xfb, 0x25, 0xf4, 0x1c, 0x26, 0x1d, 0x0a, 0x7e, 0x99, 0x6b, 0x9e, 0x7a, 0x79,
	0x6b, 0xb8, 0x98, 0x8e, 0xe0, 0x6a, 0x3a, 0x0e, 0x5e, 0xc3, 0x33, 0xa1, 0x26, 0x7c, 0x8a, 0x46,
	0x8a, 0xc9, 0x8c, 0x4f, 0x8d, 0x14, 0xcf, 0x45, 0x2e, 0x51, 0x55, 0x13, 0x7a, 0x58, 0xb9, 0x77,
	0x94, 0xdd, 0xef, 0x60, 0x63, 0x51, 0xcc, 0x09, 0x91, 0xef, 0xff, 0x5f, 0x7a, 0x79, 0x4d, 0x7b,
	0x36, 0x7e, 0xf1, 0x33, 0x00, 0x00, 0xff, 0xff, 0x8c, 0x8e, 0x52, 0x0e, 0xba, 0x09, 0x00, 0x00,
}
