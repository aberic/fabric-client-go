// Code generated by protoc-gen-go. DO NOT EDIT.
// source: grpc/proto/genesis/block.proto

package genesis

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

type ReqGenesisBlock struct {
	// fabric联盟基本信息
	League *League `protobuf:"bytes,1,opt,name=league,proto3" json:"league,omitempty"`
	// 联盟部署信息
	Orderer *Orderer `protobuf:"bytes,2,opt,name=orderer,proto3" json:"orderer,omitempty"`
	// 跟随创世区块一同创建的默认通道
	DefaultChannelID string `protobuf:"bytes,3,opt,name=defaultChannelID,proto3" json:"defaultChannelID,omitempty"`
	// 联盟下排序服务集合
	OrdererOrgs []*OrdererOrg `protobuf:"bytes,4,rep,name=ordererOrgs,proto3" json:"ordererOrgs,omitempty"`
	// 联盟下协会集合
	Consortiums          []*Consortium `protobuf:"bytes,5,rep,name=consortiums,proto3" json:"consortiums,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *ReqGenesisBlock) Reset()         { *m = ReqGenesisBlock{} }
func (m *ReqGenesisBlock) String() string { return proto.CompactTextString(m) }
func (*ReqGenesisBlock) ProtoMessage()    {}
func (*ReqGenesisBlock) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{0}
}

func (m *ReqGenesisBlock) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReqGenesisBlock.Unmarshal(m, b)
}
func (m *ReqGenesisBlock) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReqGenesisBlock.Marshal(b, m, deterministic)
}
func (m *ReqGenesisBlock) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReqGenesisBlock.Merge(m, src)
}
func (m *ReqGenesisBlock) XXX_Size() int {
	return xxx_messageInfo_ReqGenesisBlock.Size(m)
}
func (m *ReqGenesisBlock) XXX_DiscardUnknown() {
	xxx_messageInfo_ReqGenesisBlock.DiscardUnknown(m)
}

var xxx_messageInfo_ReqGenesisBlock proto.InternalMessageInfo

func (m *ReqGenesisBlock) GetLeague() *League {
	if m != nil {
		return m.League
	}
	return nil
}

func (m *ReqGenesisBlock) GetOrderer() *Orderer {
	if m != nil {
		return m.Orderer
	}
	return nil
}

func (m *ReqGenesisBlock) GetDefaultChannelID() string {
	if m != nil {
		return m.DefaultChannelID
	}
	return ""
}

func (m *ReqGenesisBlock) GetOrdererOrgs() []*OrdererOrg {
	if m != nil {
		return m.OrdererOrgs
	}
	return nil
}

func (m *ReqGenesisBlock) GetConsortiums() []*Consortium {
	if m != nil {
		return m.Consortiums
	}
	return nil
}

type RespGenesisBlock struct {
	// 请求返回结果：success=0；fail=1
	Code Code `protobuf:"varint,1,opt,name=code,proto3,enum=genesis.Code" json:"code,omitempty"`
	// 当且仅当返回码为1时，此处包含错误信息
	ErrMsg string `protobuf:"bytes,2,opt,name=errMsg,proto3" json:"errMsg,omitempty"`
	// 创世区块数据，解析使用InspectBlock即可
	BlockData            []byte   `protobuf:"bytes,3,opt,name=blockData,proto3" json:"blockData,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RespGenesisBlock) Reset()         { *m = RespGenesisBlock{} }
func (m *RespGenesisBlock) String() string { return proto.CompactTextString(m) }
func (*RespGenesisBlock) ProtoMessage()    {}
func (*RespGenesisBlock) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{1}
}

func (m *RespGenesisBlock) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespGenesisBlock.Unmarshal(m, b)
}
func (m *RespGenesisBlock) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespGenesisBlock.Marshal(b, m, deterministic)
}
func (m *RespGenesisBlock) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespGenesisBlock.Merge(m, src)
}
func (m *RespGenesisBlock) XXX_Size() int {
	return xxx_messageInfo_RespGenesisBlock.Size(m)
}
func (m *RespGenesisBlock) XXX_DiscardUnknown() {
	xxx_messageInfo_RespGenesisBlock.DiscardUnknown(m)
}

var xxx_messageInfo_RespGenesisBlock proto.InternalMessageInfo

func (m *RespGenesisBlock) GetCode() Code {
	if m != nil {
		return m.Code
	}
	return Code_Success
}

func (m *RespGenesisBlock) GetErrMsg() string {
	if m != nil {
		return m.ErrMsg
	}
	return ""
}

func (m *RespGenesisBlock) GetBlockData() []byte {
	if m != nil {
		return m.BlockData
	}
	return nil
}

type ReqChannelTx struct {
	// fabric联盟基本信息
	League *League `protobuf:"bytes,1,opt,name=league,proto3" json:"league,omitempty"`
	// 联盟下协会
	Consortium string `protobuf:"bytes,2,opt,name=consortium,proto3" json:"consortium,omitempty"`
	// 联盟下通道
	ChannelID string `protobuf:"bytes,3,opt,name=channelID,proto3" json:"channelID,omitempty"`
	// 联盟下非orderer组织集合
	PeerOrgs             []*PeerOrg `protobuf:"bytes,4,rep,name=peerOrgs,proto3" json:"peerOrgs,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *ReqChannelTx) Reset()         { *m = ReqChannelTx{} }
func (m *ReqChannelTx) String() string { return proto.CompactTextString(m) }
func (*ReqChannelTx) ProtoMessage()    {}
func (*ReqChannelTx) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{2}
}

func (m *ReqChannelTx) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReqChannelTx.Unmarshal(m, b)
}
func (m *ReqChannelTx) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReqChannelTx.Marshal(b, m, deterministic)
}
func (m *ReqChannelTx) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReqChannelTx.Merge(m, src)
}
func (m *ReqChannelTx) XXX_Size() int {
	return xxx_messageInfo_ReqChannelTx.Size(m)
}
func (m *ReqChannelTx) XXX_DiscardUnknown() {
	xxx_messageInfo_ReqChannelTx.DiscardUnknown(m)
}

var xxx_messageInfo_ReqChannelTx proto.InternalMessageInfo

func (m *ReqChannelTx) GetLeague() *League {
	if m != nil {
		return m.League
	}
	return nil
}

func (m *ReqChannelTx) GetConsortium() string {
	if m != nil {
		return m.Consortium
	}
	return ""
}

func (m *ReqChannelTx) GetChannelID() string {
	if m != nil {
		return m.ChannelID
	}
	return ""
}

func (m *ReqChannelTx) GetPeerOrgs() []*PeerOrg {
	if m != nil {
		return m.PeerOrgs
	}
	return nil
}

type RespChannelTx struct {
	// 请求返回结果：success=0；fail=1
	Code Code `protobuf:"varint,1,opt,name=code,proto3,enum=genesis.Code" json:"code,omitempty"`
	// 当且仅当返回码为1时，此处包含错误信息
	ErrMsg string `protobuf:"bytes,2,opt,name=errMsg,proto3" json:"errMsg,omitempty"`
	// 通道区块数据，解析使用InspectChannelCreateTx即可
	ChannelTxData        []byte   `protobuf:"bytes,3,opt,name=channelTxData,proto3" json:"channelTxData,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RespChannelTx) Reset()         { *m = RespChannelTx{} }
func (m *RespChannelTx) String() string { return proto.CompactTextString(m) }
func (*RespChannelTx) ProtoMessage()    {}
func (*RespChannelTx) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{3}
}

func (m *RespChannelTx) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespChannelTx.Unmarshal(m, b)
}
func (m *RespChannelTx) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespChannelTx.Marshal(b, m, deterministic)
}
func (m *RespChannelTx) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespChannelTx.Merge(m, src)
}
func (m *RespChannelTx) XXX_Size() int {
	return xxx_messageInfo_RespChannelTx.Size(m)
}
func (m *RespChannelTx) XXX_DiscardUnknown() {
	xxx_messageInfo_RespChannelTx.DiscardUnknown(m)
}

var xxx_messageInfo_RespChannelTx proto.InternalMessageInfo

func (m *RespChannelTx) GetCode() Code {
	if m != nil {
		return m.Code
	}
	return Code_Success
}

func (m *RespChannelTx) GetErrMsg() string {
	if m != nil {
		return m.ErrMsg
	}
	return ""
}

func (m *RespChannelTx) GetChannelTxData() []byte {
	if m != nil {
		return m.ChannelTxData
	}
	return nil
}

// fabric联盟基本信息
type League struct {
	// 联盟根域名
	Domain string `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	// fabric版本号
	Version              Version  `protobuf:"varint,2,opt,name=version,proto3,enum=genesis.Version" json:"version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *League) Reset()         { *m = League{} }
func (m *League) String() string { return proto.CompactTextString(m) }
func (*League) ProtoMessage()    {}
func (*League) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{4}
}

func (m *League) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_League.Unmarshal(m, b)
}
func (m *League) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_League.Marshal(b, m, deterministic)
}
func (m *League) XXX_Merge(src proto.Message) {
	xxx_messageInfo_League.Merge(m, src)
}
func (m *League) XXX_Size() int {
	return xxx_messageInfo_League.Size(m)
}
func (m *League) XXX_DiscardUnknown() {
	xxx_messageInfo_League.DiscardUnknown(m)
}

var xxx_messageInfo_League proto.InternalMessageInfo

func (m *League) GetDomain() string {
	if m != nil {
		return m.Domain
	}
	return ""
}

func (m *League) GetVersion() Version {
	if m != nil {
		return m.Version
	}
	return Version_V1_4_4
}

// Consortium 暂定翻译成协会
//
// 协会是区块链网络上的除了orderer组织以外的组织集合。
//
// 这些组织形成一个协会，协会内组织拥有自己的节点并能够加入相同通道。
//
// 虽然一个区块链网络可以有多个协会，但大多数区块链网络只有一个协会。
//
// 在通道创建时，添加到通道的所有组织都必须是协会的一部分。但是，没有在协会中定义的组织可以添加到现有的通道中。
type Consortium struct {
	// consortium名称
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// 联盟下非orderer组织集合
	PeerOrgs             []*PeerOrg `protobuf:"bytes,2,rep,name=peerOrgs,proto3" json:"peerOrgs,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *Consortium) Reset()         { *m = Consortium{} }
func (m *Consortium) String() string { return proto.CompactTextString(m) }
func (*Consortium) ProtoMessage()    {}
func (*Consortium) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{5}
}

func (m *Consortium) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Consortium.Unmarshal(m, b)
}
func (m *Consortium) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Consortium.Marshal(b, m, deterministic)
}
func (m *Consortium) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Consortium.Merge(m, src)
}
func (m *Consortium) XXX_Size() int {
	return xxx_messageInfo_Consortium.Size(m)
}
func (m *Consortium) XXX_DiscardUnknown() {
	xxx_messageInfo_Consortium.DiscardUnknown(m)
}

var xxx_messageInfo_Consortium proto.InternalMessageInfo

func (m *Consortium) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Consortium) GetPeerOrgs() []*PeerOrg {
	if m != nil {
		return m.PeerOrgs
	}
	return nil
}

// 联盟部署信息
type Orderer struct {
	// 地址过去是client和peer可以连接的orderer地址列表
	//
	// 但是，这并不允许client关联orderer地址和orderer组织，这对于诸如TLS验证之类的事情是非常有用的
	//
	// 指定orderer地址的首选方法是现在在您的org定义中包含ordererendpoint项
	Addresses []string `protobuf:"bytes,3,rep,name=addresses,proto3" json:"addresses,omitempty"`
	// 批处理超时:创建批处理之前等待的时间量
	BatchTimeout int64 `protobuf:"varint,4,opt,name=BatchTimeout,proto3" json:"BatchTimeout,omitempty"`
	// 批处理大小:控制成批处理到一个块中的消息的数量
	BatchSize *BatchSize `protobuf:"bytes,5,opt,name=batchSize,proto3" json:"batchSize,omitempty"`
	// EtcdRaft定义了在选择“EtcdRaft”orderertype时必须设置的配置
	EtcdRaft *EtcdRaft `protobuf:"bytes,6,opt,name=etcdRaft,proto3" json:"etcdRaft,omitempty"`
	// 最大通道是orderer网络上允许的最大通道数。当设置为0时，这意味着没有最大通道数
	MaxChannels          uint64   `protobuf:"varint,7,opt,name=MaxChannels,proto3" json:"MaxChannels,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Orderer) Reset()         { *m = Orderer{} }
func (m *Orderer) String() string { return proto.CompactTextString(m) }
func (*Orderer) ProtoMessage()    {}
func (*Orderer) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{6}
}

func (m *Orderer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Orderer.Unmarshal(m, b)
}
func (m *Orderer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Orderer.Marshal(b, m, deterministic)
}
func (m *Orderer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Orderer.Merge(m, src)
}
func (m *Orderer) XXX_Size() int {
	return xxx_messageInfo_Orderer.Size(m)
}
func (m *Orderer) XXX_DiscardUnknown() {
	xxx_messageInfo_Orderer.DiscardUnknown(m)
}

var xxx_messageInfo_Orderer proto.InternalMessageInfo

func (m *Orderer) GetAddresses() []string {
	if m != nil {
		return m.Addresses
	}
	return nil
}

func (m *Orderer) GetBatchTimeout() int64 {
	if m != nil {
		return m.BatchTimeout
	}
	return 0
}

func (m *Orderer) GetBatchSize() *BatchSize {
	if m != nil {
		return m.BatchSize
	}
	return nil
}

func (m *Orderer) GetEtcdRaft() *EtcdRaft {
	if m != nil {
		return m.EtcdRaft
	}
	return nil
}

func (m *Orderer) GetMaxChannels() uint64 {
	if m != nil {
		return m.MaxChannels
	}
	return 0
}

// 批处理大小:控制成批处理到一个块中的消息的数量
//
// orderer不透明地查看消息，但是通常，消息可能被认为是Fabric事务
//
// “批处理”是块的“数据”字段中的一组消息。当应用签名、散列和其他元数据时，块将比批处理大小大几kb
type BatchSize struct {
	// 最大消息数:批处理中允许的最大消息数。没有一个块包含超过这个数量的消息
	MaxMessageCount uint32 `protobuf:"varint,1,opt,name=maxMessageCount,proto3" json:"maxMessageCount,omitempty"`
	// 绝对最大字节数:批处理中允许的序列化消息的绝对最大字节数
	//
	// 最大块大小是这个值加上相关元数据的大小(通常是几个KB，这取决于签名标识的大小)
	//
	// 任何大于此值的事务将被orderer拒绝
	//
	// 如果选择了“kafka”OrdererType，则设置“message.max”。字节数”和“replica.fetch.max。在Kafka代理上设置一个比这个更大的值
	AbsoluteMaxBytes uint32 `protobuf:"varint,2,opt,name=absoluteMaxBytes,proto3" json:"absoluteMaxBytes,omitempty"`
	// 首选最大字节:批处理中序列化消息所允许的首选最大字节数
	//
	// 大致上，这个字段可以被认为是批处理的最大努力
	//
	// 批处理将填充消息，直到达到这个大小(或超过最大消息数，或超过批处理超时)
	//
	// 如果向批处理添加新消息会导致批处理超过首选的最大字节，那么将关闭当前批处理并将其写入一个块，并创建一个包含新消息的新批处理
	//
	// 如果接收到的消息大于首选的最大字节，则其批处理将仅包含该消息
	//
	// 因为消息可能大于首选的最大字节(直到AbsoluteMaxBytes)，所以某些批可能超过首选的最大字节，但始终只包含一个事务
	PreferredMaxBytes    uint32   `protobuf:"varint,3,opt,name=preferredMaxBytes,proto3" json:"preferredMaxBytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BatchSize) Reset()         { *m = BatchSize{} }
func (m *BatchSize) String() string { return proto.CompactTextString(m) }
func (*BatchSize) ProtoMessage()    {}
func (*BatchSize) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{7}
}

func (m *BatchSize) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BatchSize.Unmarshal(m, b)
}
func (m *BatchSize) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BatchSize.Marshal(b, m, deterministic)
}
func (m *BatchSize) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BatchSize.Merge(m, src)
}
func (m *BatchSize) XXX_Size() int {
	return xxx_messageInfo_BatchSize.Size(m)
}
func (m *BatchSize) XXX_DiscardUnknown() {
	xxx_messageInfo_BatchSize.DiscardUnknown(m)
}

var xxx_messageInfo_BatchSize proto.InternalMessageInfo

func (m *BatchSize) GetMaxMessageCount() uint32 {
	if m != nil {
		return m.MaxMessageCount
	}
	return 0
}

func (m *BatchSize) GetAbsoluteMaxBytes() uint32 {
	if m != nil {
		return m.AbsoluteMaxBytes
	}
	return 0
}

func (m *BatchSize) GetPreferredMaxBytes() uint32 {
	if m != nil {
		return m.PreferredMaxBytes
	}
	return 0
}

// EtcdRaft定义了在选择“EtcdRaft”orderertype时必须设置的配置
type EtcdRaft struct {
	// 这个网络的一组raft副本
	//
	// 对于基于etcd/raft的实现，fabric网络中每个副本都是一个OSN
	//
	// 因此，此列表中枚举的host:port项的一个子集应该在Orderer.Addresses下复制
	Consenters []*Consenter `protobuf:"bytes,1,rep,name=consenters,proto3" json:"consenters,omitempty"`
	// 为所有etcd/raft节点指定的选项。这里的值是所有新通道的默认值，可以通过配置更新对每个通道进行修改
	Options              *Options `protobuf:"bytes,2,opt,name=options,proto3" json:"options,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EtcdRaft) Reset()         { *m = EtcdRaft{} }
func (m *EtcdRaft) String() string { return proto.CompactTextString(m) }
func (*EtcdRaft) ProtoMessage()    {}
func (*EtcdRaft) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{8}
}

func (m *EtcdRaft) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EtcdRaft.Unmarshal(m, b)
}
func (m *EtcdRaft) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EtcdRaft.Marshal(b, m, deterministic)
}
func (m *EtcdRaft) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EtcdRaft.Merge(m, src)
}
func (m *EtcdRaft) XXX_Size() int {
	return xxx_messageInfo_EtcdRaft.Size(m)
}
func (m *EtcdRaft) XXX_DiscardUnknown() {
	xxx_messageInfo_EtcdRaft.DiscardUnknown(m)
}

var xxx_messageInfo_EtcdRaft proto.InternalMessageInfo

func (m *EtcdRaft) GetConsenters() []*Consenter {
	if m != nil {
		return m.Consenters
	}
	return nil
}

func (m *EtcdRaft) GetOptions() *Options {
	if m != nil {
		return m.Options
	}
	return nil
}

// fabric网络中基于raft的orderer单个节点信息
type Consenter struct {
	Host                 string   `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Port                 uint32   `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	ClientTlsCert        []byte   `protobuf:"bytes,3,opt,name=clientTlsCert,proto3" json:"clientTlsCert,omitempty"`
	ServerTlsCert        []byte   `protobuf:"bytes,4,opt,name=serverTlsCert,proto3" json:"serverTlsCert,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Consenter) Reset()         { *m = Consenter{} }
func (m *Consenter) String() string { return proto.CompactTextString(m) }
func (*Consenter) ProtoMessage()    {}
func (*Consenter) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{9}
}

func (m *Consenter) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Consenter.Unmarshal(m, b)
}
func (m *Consenter) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Consenter.Marshal(b, m, deterministic)
}
func (m *Consenter) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Consenter.Merge(m, src)
}
func (m *Consenter) XXX_Size() int {
	return xxx_messageInfo_Consenter.Size(m)
}
func (m *Consenter) XXX_DiscardUnknown() {
	xxx_messageInfo_Consenter.DiscardUnknown(m)
}

var xxx_messageInfo_Consenter proto.InternalMessageInfo

func (m *Consenter) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func (m *Consenter) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *Consenter) GetClientTlsCert() []byte {
	if m != nil {
		return m.ClientTlsCert
	}
	return nil
}

func (m *Consenter) GetServerTlsCert() []byte {
	if m != nil {
		return m.ServerTlsCert
	}
	return nil
}

// 为所有etcd/raft节点指定的选项。这里的值是所有新通道的默认值，可以通过配置更新对每个通道进行修改
type Options struct {
	// TickInterval是两个节点之间的时间间隔
	TickInterval string `protobuf:"bytes,1,opt,name=TickInterval,proto3" json:"TickInterval,omitempty"`
	// ElectionTick是节点的数量
	//
	// 在两次选举之间必须通过的调用。也就是说，如果一个追随者在选举结束前没有收到任何现任领导人的信息，他将成为候选人并开始选举
	//
	// 选举的节奏必须比心跳的节奏快
	ElectionTick uint32 `protobuf:"varint,2,opt,name=ElectionTick,proto3" json:"ElectionTick,omitempty"`
	// 心跳次数是心跳之间必须传递的节点次数。也就是说，领导者在每一次心跳时都发送心跳信息以保持其领导力
	HeartbeatTick uint32 `protobuf:"varint,3,opt,name=HeartbeatTick,proto3" json:"HeartbeatTick,omitempty"`
	// MaxInflightBlocks在乐观复制阶段限制动态附加消息的最大数量
	MaxInflightBlocks uint32 `protobuf:"varint,4,opt,name=MaxInflightBlocks,proto3" json:"MaxInflightBlocks,omitempty"`
	// SnapshotIntervalSize定义每个快照的字节数
	SnapshotIntervalSize uint32   `protobuf:"varint,5,opt,name=SnapshotIntervalSize,proto3" json:"SnapshotIntervalSize,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Options) Reset()         { *m = Options{} }
func (m *Options) String() string { return proto.CompactTextString(m) }
func (*Options) ProtoMessage()    {}
func (*Options) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{10}
}

func (m *Options) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Options.Unmarshal(m, b)
}
func (m *Options) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Options.Marshal(b, m, deterministic)
}
func (m *Options) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Options.Merge(m, src)
}
func (m *Options) XXX_Size() int {
	return xxx_messageInfo_Options.Size(m)
}
func (m *Options) XXX_DiscardUnknown() {
	xxx_messageInfo_Options.DiscardUnknown(m)
}

var xxx_messageInfo_Options proto.InternalMessageInfo

func (m *Options) GetTickInterval() string {
	if m != nil {
		return m.TickInterval
	}
	return ""
}

func (m *Options) GetElectionTick() uint32 {
	if m != nil {
		return m.ElectionTick
	}
	return 0
}

func (m *Options) GetHeartbeatTick() uint32 {
	if m != nil {
		return m.HeartbeatTick
	}
	return 0
}

func (m *Options) GetMaxInflightBlocks() uint32 {
	if m != nil {
		return m.MaxInflightBlocks
	}
	return 0
}

func (m *Options) GetSnapshotIntervalSize() uint32 {
	if m != nil {
		return m.SnapshotIntervalSize
	}
	return 0
}

// 请求生成指定联盟默认org服务集合
type PeerOrg struct {
	// 组织主域名
	Domain string `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	// 组织名称
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// ordererendpoint是这个组织运行的所有orderers的列表
	//
	// client和peer可以分别连接到这些orderers来推动事务和接收块，如：127.0.0.1:7050
	OrdererEndpoints []string `protobuf:"bytes,5,rep,name=ordererEndpoints,proto3" json:"ordererEndpoints,omitempty"`
	// 组织证书信息
	Cert *MspCert `protobuf:"bytes,6,opt,name=cert,proto3" json:"cert,omitempty"`
	// 锚节点定义了节点的位置，这些节点可用于跨组织的gossip通信。注意，这个值只在应用程序部分上下文的genesis块中编码
	AnchorPeers          []*AnchorPeer `protobuf:"bytes,7,rep,name=anchorPeers,proto3" json:"anchorPeers,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *PeerOrg) Reset()         { *m = PeerOrg{} }
func (m *PeerOrg) String() string { return proto.CompactTextString(m) }
func (*PeerOrg) ProtoMessage()    {}
func (*PeerOrg) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{11}
}

func (m *PeerOrg) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PeerOrg.Unmarshal(m, b)
}
func (m *PeerOrg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PeerOrg.Marshal(b, m, deterministic)
}
func (m *PeerOrg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PeerOrg.Merge(m, src)
}
func (m *PeerOrg) XXX_Size() int {
	return xxx_messageInfo_PeerOrg.Size(m)
}
func (m *PeerOrg) XXX_DiscardUnknown() {
	xxx_messageInfo_PeerOrg.DiscardUnknown(m)
}

var xxx_messageInfo_PeerOrg proto.InternalMessageInfo

func (m *PeerOrg) GetDomain() string {
	if m != nil {
		return m.Domain
	}
	return ""
}

func (m *PeerOrg) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *PeerOrg) GetOrdererEndpoints() []string {
	if m != nil {
		return m.OrdererEndpoints
	}
	return nil
}

func (m *PeerOrg) GetCert() *MspCert {
	if m != nil {
		return m.Cert
	}
	return nil
}

func (m *PeerOrg) GetAnchorPeers() []*AnchorPeer {
	if m != nil {
		return m.AnchorPeers
	}
	return nil
}

// 请求生成指定联盟默认orderer服务集合
type OrdererOrg struct {
	// 组织主域名
	Domain string `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
	// 组织名称
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// ordererendpoint是这个组织运行的所有orderers的列表
	//
	// client和peer可以分别连接到这些orderers来推动事务和接收块，如：127.0.0.1:7050
	OrdererEndpoints []string `protobuf:"bytes,5,rep,name=ordererEndpoints,proto3" json:"ordererEndpoints,omitempty"`
	// 组织证书信息
	Cert                 *MspCert `protobuf:"bytes,6,opt,name=cert,proto3" json:"cert,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *OrdererOrg) Reset()         { *m = OrdererOrg{} }
func (m *OrdererOrg) String() string { return proto.CompactTextString(m) }
func (*OrdererOrg) ProtoMessage()    {}
func (*OrdererOrg) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{12}
}

func (m *OrdererOrg) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OrdererOrg.Unmarshal(m, b)
}
func (m *OrdererOrg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OrdererOrg.Marshal(b, m, deterministic)
}
func (m *OrdererOrg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OrdererOrg.Merge(m, src)
}
func (m *OrdererOrg) XXX_Size() int {
	return xxx_messageInfo_OrdererOrg.Size(m)
}
func (m *OrdererOrg) XXX_DiscardUnknown() {
	xxx_messageInfo_OrdererOrg.DiscardUnknown(m)
}

var xxx_messageInfo_OrdererOrg proto.InternalMessageInfo

func (m *OrdererOrg) GetDomain() string {
	if m != nil {
		return m.Domain
	}
	return ""
}

func (m *OrdererOrg) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *OrdererOrg) GetOrdererEndpoints() []string {
	if m != nil {
		return m.OrdererEndpoints
	}
	return nil
}

func (m *OrdererOrg) GetCert() *MspCert {
	if m != nil {
		return m.Cert
	}
	return nil
}

// 组织证书信息
type MspCert struct {
	// 组织管理员证书
	AdminCert []byte `protobuf:"bytes,1,opt,name=adminCert,proto3" json:"adminCert,omitempty"`
	// 组织根证书
	CaCert []byte `protobuf:"bytes,2,opt,name=caCert,proto3" json:"caCert,omitempty"`
	// 组织tls根证书
	TlsCaCert            []byte   `protobuf:"bytes,3,opt,name=tlsCaCert,proto3" json:"tlsCaCert,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MspCert) Reset()         { *m = MspCert{} }
func (m *MspCert) String() string { return proto.CompactTextString(m) }
func (*MspCert) ProtoMessage()    {}
func (*MspCert) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{13}
}

func (m *MspCert) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MspCert.Unmarshal(m, b)
}
func (m *MspCert) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MspCert.Marshal(b, m, deterministic)
}
func (m *MspCert) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MspCert.Merge(m, src)
}
func (m *MspCert) XXX_Size() int {
	return xxx_messageInfo_MspCert.Size(m)
}
func (m *MspCert) XXX_DiscardUnknown() {
	xxx_messageInfo_MspCert.DiscardUnknown(m)
}

var xxx_messageInfo_MspCert proto.InternalMessageInfo

func (m *MspCert) GetAdminCert() []byte {
	if m != nil {
		return m.AdminCert
	}
	return nil
}

func (m *MspCert) GetCaCert() []byte {
	if m != nil {
		return m.CaCert
	}
	return nil
}

func (m *MspCert) GetTlsCaCert() []byte {
	if m != nil {
		return m.TlsCaCert
	}
	return nil
}

// 锚节点定义了节点的位置，这些节点可用于跨组织的gossip通信。注意，这个值只在应用程序部分上下文的genesis块中编码
type AnchorPeer struct {
	Host                 string   `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Port                 int32    `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AnchorPeer) Reset()         { *m = AnchorPeer{} }
func (m *AnchorPeer) String() string { return proto.CompactTextString(m) }
func (*AnchorPeer) ProtoMessage()    {}
func (*AnchorPeer) Descriptor() ([]byte, []int) {
	return fileDescriptor_6dbc2330b31a54f8, []int{14}
}

func (m *AnchorPeer) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AnchorPeer.Unmarshal(m, b)
}
func (m *AnchorPeer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AnchorPeer.Marshal(b, m, deterministic)
}
func (m *AnchorPeer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AnchorPeer.Merge(m, src)
}
func (m *AnchorPeer) XXX_Size() int {
	return xxx_messageInfo_AnchorPeer.Size(m)
}
func (m *AnchorPeer) XXX_DiscardUnknown() {
	xxx_messageInfo_AnchorPeer.DiscardUnknown(m)
}

var xxx_messageInfo_AnchorPeer proto.InternalMessageInfo

func (m *AnchorPeer) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func (m *AnchorPeer) GetPort() int32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func init() {
	proto.RegisterType((*ReqGenesisBlock)(nil), "genesis.ReqGenesisBlock")
	proto.RegisterType((*RespGenesisBlock)(nil), "genesis.RespGenesisBlock")
	proto.RegisterType((*ReqChannelTx)(nil), "genesis.ReqChannelTx")
	proto.RegisterType((*RespChannelTx)(nil), "genesis.RespChannelTx")
	proto.RegisterType((*League)(nil), "genesis.League")
	proto.RegisterType((*Consortium)(nil), "genesis.Consortium")
	proto.RegisterType((*Orderer)(nil), "genesis.Orderer")
	proto.RegisterType((*BatchSize)(nil), "genesis.BatchSize")
	proto.RegisterType((*EtcdRaft)(nil), "genesis.EtcdRaft")
	proto.RegisterType((*Consenter)(nil), "genesis.Consenter")
	proto.RegisterType((*Options)(nil), "genesis.Options")
	proto.RegisterType((*PeerOrg)(nil), "genesis.PeerOrg")
	proto.RegisterType((*OrdererOrg)(nil), "genesis.OrdererOrg")
	proto.RegisterType((*MspCert)(nil), "genesis.MspCert")
	proto.RegisterType((*AnchorPeer)(nil), "genesis.AnchorPeer")
}

func init() { proto.RegisterFile("grpc/proto/genesis/block.proto", fileDescriptor_6dbc2330b31a54f8) }

var fileDescriptor_6dbc2330b31a54f8 = []byte{
	// 890 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xc4, 0x56, 0xcd, 0x6e, 0x23, 0x45,
	0x10, 0xd6, 0xd8, 0x8e, 0x1d, 0x57, 0xe2, 0x4d, 0xb6, 0x41, 0x68, 0x84, 0xd0, 0xca, 0x8c, 0x56,
	0xc2, 0x8a, 0x76, 0x1d, 0x64, 0xe0, 0x01, 0xb0, 0x37, 0x82, 0x48, 0x31, 0x59, 0xf5, 0x46, 0x1c,
	0x90, 0x38, 0xb4, 0x67, 0xca, 0xf6, 0x90, 0x71, 0xf7, 0x6c, 0x77, 0x3b, 0x32, 0x5c, 0xe0, 0xcc,
	0x85, 0x87, 0xe0, 0x3d, 0x78, 0x04, 0xee, 0xbc, 0x0d, 0xea, 0x9f, 0xf9, 0xb3, 0x17, 0x05, 0x89,
	0x03, 0xb7, 0xe9, 0xaf, 0xbe, 0xea, 0xae, 0xfa, 0xaa, 0xaa, 0x7b, 0xe0, 0xd9, 0x4a, 0xe6, 0xf1,
	0x65, 0x2e, 0x85, 0x16, 0x97, 0x2b, 0xe4, 0xa8, 0x52, 0x75, 0xb9, 0xc8, 0x44, 0x7c, 0x3f, 0xb6,
	0x18, 0xe9, 0x79, 0xf0, 0xc3, 0x77, 0x11, 0x91, 0x6f, 0x37, 0xca, 0x11, 0xa3, 0x5f, 0x5a, 0x70,
	0x46, 0xf1, 0xed, 0x57, 0xce, 0x34, 0x35, 0x5b, 0x90, 0x4f, 0xa0, 0x9b, 0x21, 0x5b, 0x6d, 0x31,
	0x0c, 0x86, 0xc1, 0xe8, 0x64, 0x72, 0x36, 0xf6, 0x9e, 0xe3, 0x1b, 0x0b, 0x53, 0x6f, 0x26, 0x17,
	0xd0, 0x13, 0x32, 0x41, 0x89, 0x32, 0x6c, 0x59, 0xe6, 0x79, 0xc9, 0xbc, 0x75, 0x38, 0x2d, 0x08,
	0xe4, 0x02, 0xce, 0x13, 0x5c, 0xb2, 0x6d, 0xa6, 0x67, 0x6b, 0xc6, 0x39, 0x66, 0xd7, 0xaf, 0xc2,
	0xf6, 0x30, 0x18, 0xf5, 0xe9, 0x01, 0x4e, 0xbe, 0x80, 0x13, 0xef, 0x76, 0x2b, 0x57, 0x2a, 0xec,
	0x0c, 0xdb, 0xa3, 0x93, 0xc9, 0x7b, 0xfb, 0x7b, 0xdf, 0xca, 0x15, 0xad, 0xf3, 0x8c, 0x5b, 0x2c,
	0xb8, 0x12, 0x52, 0xa7, 0xdb, 0x8d, 0x0a, 0x8f, 0xf6, 0xdc, 0x66, 0xa5, 0x8d, 0xd6, 0x79, 0xd1,
	0x3d, 0x9c, 0x53, 0x54, 0x79, 0x43, 0x82, 0x8f, 0xa1, 0x13, 0x8b, 0xc4, 0x09, 0xf0, 0x64, 0x32,
	0xa8, 0xed, 0x91, 0x20, 0xb5, 0x26, 0xf2, 0x01, 0x74, 0x51, 0xca, 0xb9, 0x5a, 0xd9, 0xdc, 0xfb,
	0xd4, 0xaf, 0xc8, 0x47, 0xd0, 0xb7, 0x95, 0x78, 0xc5, 0x34, 0xb3, 0x19, 0x9e, 0xd2, 0x0a, 0x88,
	0x7e, 0x0f, 0xe0, 0x94, 0xe2, 0x5b, 0x9f, 0xeb, 0xdd, 0xee, 0xdf, 0x8b, 0xfd, 0x0c, 0xa0, 0x8a,
	0xda, 0x9f, 0x59, 0x43, 0xcc, 0xb9, 0xf1, 0x9e, 0xb2, 0x15, 0x40, 0x5e, 0xc0, 0x71, 0x8e, 0x0d,
	0x3d, 0xab, 0x5a, 0xbd, 0x76, 0x06, 0x5a, 0x32, 0xa2, 0x1c, 0x06, 0x46, 0x92, 0x2a, 0xca, 0xff,
	0xa0, 0xc7, 0x73, 0x18, 0xc4, 0xc5, 0x3e, 0x35, 0x4d, 0x9a, 0x60, 0x74, 0x03, 0x5d, 0x97, 0xaf,
	0xd9, 0x27, 0x11, 0x1b, 0x96, 0x72, 0x7b, 0x58, 0x9f, 0xfa, 0x95, 0x69, 0xb6, 0x07, 0x94, 0x2a,
	0x15, 0xdc, 0x1e, 0xf0, 0xa4, 0x96, 0xc0, 0xb7, 0x0e, 0xa7, 0x05, 0x21, 0xfa, 0x06, 0xa0, 0xaa,
	0x36, 0x21, 0xd0, 0xe1, 0x6c, 0x83, 0x7e, 0x3f, 0xfb, 0xdd, 0xd0, 0xa3, 0xf5, 0xa8, 0x1e, 0x7f,
	0x06, 0xd0, 0xf3, 0x5d, 0x67, 0x74, 0x66, 0x49, 0x22, 0x51, 0x29, 0x54, 0x61, 0x7b, 0xd8, 0x36,
	0x3a, 0x97, 0x00, 0x89, 0xe0, 0x74, 0xca, 0x74, 0xbc, 0xbe, 0x4b, 0x37, 0x28, 0xb6, 0x3a, 0xec,
	0x0c, 0x83, 0x51, 0x9b, 0x36, 0x30, 0xf2, 0x29, 0xf4, 0x17, 0x66, 0xfd, 0x26, 0xfd, 0x09, 0xc3,
	0x23, 0x5b, 0x75, 0x52, 0x1e, 0x3e, 0x2d, 0x2c, 0xb4, 0x22, 0x91, 0x97, 0x70, 0x8c, 0x3a, 0x4e,
	0x28, 0x5b, 0xea, 0xb0, 0x6b, 0x1d, 0x9e, 0x96, 0x0e, 0x57, 0xde, 0x40, 0x4b, 0x0a, 0x19, 0xc2,
	0xc9, 0x9c, 0xed, 0x7c, 0xf5, 0x54, 0xd8, 0x1b, 0x06, 0xa3, 0x0e, 0xad, 0x43, 0xd1, 0x6f, 0x01,
	0xf4, 0xcb, 0x93, 0xc8, 0x08, 0xce, 0x36, 0x6c, 0x37, 0x47, 0xa5, 0xd8, 0x0a, 0x67, 0x62, 0xcb,
	0xb5, 0xd5, 0x6a, 0x40, 0xf7, 0x61, 0x33, 0xc5, 0x6c, 0xa1, 0x44, 0xb6, 0xd5, 0x38, 0x67, 0xbb,
	0xe9, 0x8f, 0x1a, 0x95, 0xad, 0xc6, 0x80, 0x1e, 0xe0, 0xe4, 0x05, 0x3c, 0xcd, 0x25, 0x2e, 0x51,
	0x4a, 0x4c, 0x4a, 0x72, 0xdb, 0x92, 0x0f, 0x0d, 0xd1, 0x0f, 0x70, 0x5c, 0x64, 0x42, 0x26, 0xae,
	0xd5, 0x91, 0x6b, 0x94, 0x2a, 0x0c, 0x6c, 0x79, 0x48, 0x63, 0x8e, 0xad, 0x89, 0xd6, 0x58, 0xf6,
	0x2e, 0xca, 0x75, 0x2a, 0xb8, 0x3a, 0xbc, 0x8b, 0x1c, 0x4e, 0x0b, 0x42, 0xf4, 0x33, 0xf4, 0xcb,
	0x4d, 0x4c, 0x77, 0xac, 0x85, 0xd2, 0x45, 0x77, 0x98, 0x6f, 0x83, 0xe5, 0x42, 0x6a, 0x9f, 0x9a,
	0xfd, 0xb6, 0x7d, 0x9c, 0xa5, 0xc8, 0xf5, 0x5d, 0xa6, 0x66, 0x28, 0x75, 0xd9, 0xc7, 0x75, 0xd0,
	0xb0, 0x14, 0xca, 0x07, 0x94, 0x05, 0xab, 0xe3, 0x58, 0x0d, 0x30, 0xfa, 0xcb, 0xf4, 0x93, 0x0b,
	0xc6, 0x74, 0xcc, 0x5d, 0x1a, 0xdf, 0x5f, 0x9b, 0x60, 0x1e, 0x58, 0xe6, 0xe3, 0x68, 0x60, 0x86,
	0x73, 0x95, 0x61, 0x6c, 0x1c, 0x0c, 0xee, 0xe3, 0x6a, 0x60, 0xe6, 0xe4, 0xaf, 0x91, 0x49, 0xbd,
	0x40, 0xa6, 0x2d, 0xc9, 0x49, 0xdd, 0x04, 0x4d, 0x51, 0xe6, 0x6c, 0x77, 0xcd, 0x97, 0x59, 0xba,
	0x5a, 0x6b, 0x7b, 0xd9, 0x29, 0x1b, 0xe3, 0x80, 0x1e, 0x1a, 0xc8, 0x04, 0xde, 0x7f, 0xc3, 0x59,
	0xae, 0xd6, 0x42, 0x17, 0xb1, 0x94, 0x4d, 0x3b, 0xa0, 0xef, 0xb4, 0x45, 0x7f, 0x04, 0xd0, 0xf3,
	0x13, 0xf4, 0x8f, 0xb3, 0x5c, 0x4c, 0x64, 0xab, 0x36, 0x91, 0x17, 0x70, 0xee, 0x2f, 0xf3, 0x2b,
	0x9e, 0xe4, 0x22, 0xe5, 0xda, 0x5d, 0xe1, 0x7d, 0x7a, 0x80, 0x93, 0xe7, 0xd0, 0x89, 0x8d, 0xb8,
	0xdd, 0xbd, 0x4a, 0xcf, 0x55, 0x6e, 0xf4, 0xa5, 0xd6, 0x6a, 0xde, 0x03, 0xc6, 0xe3, 0xb5, 0x90,
	0x26, 0x1c, 0x33, 0x06, 0xcd, 0xf7, 0xe0, 0xcb, 0xd2, 0x46, 0xeb, 0xbc, 0xe8, 0xd7, 0x00, 0xa0,
	0x7a, 0x62, 0xfe, 0xdf, 0x1c, 0xa2, 0xef, 0xa1, 0xe7, 0x01, 0x77, 0xf1, 0x6c, 0x52, 0x6e, 0xdb,
	0x2a, 0x70, 0x0f, 0x4b, 0x09, 0x98, 0x30, 0x63, 0x66, 0x4d, 0x2d, 0x6b, 0xf2, 0x2b, 0xe3, 0xa5,
	0x33, 0x35, 0x63, 0xb5, 0x96, 0xad, 0x80, 0xe8, 0x73, 0x80, 0x4a, 0x86, 0x47, 0x47, 0xe1, 0xc8,
	0x8d, 0xc2, 0xf4, 0x06, 0x2e, 0x62, 0x3e, 0x66, 0x0b, 0x94, 0x69, 0x3c, 0x5e, 0xb2, 0x85, 0x4c,
	0xe3, 0x97, 0x6e, 0x0c, 0xc6, 0xe6, 0x77, 0xc3, 0xfd, 0x5a, 0x14, 0x09, 0x4d, 0xc1, 0x36, 0xd3,
	0x6b, 0x83, 0x7d, 0x47, 0x0e, 0x7f, 0x47, 0x16, 0x5d, 0xbb, 0xfc, 0xec, 0xef, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xe7, 0xc3, 0xfc, 0x54, 0xd4, 0x08, 0x00, 0x00,
}
