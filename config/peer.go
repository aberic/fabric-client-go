/*
 * Copyright (c) 2019. Aberic - All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"errors"
	"github.com/aberic/fabric-client-go/grpc/proto/config"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"path/filepath"
)

// Peer 节点，用于发送各种请求的节点列表，包括背书、查询和事件侦听器注册
type Peer struct {
	URL      string `yaml:"url"`      // URL 此URL用于发送背书和查询请求
	EventURL string `yaml:"eventUrl"` // EventURL 只在使用EventHub时才需要(默认是交付服务)
	// GRPCOptions 这些是由gRPC库定义的标准属性，它们将按原样传递给gRPC客户端构造函数
	GRPCOptions *PeerGRPCOptions `yaml:"grpcOptions"`
	TLSCACerts  *PeerTLSCACerts  `yaml:"tlsCACerts"`
}

// PeerGRPCOptions PeerGRPCOptions
type PeerGRPCOptions struct {
	// SSLTargetNameOverride peer0.org1.example.com
	SSLTargetNameOverride string `yaml:"ssl-target-name-override"`
	// KeepAliveTime
	//
	// 这些参数应该与服务器上的keepalive策略协调设置，因为不兼容的设置可能导致连接关闭
	//
	// 当“keep-alive-time”的持续时间设置为0或更少时，将禁用keep alive客户端参数
	KeepAliveTime string `yaml:"keep-alive-time"`
	// KeepAliveTimeout
	//
	// 这些参数应该与服务器上的keepalive策略协调设置，因为不兼容的设置可能导致连接关闭
	//
	// 当“keep-alive-time”的持续时间设置为0或更少时，将禁用keep alive客户端参数
	KeepAliveTimeout string `yaml:"keep-alive-timeout"`
	// KeepAlivePermit
	//
	// 这些参数应该与服务器上的keepalive策略协调设置，因为不兼容的设置可能导致连接关闭
	//
	// 当“keep-alive-time”的持续时间设置为0或更少时，将禁用keep alive客户端参数
	KeepAlivePermit bool `yaml:"keep-alive-permit"`
	FailFast        bool `yaml:"fail-fast"`
	AllowInsecure   bool `yaml:"allow-insecure"`
}

// PeerTLSCACerts PeerTLSCACerts
type PeerTLSCACerts struct {
	Path string `yaml:"path"` // /fabric/crypto-config/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
}

func (p *Peer) set(leagueDomain string, org *config.Org, peer *config.Peer) error {
	if gnomon.StringIsNotEmpty(peer.Url) {
		p.URL = peer.Url
	} else {
		return errors.New("url can't be empty")
	}
	if gnomon.StringIsNotEmpty(peer.EventUrl) {
		p.EventURL = peer.EventUrl
	} else {
		return errors.New("event url can't be empty")
	}
	if nil != peer.GrpcOptions {
		if err := p.setPeerGRPCOptions(peer.GrpcOptions); nil != err {
			return err
		}
	}
	orgPath := utils.CryptoOrgPath(leagueDomain, org.Domain, org.Name, true)
	rootTLSCACertFileName := utils.RootOrgTLSCACertFileName(org.Name, org.Domain)
	tlsCaCertPath := filepath.Join(orgPath, "tlsca", rootTLSCACertFileName)
	p.TLSCACerts.Path = tlsCaCertPath
	return nil
}

func (p *Peer) setPeerGRPCOptions(options *config.GRPCOptions) error {
	if gnomon.StringIsNotEmpty(options.SslTargetNameOverride) {
		p.GRPCOptions.SSLTargetNameOverride = options.SslTargetNameOverride
	} else {
		return errors.New("ssl-target-name-override can't be empty")
	}
	if gnomon.StringIsNotEmpty(options.KeepAliveTime) {
		p.GRPCOptions.KeepAliveTime = options.KeepAliveTime
	} else {
		p.GRPCOptions.KeepAliveTime = "0s"
	}
	if gnomon.StringIsNotEmpty(options.KeepAliveTimeout) {
		p.GRPCOptions.KeepAliveTimeout = options.KeepAliveTimeout
	} else {
		p.GRPCOptions.KeepAliveTimeout = "20s"
	}
	p.GRPCOptions.KeepAlivePermit = options.KeepAlivePermit
	p.GRPCOptions.FailFast = options.FailFast
	p.GRPCOptions.AllowInsecure = options.AllowInsecure
	return nil
}
