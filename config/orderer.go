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

// Orderer 发送事务和通道创建/更新请求
type Orderer struct {
	URL string `yaml:"url"` // URL grpcs://127.0.0.1:7050
	// GRPCOptions 这些是由gRPC库定义的标准属性，它们将按原样传递给gRPC客户端构造函数
	GRPCOptions *OrdererGRPCOptions `yaml:"grpcOptions"`
	TLSCACerts  *OrdererTLSCACerts  `yaml:"tlsCACerts"`
}

// OrdererGRPCOptions OrdererGRPCOptions
type OrdererGRPCOptions struct {
	// SSLTargetNameOverride orderer.example.com
	SSLTargetNameOverride string `yaml:"ssl-target-name-override"`
	// 这些参数应该与服务器上的keepalive策略协调设置，因为不兼容的设置可能导致连接关闭
	//
	// 当“keep-alive-time”的持续时间设置为0或更少时，将禁用keep alive客户端参数
	KeepAliveTime string `yaml:"keep-alive-time"`
	// 这些参数应该与服务器上的keepalive策略协调设置，因为不兼容的设置可能导致连接关闭
	//
	// 当“keep-alive-time”的持续时间设置为0或更少时，将禁用keep alive客户端参数
	KeepAliveTimeout string `yaml:"keep-alive-timeout"`
	// 这些参数应该与服务器上的keepalive策略协调设置，因为不兼容的设置可能导致连接关闭
	//
	// 当“keep-alive-time”的持续时间设置为0或更少时，将禁用keep alive客户端参数
	KeepAlivePermit bool `yaml:"keep-alive-permit"`
	FailFast        bool `yaml:"fail-fast"`
	// AllowInsecure 如果地址没有定义协议，则考虑允许不安全;如果为true，则考虑grpc或其他grpc
	AllowInsecure bool `yaml:"allow-insecure"`
}

// OrdererTLSCACerts OrdererTLSCACerts
type OrdererTLSCACerts struct {
	// Path 证书位置绝对路径
	Path string `yaml:"path"` // /fabric/crypto-config/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
}

func (o *Orderer) set(leagueDomain string, orderer *config.Orderer, node *config.Node) error {
	if gnomon.StringIsNotEmpty(node.Url) {
		o.URL = node.Url
	} else {
		return errors.New("url can't be empty")
	}
	if nil != node.GrpcOptions {
		if err := o.setOrdererGRPCOptions(node.GrpcOptions); nil != err {
			return err
		}
	}
	orgPath := utils.CryptoOrgPath(leagueDomain, orderer.Domain, orderer.Name, false)
	rootTLSCACertFileName := utils.RootOrgTLSCACertFileName(orderer.Name, orderer.Domain)
	tlsCaCertPath := filepath.Join(orgPath, "tlsca", rootTLSCACertFileName)
	o.TLSCACerts.Path = tlsCaCertPath
	return nil
}

func (o *Orderer) setOrdererGRPCOptions(options *config.GRPCOptions) error {
	if gnomon.StringIsNotEmpty(options.SslTargetNameOverride) {
		o.GRPCOptions.SSLTargetNameOverride = options.SslTargetNameOverride
	} else {
		return errors.New("ssl-target-name-override can't be empty")
	}
	if gnomon.StringIsNotEmpty(options.KeepAliveTime) {
		o.GRPCOptions.KeepAliveTime = options.KeepAliveTime
	} else {
		o.GRPCOptions.KeepAliveTime = "0s"
	}
	if gnomon.StringIsNotEmpty(options.KeepAliveTimeout) {
		o.GRPCOptions.KeepAliveTimeout = options.KeepAliveTimeout
	} else {
		o.GRPCOptions.KeepAliveTimeout = "20s"
	}
	o.GRPCOptions.KeepAlivePermit = options.KeepAlivePermit
	o.GRPCOptions.FailFast = options.FailFast
	o.GRPCOptions.AllowInsecure = options.AllowInsecure
	return nil
}
