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
	"path"
	"path/filepath"
)

// Client go sdk 使用的客户端
type Client struct {
	// Organization 这个应用程序实例属于哪个组织?值必须是在“组织”下定义的组织的名称，如：Org1或league-org1
	Organization string `yaml:"organization"`
	// Logging 日志级别，debug、info、warn、error等
	Logging *ClientLogging `yaml:"logging"`
	// 节点超时的全局配置，如果省略此部分，则将使用缺省值
	Peer *ClientPeer `yaml:"peer"`
	// 事件服务超时的全局配置，如果省略此部分，则将使用缺省值
	EventService *ClientEventService `yaml:"eventService"`
	// orderer超时的全局配置，如果省略此部分，则将使用缺省值
	Order *ClientOrder `yaml:"orderer"`
	// 超时的全局配置，如果省略此部分，则将使用缺省值
	Global *ClientGlobal `yaml:"global"`
	// CryptoConfig 客户端
	CryptoConfig    *ClientCryptoConfig    `yaml:"cryptoconfig"`
	CredentialStore *ClientCredentialStore `yaml:"credentialStore"`
	// BCCSP 客户端的BCCSP配置
	BCCSP    *ClientBCCSP    `yaml:"BCCSP"`
	TLSCerts *ClientTLSCerts `yaml:"tlsCerts"`
}

// ClientLogging 客户端日志设置对象
type ClientLogging struct {
	Level string `yaml:"level"` // info
}

// ClientCryptoConfig 客户端
type ClientCryptoConfig struct {
	// Path 带有密钥和证书的MSP目录的根目录
	Path string `yaml:"path"` // /Users/Documents/fabric/crypto-config
}

type ClientCredentialStore struct {
	Path        string                            `yaml:"path"` // /tmp/state-store"
	CryptoStore *ClientCredentialStoreCryptoStore `yaml:"cryptoStore"`
}

type ClientCredentialStoreCryptoStore struct {
	Path string `yaml:"path"` // /tmp/msp
}

type ClientBCCSP struct {
	Security *ClientBCCSPSecurity `yaml:"security"`
}

type ClientBCCSPSecurity struct {
	Enabled       bool                        `yaml:"enabled"`
	Default       *ClientBCCSPSecurityDefault `yaml:"default"`
	HashAlgorithm string                      `yaml:"hashAlgorithm"`
	SoftVerify    bool                        `yaml:"softVerify"`
	Level         int32                       `yaml:"level"`
}

type ClientBCCSPSecurityDefault struct {
	Provider string `yaml:"provider"`
}

type ClientTLSCerts struct {
	// SystemCertPool 是否开启TLS，默认false
	SystemCertPool bool `yaml:"systemCertPool"`
	// Client 客户端密钥和证书，用于TLS与节点和排序服务的握手
	Client *ClientTLSCertsClient `yaml:"client"`
}

type ClientTLSCertsClient struct {
	Key  *ClientTLSCertsClientKey  `yaml:"key"`
	Cert *ClientTLSCertsClientCert `yaml:"cert"`
}

type ClientTLSCertsClientKey struct {
	Path string `yaml:"path"` // /fabric/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/tls/client.key
}

type ClientTLSCertsClientCert struct {
	Path string `yaml:"path"` // /fabric/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/tls/client.crt
}

type ClientPeer struct {
	Timeout *ClientPeerTimeout `yaml:"timeout"`
}

type ClientPeerTimeout struct {
	Connection string                      `yaml:"connection"`
	Response   string                      `yaml:"response"`
	Discovery  *ClientPeerTimeoutDiscovery `yaml:"discovery"`
}

type ClientPeerTimeoutDiscovery struct {
	// GreyListExpiry 发现服务失效列表筛选器的有效期。
	//
	// 通道客户端将列出脱机的失效节点名单，防止在后续重试中重新选择它们。
	//
	// 这个间隔将定义一个节点被灰列出的时间
	GreyListExpiry string `yaml:"greylistExpiry"`
}

type ClientEventService struct {
	Timeout *ClientEventServiceTimeout `yaml:"timeout"`
}

type ClientEventServiceTimeout struct {
	RegistrationResponse string `yaml:"registrationResponse"`
}

type ClientOrder struct {
	Timeout *ClientOrderTimeout `yaml:"timeout"`
}

type ClientOrderTimeout struct {
	Connection string `yaml:"connection"`
	Response   string `yaml:"response"`
}

type ClientGlobal struct {
	Timeout *ClientGlobalTimeout `yaml:"timeout"`
	Cache   *ClientGlobalCache   `yaml:"cache"`
}

type ClientGlobalTimeout struct {
	Query   string `yaml:"query"`
	Execute string `yaml:"execute"`
	Resmgmt string `yaml:"resmgmt"`
}

type ClientGlobalCache struct {
	ConnectionIdle    string `yaml:"connectionIdle"`
	EventServiceIdle  string `yaml:"eventServiceIdle"`
	ChannelConfig     string `yaml:"channelConfig"`
	ChannelMembership string `yaml:"channelMembership"`
	Discovery         string `yaml:"discovery"`
	Selection         string `yaml:"selection"`
}

func NewConfigClient(league *config.League, org *config.Org) (*Client, string, error) {
	if gnomon.String().IsEmpty(league.Domain) || gnomon.String().IsEmpty(org.Domain) ||
		gnomon.String().IsEmpty(org.Name) || gnomon.String().IsEmpty(org.Username) {
		return nil, "", errors.New("league or org info params should be set")
	}
	cryptoConfigPath := utils.CryptoConfigPath(league.Domain)
	_, orgUserPath := utils.CryptoOrgAndNodePath(league.Domain, org.Domain, org.Name, org.Username, true)
	return &Client{
		Organization: org.Name,
		Logging: &ClientLogging{
			Level: "info",
		},
		Peer: &ClientPeer{
			Timeout: &ClientPeerTimeout{
				Connection: "10s",
				Response:   "180s",
				Discovery: &ClientPeerTimeoutDiscovery{
					GreyListExpiry: "10s",
				},
			},
		},
		EventService: &ClientEventService{
			Timeout: &ClientEventServiceTimeout{
				RegistrationResponse: "15s",
			},
		},
		Order: &ClientOrder{
			Timeout: &ClientOrderTimeout{
				Connection: "15s",
				Response:   "15s",
			},
		},
		Global: &ClientGlobal{
			Timeout: &ClientGlobalTimeout{
				Query:   "180s",
				Execute: "180s",
				Resmgmt: "180s",
			},
			Cache: &ClientGlobalCache{
				ConnectionIdle:    "30s",
				EventServiceIdle:  "2m",
				ChannelMembership: "30m",
				ChannelConfig:     "30s",
				Discovery:         "10s",
				Selection:         "10m",
			},
		},
		CryptoConfig: &ClientCryptoConfig{
			Path: cryptoConfigPath,
		},
		CredentialStore: &ClientCredentialStore{
			Path:        path.Join(orgUserPath, "msp", "signcerts"),
			CryptoStore: &ClientCredentialStoreCryptoStore{Path: path.Join(orgUserPath, "msp")},
		},
		BCCSP: &ClientBCCSP{
			Security: &ClientBCCSPSecurity{
				Enabled: true,
				Default: &ClientBCCSPSecurityDefault{
					Provider: "SW",
				},
				HashAlgorithm: "SHA2",
				SoftVerify:    true,
				Level:         256,
			},
		},
		TLSCerts: &ClientTLSCerts{
			SystemCertPool: false,
		},
	}, orgUserPath, nil
}

func (c *Client) set(client *config.Client, orgUserPath string) error {
	if nil == client {
		return nil
	}
	c.setLogging(client)
	c.setPeer(client)
	c.setEventService(client)
	c.setOrder(client)
	c.setGlobal(client)
	c.setBCCSP(client)
	return c.setTLSCerts(client, orgUserPath)
}

func (c *Client) setLogging(client *config.Client) {
	if nil != client.Logging && gnomon.String().IsNotEmpty(client.Logging.Level) {
		c.Logging.Level = client.Logging.Level
	} else {
		c.Logging.Level = "info"
	}
}

func (c *Client) setPeer(client *config.Client) {
	if nil != client.Peer && nil != client.Peer.Timeout {
		if gnomon.String().IsNotEmpty(client.Peer.Timeout.Connection) {
			c.Peer.Timeout.Connection = client.Peer.Timeout.Connection
			c.Peer.Timeout.Response = client.Peer.Timeout.Response
			c.Peer.Timeout.Discovery.GreyListExpiry = client.Peer.Timeout.Discovery.GreyListExpiry
		}
		if gnomon.String().IsNotEmpty(client.Peer.Timeout.Response) {
			c.Peer.Timeout.Response = client.Peer.Timeout.Response
		}
		if nil != client.Peer.Timeout.Discovery && gnomon.String().IsNotEmpty(client.Peer.Timeout.Discovery.GreyListExpiry) {
			c.Peer.Timeout.Discovery.GreyListExpiry = client.Peer.Timeout.Discovery.GreyListExpiry
		}
	}
}

func (c *Client) setEventService(client *config.Client) {
	if nil != client.EventService && nil != client.EventService.Timeout && gnomon.String().IsNotEmpty(client.EventService.Timeout.RegistrationResponse) {
		c.EventService.Timeout.RegistrationResponse = client.EventService.Timeout.RegistrationResponse
	}
}

func (c *Client) setOrder(client *config.Client) {
	if nil != client.Order && nil != client.Order.Timeout {
		if gnomon.String().IsNotEmpty(client.Order.Timeout.Connection) {
			c.Order.Timeout.Connection = client.Order.Timeout.Connection
		}
		if gnomon.String().IsNotEmpty(client.Order.Timeout.Response) {
			c.Order.Timeout.Response = client.Order.Timeout.Response
		}
	}
}

func (c *Client) setGlobal(client *config.Client) {
	if nil != client.Global {
		if nil != client.Global.Timeout {
			if gnomon.String().IsNotEmpty(client.Global.Timeout.Query) {
				c.Global.Timeout.Query = client.Global.Timeout.Query
			}
			if gnomon.String().IsNotEmpty(client.Global.Timeout.Execute) {
				c.Global.Timeout.Execute = client.Global.Timeout.Execute
			}
			if gnomon.String().IsNotEmpty(client.Global.Timeout.Resmgmt) {
				c.Global.Timeout.Resmgmt = client.Global.Timeout.Resmgmt
			}
		}
		if nil != client.Global.Cache {
			if gnomon.String().IsNotEmpty(client.Global.Cache.ConnectionIdle) {
				c.Global.Cache.ConnectionIdle = client.Global.Cache.ConnectionIdle
			}
			if gnomon.String().IsNotEmpty(client.Global.Cache.EventServiceIdle) {
				c.Global.Cache.EventServiceIdle = client.Global.Cache.EventServiceIdle
			}
			if gnomon.String().IsNotEmpty(client.Global.Cache.ChannelMembership) {
				c.Global.Cache.ChannelMembership = client.Global.Cache.ChannelMembership
			}
			if gnomon.String().IsNotEmpty(client.Global.Cache.ChannelConfig) {
				c.Global.Cache.ChannelConfig = client.Global.Cache.ChannelConfig
			}
			if gnomon.String().IsNotEmpty(client.Global.Cache.Discovery) {
				c.Global.Cache.Discovery = client.Global.Cache.Discovery
			}
			if gnomon.String().IsNotEmpty(client.Global.Cache.Selection) {
				c.Global.Cache.Selection = client.Global.Cache.Selection
			}
		}
	}
}

func (c *Client) setBCCSP(client *config.Client) {
	if nil != client.BCCSP && nil != client.BCCSP.Security {
		c.BCCSP.Security.Enabled = client.BCCSP.Security.Enabled
		c.BCCSP.Security.SoftVerify = client.BCCSP.Security.SoftVerify
		if nil != client.BCCSP.Security.Default && gnomon.String().IsNotEmpty(client.BCCSP.Security.Default.Provider) {
			c.BCCSP.Security.Default.Provider = client.BCCSP.Security.Default.Provider
		}
		if gnomon.String().IsNotEmpty(client.BCCSP.Security.HashAlgorithm) {
			c.BCCSP.Security.HashAlgorithm = client.BCCSP.Security.HashAlgorithm
		}
		if client.BCCSP.Security.Level > 0 {
			c.BCCSP.Security.Level = client.BCCSP.Security.Level
		}
	}
}

func (c *Client) setTLSCerts(client *config.Client, orgUserPath string) error {
	if client.Tls {
		c.TLSCerts.SystemCertPool = true
		c.TLSCerts.Client.Key.Path = filepath.Join(orgUserPath, "tls", "client.key")
		c.TLSCerts.Client.Cert.Path = filepath.Join(orgUserPath, "tls", "client.crt")
	}
	return nil
}
