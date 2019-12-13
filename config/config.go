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
	"fmt"
	"github.com/aberic/fabric-client-go/grpc/proto/config"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Config 网络连接配置为客户端应用程序提供有关目标区块链网络的信息
type Config struct {
	Version       string                   `yaml:"version"`       // Version 内容的版本。用于SDK应用相应的解析规则
	Client        *Client                  `yaml:"client"`        // Client GO SDK使用的客户端
	Channels      map[string]*Channel      `yaml:"channels"`      // Channels 可选，如果有通道操作则需要补充完整
	Organizations map[string]*Organization `yaml:"organizations"` // Organizations 此网络的参与机构名单
	// Orderers
	//
	// 发送事务和通道创建/更新请求的Order列表。如果定义了多个，那么SDK将根据文档定义来使用特定的Order
	Orderers map[string]*Orderer `yaml:"orderers"`
	// Peers
	//
	// 发送各种请求的节点列表，包括背书、查询和事件侦听器注册。
	Peers map[string]*Peer `yaml:"peers"`
	// CertificateAuthorities
	//
	// Fabric- ca是由Hyperledger Fabric提供的一种特殊的证书颁发机构，它允许通过REST api进行证书管理。
	//
	// 应用程序可以选择使用标准的证书颁发机构，而不是Fabric-CA，在这种情况下，不会指定此部分。
	CertificateAuthorities map[string]*CertificateAuthority `yaml:"certificateAuthorities"`
}

func (c *Config) set(init *config.ReqConfigInit) error {
	var err error
	if gnomon.String().IsEmpty(init.Version) {
		err = errors.New("version can't be nil")
		goto ERR
	}
	if nil == init.Org || gnomon.String().IsEmpty(init.Org.Domain) || gnomon.String().IsEmpty(init.Org.Name) ||
		gnomon.String().IsEmpty(init.Org.Username) {
		return errors.New("org or org require params can't be nil")
	}
	c.Version = init.Version
	if err = c.setClient(init); nil != err {
		goto ERR
	}
	c.setChannels(init)
	c.setOrganizations(init)
	if err = c.setOrderers(init); nil != err {
		goto ERR
	}
	if err = c.setPeers(init); nil != err {
		goto ERR
	}
	if err = c.setCertificateAuthorities(init); nil != err {
		goto ERR
	}
	if err = c.mkAllDir(init); nil != err {
		goto ERR
	}
	return nil
ERR:
	return fmt.Errorf("config set error: %w", err)
}

func (c *Config) setClient(init *config.ReqConfigInit) error {
	client, orgUserPath, err := NewConfigClient(init.League, init.Org)
	if nil != err {
		return fmt.Errorf("client set error: %w", err)
	}
	if err = client.set(init.Client, orgUserPath); nil != err {
		return fmt.Errorf("client set error: %w", err)
	}
	c.Client = client
	return nil
}

func (c *Config) setChannels(init *config.ReqConfigInit) {
	c.Channels = make(map[string]*Channel)
	c.Channels["_default"] = NewConfigChannel()
	for channelName, channel := range init.Channels {
		ch := NewConfigChannel()
		ch.set(init.Org, channel)
		c.Channels[channelName] = ch
	}
}

func (c *Config) setOrganizations(init *config.ReqConfigInit) {
	c.Organizations = make(map[string]*Organization)
	// 设置orderer
	if nil != init.Orderer {
		orderer := &Organization{}
		orderer.setOrderer(init.League, init.Orderer)
		c.Organizations[init.Orderer.Name] = orderer
	}
	// 设置org
	org := &Organization{}
	org.setOrg(init.League, init.Org)
	c.Organizations[init.Org.Name] = org
}

func (c *Config) setOrderers(init *config.ReqConfigInit) error {
	c.Orderers = make(map[string]*Orderer)
	if nil != init.Orderer {
		for _, node := range init.Orderer.Nodes {
			order := &Orderer{GRPCOptions: &OrdererGRPCOptions{}, TLSCACerts: &OrdererTLSCACerts{}}
			if err := order.set(init.League, init.Orderer, node); nil != err {
				return fmt.Errorf("orderers set error: %w", err)
			}
			c.Orderers[node.Name] = order
		}
	}
	return nil
}

func (c *Config) setPeers(init *config.ReqConfigInit) error {
	c.Peers = make(map[string]*Peer)
	if nil != init.Org {

	}
	for _, peer := range init.Org.Peers {
		p := &Peer{GRPCOptions: &PeerGRPCOptions{}, TLSCACerts: &PeerTLSCACerts{}}
		if err := p.set(init.League, init.Org, peer); nil != err {
			return fmt.Errorf("peers set error: %w", err)
		}
		c.Peers[peer.Name] = p
	}
	return nil
}

func (c *Config) setCertificateAuthorities(init *config.ReqConfigInit) error {
	c.CertificateAuthorities = make(map[string]*CertificateAuthority)
	for _, certificateAuthority := range init.Org.Cas {
		ca := &CertificateAuthority{
			TLSCACerts: &CertificateAuthorityTLSCACerts{Client: &CertificateAuthorityTLSCACertsClient{
				Key:  &CertificateAuthorityTLSCACertsClientKey{},
				Cert: &CertificateAuthorityTLSCACertsClientCert{},
			}},
			Registrar: &CertificateAuthorityRegistrar{},
		}
		if err := ca.set(init.League, init.Org, certificateAuthority); nil != err {
			return fmt.Errorf("ca set error: %w", err)
		}
		c.CertificateAuthorities[certificateAuthority.Name] = ca
	}
	return nil
}

// mkAllDir 创建crypto相关文件及信息，按照fabric的官方模板和格式
//
// 优先创建用户相关证书信息，以便后续创建组织和组织子节点内容时拷贝
func (c *Config) mkAllDir(init *config.ReqConfigInit) error {
	if err := c.mkOrdererDir(init.League, init.Orderer); nil != err {
		return err
	}
	return c.mkPeerDir(init.League, init.Org)
}

func (c *Config) mkOrdererDir(league *config.League, orderer *config.Orderer) error {
	var (
		admins []*adminCrypto
		err    error
	)
	if nil == orderer || gnomon.String().IsEmpty(orderer.Domain) || gnomon.String().IsEmpty(orderer.Name) ||
		gnomon.String().IsEmpty(orderer.Username) || nil == orderer.User {
		return nil
	}
	orgPath, userPath := utils.CryptoOrgAndUserPath(league.Domain, orderer.Domain, orderer.Name, orderer.Username, false)
	rootCACertFileName := utils.RootCACertFileName(league.Domain)
	rootTLSCACertFileName := utils.RootTLSCACertFileName(league.Domain)
	if err = os.MkdirAll(userPath, 0755); !gnomon.File().PathExists(userPath) && nil != err {
		return err
	}
	userSKIFileName, err := utils.SKI(league.Domain, orderer.Domain, orderer.Name, orderer.Username, true, orderer.User.Crypto.Key)
	if nil != err {
		return err
	}
	userCertFileName := utils.CertUserCAName(orderer.Name, orderer.Domain, orderer.User.Name)
	if err = c.mkMspDir(league, path.Join(userPath, "msp"), rootCACertFileName, rootTLSCACertFileName, nil, &userCrypto{
		skiFileName:  userSKIFileName,
		certFileName: userCertFileName,
		tlsPath:      path.Join(userPath, "tls"),
		isUser:       true,
		Crypto:       orderer.User.Crypto,
	}); nil != err {
		return err
	}
	admins = append(admins, &adminCrypto{certFileName: userCertFileName, certBytes: orderer.User.Crypto.Cert})

	if err = os.MkdirAll(orgPath, 0755); !gnomon.File().PathExists(orgPath) && nil != err {
		return err
	}
	if err = c.mkOrgDir(league, orgPath, "orderers", rootCACertFileName, rootTLSCACertFileName, admins); nil != err {
		return err
	}
	for _, node := range orderer.Nodes {
		_, nodePath := utils.CryptoOrgAndNodePath(league.Domain, orderer.Domain, orderer.Name, node.Name, false)
		nodeSKIFileName, err := utils.SKI(league.Domain, orderer.Domain, orderer.Name, node.Name, false, node.Crypto.Key)
		if nil != err {
			return err
		}
		nodeCertFileName := utils.CertNodeCAName(orderer.Name, orderer.Domain, node.Name)
		if err = c.mkMspDir(league, path.Join(nodePath, "msp"), rootCACertFileName, rootTLSCACertFileName, admins, &userCrypto{
			skiFileName:  nodeSKIFileName,
			certFileName: nodeCertFileName,
			tlsPath:      path.Join(nodePath, "tls"),
			isUser:       false,
			Crypto:       node.Crypto,
		}); nil != err {
			return err
		}
	}
	return nil
}

func (c *Config) mkPeerDir(league *config.League, org *config.Org) error {
	var (
		admins []*adminCrypto
		err    error
	)
	if nil == org || gnomon.String().IsEmpty(org.Domain) || gnomon.String().IsEmpty(org.Name) ||
		gnomon.String().IsEmpty(org.Username) || len(org.Users) == 0 {
		return nil
	}

	orgPath := utils.CryptoOrgPath(league.Domain, org.Domain, org.Name, true)
	rootCACertFileName := utils.RootCACertFileName(league.Domain)
	rootTLSCACertFileName := utils.RootTLSCACertFileName(league.Domain)

	for _, user := range org.Users {
		_, userPath := utils.CryptoOrgAndUserPath(league.Domain, org.Domain, org.Name, user.Name, true)
		if err = os.MkdirAll(orgPath, 0755); gnomon.File().PathExists(userPath) && nil != err {
			return err
		}
		userSKIFileName, err := utils.SKI(league.Domain, org.Domain, org.Name, user.Name, true, user.Crypto.Key)
		if nil != err {
			return err
		}
		userCertFileName := utils.CertUserCAName(org.Name, org.Domain, user.Name)
		if err = c.mkMspDir(league, path.Join(userPath, "msp"), rootCACertFileName, rootTLSCACertFileName, nil, &userCrypto{
			skiFileName:  userSKIFileName,
			certFileName: userCertFileName,
			tlsPath:      path.Join(userPath, "tls"),
			isUser:       true,
			Crypto:       user.Crypto,
		}); nil != err {
			return err
		}
		if user.IsAdmin {
			admins = append(admins, &adminCrypto{certFileName: userCertFileName, certBytes: user.Crypto.Cert})
		}
	}

	if err = os.MkdirAll(orgPath, 0755); gnomon.File().PathExists(orgPath) && nil != err {
		return err
	}
	if err = c.mkOrgDir(league, orgPath, "peers", rootCACertFileName, rootTLSCACertFileName, admins); nil != err {
		return err
	}
	for _, peer := range org.Peers {
		_, peerPath := utils.CryptoOrgAndNodePath(league.Domain, org.Domain, org.Name, peer.Name, false)
		peerSKIFileName, err := utils.SKI(league.Domain, org.Domain, org.Name, peer.Name, false, peer.Crypto.Key)
		if nil != err {
			return err
		}
		peerCertFileName := utils.CertNodeCAName(org.Name, org.Domain, peer.Name)
		if err = c.mkMspDir(league, path.Join(peerPath, "msp"), rootCACertFileName, rootTLSCACertFileName, admins, &userCrypto{
			skiFileName:  peerSKIFileName,
			certFileName: peerCertFileName,
			tlsPath:      path.Join(peerPath, "tls"),
			isUser:       false,
			Crypto:       peer.Crypto,
		}); nil != err {
			return err
		}
	}
	return nil
}

func (c *Config) mkOrgDir(league *config.League, orgPath, orgs, rootCACertFileName, rootTLSCACertFileName string, admins []*adminCrypto) error {
	var err error
	caPath := path.Join(orgPath, "ca")
	mspPath := path.Join(orgPath, "msp")
	orgsPath := path.Join(orgPath, orgs)
	tlscaPath := path.Join(orgPath, "tlsca")
	usersPath := path.Join(orgPath, "users")

	if err = os.Mkdir(caPath, 0755); !gnomon.File().PathExists(caPath) && nil != err {
		return err
	}
	if err = os.Mkdir(mspPath, 0755); !gnomon.File().PathExists(mspPath) && nil != err {
		return err
	}
	if err = os.Mkdir(orgsPath, 0755); !gnomon.File().PathExists(orgsPath) && nil != err {
		return err
	}
	if err = os.Mkdir(tlscaPath, 0755); !gnomon.File().PathExists(tlscaPath) && nil != err {
		return err
	}
	if err = os.Mkdir(usersPath, 0755); !gnomon.File().PathExists(usersPath) && nil != err {
		return err
	}

	if _, err := gnomon.File().Append(filepath.Join(caPath, rootCACertFileName), league.CertBytes, true); nil != err {
		return fmt.Errorf("ca cert set error: %w", err)
	}
	if _, err := gnomon.File().Append(filepath.Join(tlscaPath, rootTLSCACertFileName), league.TlsCertBytes, true); nil != err {
		return fmt.Errorf("tls ca cert set error: %w", err)
	}

	return c.mkMspDir(league, mspPath, rootCACertFileName, rootTLSCACertFileName, admins, nil)
}

func (c *Config) mkMspDir(league *config.League, mspPath, rootCACertFileName, rootTLSCACertFileName string, admins []*adminCrypto, user *userCrypto) error {
	var err error
	admincertsPath := path.Join(mspPath, "admincerts")
	cacertsPath := path.Join(mspPath, "cacerts")
	tlscacertsPath := path.Join(mspPath, "tlscacerts")
	if err = os.Mkdir(admincertsPath, 0755); !gnomon.File().PathExists(admincertsPath) && nil != err {
		return err
	}
	if err = os.Mkdir(cacertsPath, 0755); !gnomon.File().PathExists(cacertsPath) && nil != err {
		return err
	}
	if err = os.Mkdir(tlscacertsPath, 0755); !gnomon.File().PathExists(tlscacertsPath) && nil != err {
		return err
	}

	if _, err := gnomon.File().Append(filepath.Join(cacertsPath, rootCACertFileName), league.CertBytes, true); nil != err {
		return fmt.Errorf("ca cert set error: %w", err)
	}
	if _, err := gnomon.File().Append(filepath.Join(tlscacertsPath, rootTLSCACertFileName), league.TlsCertBytes, true); nil != err {
		return fmt.Errorf("tls ca cert set error: %w", err)
	}

	if nil != user {
		keystorePath := path.Join(mspPath, "keystore")
		signcertsPath := path.Join(mspPath, "signcerts")
		if err = os.Mkdir(keystorePath, 0755); !gnomon.File().PathExists(keystorePath) && nil != err {
			return err
		}
		if err = os.Mkdir(signcertsPath, 0755); !gnomon.File().PathExists(signcertsPath) && nil != err {
			return err
		}

		if _, err := gnomon.File().Append(filepath.Join(keystorePath, user.skiFileName), user.Crypto.Key, true); nil != err {
			return fmt.Errorf("user key set error: %w", err)
		}

		if _, err := gnomon.File().Append(filepath.Join(admincertsPath, user.certFileName), user.Crypto.Cert, true); nil != err {
			return fmt.Errorf("admin ca cert set error: %w", err)
		}
		if user.isUser {
			if _, err := gnomon.File().Append(filepath.Join(signcertsPath, user.certFileName), user.Crypto.Cert, true); nil != err {
				return fmt.Errorf("user ca cert set error: %w", err)
			}
		} else {
			for _, admin := range admins {
				if _, err := gnomon.File().Append(filepath.Join(admincertsPath, admin.certFileName), admin.certBytes, true); nil != err {
					return fmt.Errorf("admin ca cert set error: %w", err)
				}
			}
		}
		return c.mkTlsDir(league, user)
	} else {
		for _, admin := range admins {
			if _, err := gnomon.File().Append(filepath.Join(admincertsPath, admin.certFileName), admin.certBytes, true); nil != err {
				return fmt.Errorf("admin ca cert set error: %w", err)
			}
		}
	}

	return nil
}

func (c *Config) mkTlsDir(league *config.League, user *userCrypto) error {
	if _, err := gnomon.File().Append(filepath.Join(user.tlsPath, "ca.crt"), league.TlsCertBytes, true); nil != err {
		return fmt.Errorf("root ca cert set error: %w", err)
	}
	tlsCryptoName := "server"
	if user.isUser {
		tlsCryptoName = "client"
	}
	tlsKeyFilePath := filepath.Join(user.tlsPath, strings.Join([]string{tlsCryptoName, "key"}, "."))
	if _, err := gnomon.File().Append(tlsKeyFilePath, user.Crypto.TlsKey, true); nil != err {
		return fmt.Errorf("tls ca key set error: %w", err)
	}
	tlsCertFilePath := filepath.Join(user.tlsPath, strings.Join([]string{tlsCryptoName, "crt"}, "."))
	if _, err := gnomon.File().Append(tlsCertFilePath, user.Crypto.TlsCert, true); nil != err {
		return fmt.Errorf("root ca cert set error: %w", err)
	}
	return nil
}
