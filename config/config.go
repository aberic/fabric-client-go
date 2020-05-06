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
	"sync"
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
	lock                   sync.RWMutex
}

// ObtainOrders ObtainOrders
func (c *Config) ObtainOrders() ([]*Order, []*Org) {
	var orders []*Order
	var orgs []*Org
	for orgName, organization := range c.Organizations {
		if organization.Peers == nil {
			for userName := range organization.Users {
				orders = append(orders, &Order{OrgName: orgName, UserName: userName})
			}
		} else {
			for userName, user := range organization.Users {
				if user.IsAdmin {
					orgs = append(orgs, &Org{OrgName: orgName, UserName: userName})
				}
			}
		}
	}
	return orders, orgs
}

func (c *Config) padding(configSet *config.ReqConfigSet) (*config.RespConfigSet, error) {
	var err error
	if gnomon.StringIsEmpty(configSet.Version) {
		err = errors.New("version can't be nil")
		goto ERR
	}
	if nil == configSet.Org || gnomon.StringIsEmpty(configSet.Org.Domain) || gnomon.StringIsEmpty(configSet.Org.Name) ||
		gnomon.StringIsEmpty(configSet.Org.Username) {
		err = errors.New("org or org require params can't be nil")
		return &config.RespConfigSet{Code: config.Code_Fail, ErrMsg: err.Error()}, err
	}
	c.Version = configSet.Version
	if err = c.setClient(configSet); nil != err {
		goto ERR
	}
	c.setChannels(configSet)
	if err = c.setOrganizations(configSet); nil != err {
		goto ERR
	}
	if err = c.setOrderers(configSet); nil != err {
		goto ERR
	}
	if err = c.setPeers(configSet); nil != err {
		goto ERR
	}
	if err = c.setCertificateAuthorities(configSet); nil != err {
		goto ERR
	}
	return &config.RespConfigSet{Code: config.Code_Success}, nil
ERR:
	err = fmt.Errorf("config set error: %e", err)
	return &config.RespConfigSet{Code: config.Code_Fail, ErrMsg: err.Error()}, err
}

func (c *Config) set(configSet *config.ReqConfigSet) (resp *config.RespConfigSet, err error) {
	if resp, err = c.padding(configSet); nil != err {
		return
	}
	if err = c.mkAllDir(configSet); nil != err {
		err = fmt.Errorf("config set error: %e", err)
		return &config.RespConfigSet{Code: config.Code_Fail, ErrMsg: err.Error()}, err
	}
	return
}

func (c *Config) setClient(configSet *config.ReqConfigSet) error {
	client, orgUserPath, err := NewConfigClient(configSet.LeagueDomain, configSet.Org)
	if nil != err {
		return fmt.Errorf("client set error: %e", err)
	}
	client.set(configSet.Client, orgUserPath)
	c.Client = client
	return nil
}

func (c *Config) setChannels(configSet *config.ReqConfigSet) {
	c.Channels = make(map[string]*Channel)
	c.Channels["_default"] = NewConfigChannel()
	for channelName, channel := range configSet.Channels {
		ch := NewConfigChannel()
		ch.set(configSet.Org, channel)
		c.Channels[channelName] = ch
	}
}

func (c *Config) setOrganizations(configSet *config.ReqConfigSet) error {
	c.Organizations = make(map[string]*Organization)
	// 设置orderer
	if nil != configSet.Orderer {
		orderer := &Organization{}
		if err := orderer.setOrderer(configSet.LeagueDomain, configSet.Orderer); nil != err {
			return err
		}
		c.Organizations[configSet.Orderer.Name] = orderer
	}
	// 设置org
	org := &Organization{}
	if err := org.setOrg(configSet.LeagueDomain, configSet.Org); nil != err {
		return err
	}
	c.Organizations[configSet.Org.Name] = org
	return nil
}

func (c *Config) setOrderers(configSet *config.ReqConfigSet) error {
	c.Orderers = make(map[string]*Orderer)
	if nil != configSet.Orderer {
		for _, node := range configSet.Orderer.Nodes {
			order := &Orderer{GRPCOptions: &OrdererGRPCOptions{}, TLSCACerts: &OrdererTLSCACerts{}}
			if err := order.set(configSet.LeagueDomain, configSet.Orderer, node); nil != err {
				return fmt.Errorf("orderers set error: %e", err)
			}
			c.Orderers[node.Name] = order
		}
	}
	return nil
}

func (c *Config) setPeers(configSet *config.ReqConfigSet) error {
	c.Peers = make(map[string]*Peer)
	if nil != configSet.Org {

	}
	for _, peer := range configSet.Org.Peers {
		p := &Peer{GRPCOptions: &PeerGRPCOptions{}, TLSCACerts: &PeerTLSCACerts{}}
		if err := p.set(configSet.LeagueDomain, configSet.Org, peer); nil != err {
			return fmt.Errorf("peers set error: %e", err)
		}
		c.Peers[peer.Name] = p
	}
	return nil
}

func (c *Config) setCertificateAuthorities(configSet *config.ReqConfigSet) error {
	c.CertificateAuthorities = make(map[string]*CertificateAuthority)
	for _, certificateAuthority := range configSet.Org.Cas {
		ca := &CertificateAuthority{
			TLSCACerts: &CertificateAuthorityTLSCACerts{Client: &CertificateAuthorityTLSCACertsClient{
				Key:  &CertificateAuthorityTLSCACertsClientKey{},
				Cert: &CertificateAuthorityTLSCACertsClientCert{},
			}},
			Registrar: &CertificateAuthorityRegistrar{},
		}
		if err := ca.set(configSet.LeagueDomain, configSet.Org, certificateAuthority); nil != err {
			return fmt.Errorf("ca set error: %e", err)
		}
		c.CertificateAuthorities[certificateAuthority.Name] = ca
	}
	return nil
}

// mkAllDir 创建crypto相关文件及信息，按照fabric的官方模板和格式
//
// 优先创建用户相关证书信息，以便后续创建组织和组织子节点内容时拷贝
func (c *Config) mkAllDir(configSet *config.ReqConfigSet) error {
	if err := c.mkOrdererDir(configSet.LeagueDomain, configSet.Orderer); nil != err {
		return err
	}
	return c.mkPeerDir(configSet.LeagueDomain, configSet.Org)
}

func (c *Config) mkOrdererDir(leagueDomain string, orderer *config.Orderer) error {
	var (
		admins []*adminCrypto
		err    error
	)
	if nil == orderer || gnomon.StringIsEmpty(orderer.Domain) || gnomon.StringIsEmpty(orderer.Name) ||
		gnomon.StringIsEmpty(orderer.Username) || nil == orderer.User {
		return nil
	}
	orgPath, userPath := utils.CryptoOrgAndUserPath(leagueDomain, orderer.Domain, orderer.Name, orderer.Username, false)
	rootCACertFileName := utils.RootOrgCACertFileName(orderer.Name, orderer.Domain)
	rootTLSCACertFileName := utils.RootOrgTLSCACertFileName(orderer.Name, orderer.Domain)
	orgCrypto := &orgCrypto{
		caCertFileName:    rootCACertFileName,
		caCertBytes:       orderer.CertBytes,
		tlsCaCertFileName: rootTLSCACertFileName,
		tlsCaCertBytes:    orderer.TlsCertBytes,
	}

	if err = os.MkdirAll(userPath, 0755); !gnomon.FilePathExists(userPath) && nil != err {
		return err
	}
	//userSKIFileName, err := utils.SKI(leagueDomain, orderer.Domain, orderer.Name, orderer.Username, true, orderer.User.Crypto.Key)
	//if nil != err {
	//	return err
	//}
	userCertFileName := utils.CertUserCAName(orderer.Name, orderer.Domain, orderer.User.Name)
	if err = c.mkMspDir(path.Join(userPath, "msp"), nil, orgCrypto, &userCrypto{
		skiFileName:  "ca_sk",
		certFileName: userCertFileName,
		tlsPath:      path.Join(userPath, "tls"),
		isUser:       true,
		Crypto:       orderer.User.Crypto,
	}); nil != err {
		return err
	}
	admins = append(admins, &adminCrypto{certFileName: userCertFileName, certBytes: orderer.User.Crypto.Cert})

	if err = c.mkOrgDir(orgPath, "orderers", admins, orgCrypto); nil != err {
		return err
	}
	for _, node := range orderer.Nodes {
		_, nodePath := utils.CryptoOrgAndNodePath(leagueDomain, orderer.Domain, orderer.Name, node.Name, false)
		//nodeSKIFileName, err := utils.SKI(leagueDomain, orderer.Domain, orderer.Name, node.Name, false, node.Crypto.Key)
		//if nil != err {
		//	return err
		//}
		nodeCertFileName := utils.CertNodeCAName(orderer.Name, orderer.Domain, node.Name)
		if err = c.mkMspDir(path.Join(nodePath, "msp"), admins, orgCrypto, &userCrypto{
			skiFileName:  "ca_sk",
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

func (c *Config) mkPeerDir(leagueDomain string, org *config.Org) error {
	var (
		admins []*adminCrypto
		err    error
	)
	if nil == org || gnomon.StringIsEmpty(org.Domain) || gnomon.StringIsEmpty(org.Name) ||
		gnomon.StringIsEmpty(org.Username) || len(org.Users) == 0 {
		return nil
	}

	orgPath := utils.CryptoOrgPath(leagueDomain, org.Domain, org.Name, true)
	rootCACertFileName := utils.RootOrgCACertFileName(org.Name, org.Domain)
	rootTLSCACertFileName := utils.RootOrgTLSCACertFileName(org.Name, org.Domain)
	orgCrypto := &orgCrypto{
		caCertFileName:    rootCACertFileName,
		caCertBytes:       org.CertBytes,
		tlsCaCertFileName: rootTLSCACertFileName,
		tlsCaCertBytes:    org.TlsCertBytes,
	}

	for _, user := range org.Users {
		_, userPath := utils.CryptoOrgAndUserPath(leagueDomain, org.Domain, org.Name, user.Name, true)
		if err = os.MkdirAll(orgPath, 0755); gnomon.FilePathExists(userPath) && nil != err {
			return err
		}
		//userSKIFileName, err := utils.SKI(leagueDomain, org.Domain, org.Name, user.Name, true, user.Crypto.Key)
		//if nil != err {
		//	return err
		//}
		userCertFileName := utils.CertUserCAName(org.Name, org.Domain, user.Name)
		if err = c.mkMspDir(path.Join(userPath, "msp"), nil, orgCrypto, &userCrypto{
			skiFileName:  "ca_sk",
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

	if err = os.MkdirAll(orgPath, 0755); gnomon.FilePathExists(orgPath) && nil != err {
		return err
	}
	if err = c.mkOrgDir(orgPath, "peers", admins, orgCrypto); nil != err {
		return err
	}
	for _, peer := range org.Peers {
		_, peerPath := utils.CryptoOrgAndNodePath(leagueDomain, org.Domain, org.Name, peer.Name, true)
		//peerSKIFileName, err := utils.SKI(leagueDomain, org.Domain, org.Name, peer.Name, false, peer.Crypto.Key)
		//if nil != err {
		//	return err
		//}
		peerCertFileName := utils.CertNodeCAName(org.Name, org.Domain, peer.Name)
		if err = c.mkMspDir(path.Join(peerPath, "msp"), admins, orgCrypto, &userCrypto{
			skiFileName:  "ca_sk",
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

func (c *Config) mkOrgDir(orgPath, orgs string, admins []*adminCrypto, org *orgCrypto) error {
	var err error
	caPath := path.Join(orgPath, "ca")
	mspPath := path.Join(orgPath, "msp")
	orgsPath := path.Join(orgPath, orgs)
	tlscaPath := path.Join(orgPath, "tlsca")
	usersPath := path.Join(orgPath, "users")

	if err = os.Mkdir(caPath, 0755); !gnomon.FilePathExists(caPath) && nil != err {
		return err
	}
	if err = os.Mkdir(mspPath, 0755); !gnomon.FilePathExists(mspPath) && nil != err {
		return err
	}
	if err = os.Mkdir(orgsPath, 0755); !gnomon.FilePathExists(orgsPath) && nil != err {
		return err
	}
	if err = os.Mkdir(tlscaPath, 0755); !gnomon.FilePathExists(tlscaPath) && nil != err {
		return err
	}
	if err = os.Mkdir(usersPath, 0755); !gnomon.FilePathExists(usersPath) && nil != err {
		return err
	}

	if _, err := gnomon.FileAppend(filepath.Join(caPath, org.caCertFileName), org.caCertBytes, true); nil != err {
		return fmt.Errorf("ca cert set error: %e", err)
	}
	if _, err := gnomon.FileAppend(filepath.Join(tlscaPath, org.tlsCaCertFileName), org.tlsCaCertBytes, true); nil != err {
		return fmt.Errorf("tls ca cert set error: %e", err)
	}

	return c.mkMspDir(mspPath, admins, org, nil)
}

func (c *Config) mkMspDir(mspPath string, admins []*adminCrypto, org *orgCrypto, user *userCrypto) error {
	var err error
	admincertsPath := path.Join(mspPath, "admincerts")
	cacertsPath := path.Join(mspPath, "cacerts")
	tlscacertsPath := path.Join(mspPath, "tlscacerts")
	if err = os.MkdirAll(mspPath, 0755); !gnomon.FilePathExists(mspPath) && nil != err {
		return err
	}
	if err = os.Mkdir(admincertsPath, 0755); !gnomon.FilePathExists(admincertsPath) && nil != err {
		return err
	}
	if err = os.Mkdir(cacertsPath, 0755); !gnomon.FilePathExists(cacertsPath) && nil != err {
		return err
	}
	if err = os.Mkdir(tlscacertsPath, 0755); !gnomon.FilePathExists(tlscacertsPath) && nil != err {
		return err
	}

	if _, err := gnomon.FileAppend(filepath.Join(cacertsPath, org.caCertFileName), org.caCertBytes, true); nil != err {
		return fmt.Errorf("ca cert set error: %e", err)
	}
	if _, err := gnomon.FileAppend(filepath.Join(tlscacertsPath, org.tlsCaCertFileName), org.tlsCaCertBytes, true); nil != err {
		return fmt.Errorf("tls ca cert set error: %e", err)
	}

	if nil == user {
		for _, admin := range admins {
			if _, err := gnomon.FileAppend(filepath.Join(admincertsPath, admin.certFileName), admin.certBytes, true); nil != err {
				return fmt.Errorf("admin ca cert set error: %e", err)
			}
		}
	} else {
		keystorePath := path.Join(mspPath, "keystore")
		signcertsPath := path.Join(mspPath, "signcerts")
		if err = os.Mkdir(keystorePath, 0755); !gnomon.FilePathExists(keystorePath) && nil != err {
			return err
		}
		if err = os.Mkdir(signcertsPath, 0755); !gnomon.FilePathExists(signcertsPath) && nil != err {
			return err
		}

		if _, err := gnomon.FileAppend(filepath.Join(keystorePath, user.skiFileName), user.Crypto.Key, true); nil != err {
			return fmt.Errorf("user key set error: %e", err)
		}

		if _, err := gnomon.FileAppend(filepath.Join(signcertsPath, user.certFileName), user.Crypto.Cert, true); nil != err {
			return fmt.Errorf("user ca cert set error: %e", err)
		}
		if user.isUser {
			if _, err := gnomon.FileAppend(filepath.Join(admincertsPath, user.certFileName), user.Crypto.Cert, true); nil != err {
				return fmt.Errorf("admin ca cert set error: %e", err)
			}
		} else {
			for _, admin := range admins {
				if _, err := gnomon.FileAppend(filepath.Join(admincertsPath, admin.certFileName), admin.certBytes, true); nil != err {
					return fmt.Errorf("admin ca cert set error: %e", err)
				}
			}
		}
		return c.mkTLSDir(org, user)
	}

	return nil
}

func (c *Config) mkTLSDir(org *orgCrypto, user *userCrypto) error {
	if _, err := gnomon.FileAppend(filepath.Join(user.tlsPath, "ca.crt"), org.tlsCaCertBytes, true); nil != err {
		return fmt.Errorf("root ca cert set error: %e", err)
	}
	tlsCryptoName := "server"
	if user.isUser {
		tlsCryptoName = "client"
	}
	tlsKeyFilePath := filepath.Join(user.tlsPath, strings.Join([]string{tlsCryptoName, "key"}, "."))
	if _, err := gnomon.FileAppend(tlsKeyFilePath, user.Crypto.TlsKey, true); nil != err {
		return fmt.Errorf("tls ca key set error: %e", err)
	}
	tlsCertFilePath := filepath.Join(user.tlsPath, strings.Join([]string{tlsCryptoName, "crt"}, "."))
	if _, err := gnomon.FileAppend(tlsCertFilePath, user.Crypto.TlsCert, true); nil != err {
		return fmt.Errorf("root ca cert set error: %e", err)
	}
	return nil
}
