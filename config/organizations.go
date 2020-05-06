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

// Organization 此网络的参与机构
type Organization struct {
	MspID      string           `yaml:"mspid"`
	CryptoPath string           `yaml:"cryptoPath"` // CryptoPath 这个组织的MSP存储(绝对路径或相对于client.cryptoconfig)
	Users      map[string]*User `yaml:"users,omitempty"`
	Peers      []string         `yaml:"peers,omitempty"`
	// CertificateAuthorities
	//
	// 在基于Fabric的网络中，证书颁发机构颁发证书用于身份验证
	//
	// 通常，证书供应是在运行时网络之外的独立进程中完成的
	//
	// ca是一个特殊的证书颁发机构，它为动态证书管理(注册、撤销、重新注册)提供了REST api
	//
	// CertificateAuthorities只针对fabric-ca服务
	CertificateAuthorities []string `yaml:"certificateAuthorities,omitempty"`
}

// User User
type User struct {
	IsAdmin bool
	Key     *Key  `yaml:"key"`
	Cert    *Cert `yaml:"cert"`
}

// Key Key
type Key struct {
	Path string `yaml:"path"`
}

// Cert Cert
type Cert struct {
	Path string `yaml:"path"`
}

func (o *Organization) setOrderer(leagueDomain string, orderer *config.Orderer) error {
	if nil == orderer.User || len(orderer.Nodes) <= 0 {
		return errors.New("node or user can't be empty")
	}
	if gnomon.StringIsNotEmpty(orderer.MspID) {
		o.MspID = orderer.MspID
	} else {
		o.MspID = utils.MspID(orderer.Name)
	}
	_, userPath := utils.CryptoOrgAndUserPath(leagueDomain, orderer.Domain, orderer.Name, orderer.Username, false)
	o.CryptoPath = path.Join(userPath, "msp")
	o.Users = map[string]*User{}
	userPemFileName := utils.CertUserCAName(orderer.Name, orderer.Domain, orderer.Username)
	o.Users[orderer.Username] = &User{
		IsAdmin: true,
		Key:     &Key{Path: filepath.Join(userPath, "msp", "keystore", "ca_sk")},
		Cert:    &Cert{Path: filepath.Join(userPath, "msp", "signcerts", userPemFileName)},
	}
	return nil
}

func (o *Organization) setOrg(leagueDomain string, org *config.Org) error {
	if len(org.Peers) <= 0 || len(org.Users) <= 0 {
		return errors.New("peer or user can't be empty")
	}
	if gnomon.StringIsNotEmpty(org.MspID) {
		o.MspID = org.MspID
	} else {
		o.MspID = utils.MspID(org.Name)
	}
	_, userPath := utils.CryptoOrgAndUserPath(leagueDomain, org.Domain, org.Name, org.Username, true)
	o.CryptoPath = path.Join(userPath, "msp")
	o.Peers = []string{}
	for _, peer := range org.Peers {
		o.Peers = append(o.Peers, peer.Name)
	}
	o.Users = map[string]*User{}
	for _, user := range org.Users {
		_, userPath := utils.CryptoOrgAndUserPath(leagueDomain, org.Domain, org.Name, user.Name, true)
		userPemFileName := utils.CertUserCAName(org.Name, org.Domain, user.Name)
		o.Users[user.Name] = &User{
			IsAdmin: user.IsAdmin,
			Key:     &Key{Path: filepath.Join(userPath, "msp", "keystore", "ca_sk")},
			Cert:    &Cert{Path: filepath.Join(userPath, "msp", "signcerts", userPemFileName)},
		}
	}
	o.CertificateAuthorities = []string{}
	for _, ca := range org.Cas {
		o.CertificateAuthorities = append(o.CertificateAuthorities, ca.Name)
	}
	return nil
}
