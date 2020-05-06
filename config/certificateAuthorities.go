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

// CertificateAuthority ca配置信息
type CertificateAuthority struct {
	URL        string                          `yaml:"url"`    // URL https://ca.org1.example.com:7054
	CAName     string                          `yaml:"caName"` // CAName 可选参数，name of the CA
	TLSCACerts *CertificateAuthorityTLSCACerts `yaml:"tlsCACerts"`
	Registrar  *CertificateAuthorityRegistrar  `yaml:"registrar"`
}

// CertificateAuthorityTLSCACerts ca CertificateAuthorityTLSCACerts
type CertificateAuthorityTLSCACerts struct {
	Path   string                                `yaml:"path"`
	Client *CertificateAuthorityTLSCACertsClient `yaml:"client"`
}

// CertificateAuthorityTLSCACertsClient ca CertificateAuthorityTLSCACertsClient
type CertificateAuthorityTLSCACertsClient struct {
	Key  *CertificateAuthorityTLSCACertsClientKey  `yaml:"key"`
	Cert *CertificateAuthorityTLSCACertsClientCert `yaml:"cert"`
}

// CertificateAuthorityTLSCACertsClientKey ca CertificateAuthorityTLSCACertsClientKey
type CertificateAuthorityTLSCACertsClientKey struct {
	Path string `yaml:"path"` // /fabric/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/tls/client.key
}

// CertificateAuthorityTLSCACertsClientCert ca CertificateAuthorityTLSCACertsClientCert
type CertificateAuthorityTLSCACertsClientCert struct {
	Path string `yaml:"path"` // /fabric/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/tls/client.crt
}

// CertificateAuthorityRegistrar ca CertificateAuthorityRegistrar
type CertificateAuthorityRegistrar struct {
	EnrollID     string `yaml:"enrollId"`     // EnrollID ca EnrollID
	EnrollSecret string `yaml:"enrollSecret"` // EnrollSecret ca EnrollSecret
}

func (c *CertificateAuthority) set(leagueDomain string, org *config.Org, ca *config.CertificateAuthority) error {
	if gnomon.StringIsNotEmpty(ca.Url) {
		c.URL = ca.Url
	} else {
		return errors.New("url can't be empty")
	}
	if gnomon.StringIsNotEmpty(ca.Name) {
		c.CAName = ca.Name
	} else {
		return errors.New("ca name can't be empty")
	}
	c.Registrar.EnrollID = ca.Registrar.EnrollId
	c.Registrar.EnrollSecret = ca.Registrar.EnrollSecret

	orgPath, userPath := utils.CryptoOrgAndUserPath(leagueDomain, org.Domain, org.Name, ca.Username, true)
	rootTLSCACertFileName := utils.RootTLSCACertFileName(leagueDomain)

	c.TLSCACerts.Path = filepath.Join(orgPath, "tlsca", rootTLSCACertFileName)
	c.TLSCACerts.Client.Key.Path = filepath.Join(userPath, "tls", "client.key")
	c.TLSCACerts.Client.Cert.Path = filepath.Join(userPath, "tls", "client.crt")
	return nil
}
