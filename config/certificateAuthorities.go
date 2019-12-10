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

type CertificateAuthority struct {
	URL        string                          `yaml:"url"`    // URL https://ca.org1.example.com:7054
	CAName     string                          `yaml:"caName"` // CAName 可选参数，name of the CA
	TLSCACerts *CertificateAuthorityTLSCACerts `yaml:"tlsCACerts"`
	Registrar  *CertificateAuthorityRegistrar  `yaml:"registrar"`
}

type CertificateAuthorityTLSCACerts struct {
	Path   string                                `yaml:"path"`
	Client *CertificateAuthorityTLSCACertsClient `yaml:"client"`
}

type CertificateAuthorityTLSCACertsClient struct {
	Key  *CertificateAuthorityTLSCACertsClientKey  `yaml:"key"`
	Cert *CertificateAuthorityTLSCACertsClientCert `yaml:"cert"`
}

type CertificateAuthorityTLSCACertsClientKey struct {
	Path string `yaml:"path"` // /fabric/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/tls/client.key
}

type CertificateAuthorityTLSCACertsClientCert struct {
	Path string `yaml:"path"` // /fabric/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com/tls/client.crt
}

type CertificateAuthorityRegistrar struct {
	EnrollId     string `yaml:"enrollId"`
	EnrollSecret string `yaml:"enrollSecret"`
}

func (c *CertificateAuthority) set(league *config.League, org *config.Org, ca *config.CertificateAuthority) error {
	if gnomon.String().IsNotEmpty(ca.Url) {
		c.URL = ca.Url
	} else {
		return errors.New("url can't be empty")
	}
	if gnomon.String().IsNotEmpty(ca.Name) {
		c.CAName = ca.Name
	} else {
		return errors.New("ca name can't be empty")
	}
	c.Registrar.EnrollId = ca.Registrar.EnrollId
	c.Registrar.EnrollSecret = ca.Registrar.EnrollSecret

	orgPath, userPath := utils.CryptoOrgAndUserPath(league.Domain, org.Domain, org.Name, ca.Username, true)
	rootTLSCACertFileName := utils.RootTLSCACertFileName(league.Domain)

	c.TLSCACerts.Path = filepath.Join(orgPath, "tlsca", rootTLSCACertFileName)
	c.TLSCACerts.Client.Key.Path = filepath.Join(userPath, "tls", "client.key")
	c.TLSCACerts.Client.Cert.Path = filepath.Join(userPath, "tls", "client.crt")
	return nil
}
