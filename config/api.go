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
	"github.com/aberic/fabric-client-go/grpc/proto/config"
)

func JustCA(caCrypto *CaCrypto) (*Config, error) {
	conf := Config{}
	if err := conf.set(&config.ReqConfigInit{
		Version: "1.0.0",
		League: &config.League{
			Domain:       caCrypto.LeagueDomain,
			CertBytes:    caCrypto.RootCertBytes,
			TlsCertBytes: caCrypto.RootTlsCertBytes,
		},
		Orderer: nil,
		Org: &config.Org{
			Domain:   caCrypto.OrgDomain,
			Name:     caCrypto.OrgName,
			Username: caCrypto.Username,
			Users: []*config.User{
				{
					Name:    caCrypto.Username,
					IsAdmin: caCrypto.IsAdmin,
					Crypto: &config.Crypto{
						Key:     caCrypto.Key,
						Cert:    caCrypto.Cert,
						TlsKey:  caCrypto.TlsKey,
						TlsCert: caCrypto.TlsCert,
					},
				},
			},
			Cas: []*config.CertificateAuthority{
				{
					Url:      caCrypto.URL,
					Name:     caCrypto.CaName,
					Username: caCrypto.Username,
					Registrar: &config.Registrar{
						EnrollId:     caCrypto.EnrollID,
						EnrollSecret: caCrypto.EnrollSecret,
					},
				},
			},
		},
		Client: &config.Client{
			Tls: true,
		},
	}); nil != err {
		return nil, err
	}
	return &conf, nil
}
