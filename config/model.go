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

import "github.com/aberic/fabric-client-go/grpc/proto/config"

// CaCrypto CaCrypto
type CaCrypto struct {
	*config.Crypto
	EnrollID, EnrollSecret          string
	LeagueDomain                    string
	OrgDomain, OrgName              string
	Username                        string
	IsAdmin                         bool
	CaName, URL                     string
	RootCertBytes, RootTLSCertBytes []byte
}

type orgCrypto struct {
	caCertFileName, tlsCaCertFileName string
	caCertBytes, tlsCaCertBytes       []byte
}

type userCrypto struct {
	skiFileName  string
	certFileName string
	tlsPath      string
	isUser       bool
	*config.Crypto
}

type adminCrypto struct {
	certFileName string
	certBytes    []byte
}

// Order Order
type Order struct {
	OrgName  string
	UserName string
}

// Org Org
type Org struct {
	OrgName  string
	UserName string
}
