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

package ca

import (
	"github.com/aberic/fabric-client-go/grpc/proto/ca"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var (
	algorithm = &ca.CryptoConfig_EccAlgorithm{
		EccAlgorithm: ca.EccAlgorithm_p256,
	}
)

func Test_all(t *testing.T) {
	leagueDomain := "league.com"
	for i := 1; i < 4; i++ {
		orgName := strings.Join([]string{"orderer", strconv.Itoa(i)}, "")
		orgDomain := strings.Join([]string{"example", strconv.Itoa(i), ".com"}, "")
		// 生成组织根信息
		testOrg(leagueDomain, orgName, orgDomain, true, t)
	}
	for i := 1; i < 4; i++ {
		orgName := strings.Join([]string{"org", strconv.Itoa(i)}, "")
		orgDomain := strings.Join([]string{"example", strconv.Itoa(i), ".com"}, "")
		// 生成组织根信息
		testOrg(leagueDomain, orgName, orgDomain, false, t)
	}
}

func Test_generateOrgRootCrypto(t *testing.T) {
	testOrg("test", "a", "b.com", false, t)
}

func testOrg(leagueDomain, orgName, orgDomain string, isOrder bool, t *testing.T) {
	org, err := generateRootCrypto(&ca.ReqRootCrypto{
		Name:   orgName,
		Domain: orgDomain,
		Subject: &ca.Subject{
			Country:       "CN",
			Province:      "Hubei",
			Locality:      "Yichang",
			OrgUnit:       orgName,
			StreetAddress: "Shengli road",
			PostalCode:    "443000",
		},
		Config: &ca.CryptoConfig{
			CryptoType:    ca.CryptoType_ECDSA,
			Algorithm:     algorithm,
			SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
		},
		TlsConfig: &ca.CryptoConfig{
			CryptoType:    ca.CryptoType_ECDSA,
			Algorithm:     algorithm,
			SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
		},
	})
	if nil != err {
		t.Fatal(err)
	}
	t.Log(org)
	testStoreOrg(leagueDomain, orgName, orgDomain, org, t)

	if isOrder {
		for j := 0; j < 3; j++ {
			childName := strings.Join([]string{"order", strconv.Itoa(j)}, "")
			// 生成组织子项目根信息
			testChild(leagueDomain, orgName, orgDomain, childName, false, org.CertBytes, org.PriKeyBytes, org.TlsCertBytes, org.TlsPriKeyBytes, t)
		}
		for j := 0; j < 3; j++ {
			var childName string
			if j == 0 {
				childName = "Admin"
			} else {
				childName = strings.Join([]string{"User", strconv.Itoa(j)}, "")
			}
			// 生成组织子项目根信息
			testChild(leagueDomain, orgName, orgDomain, childName, true, org.CertBytes, org.PriKeyBytes, org.TlsCertBytes, org.TlsPriKeyBytes, t)
		}
	} else {
		for j := 0; j < 3; j++ {
			childName := strings.Join([]string{"peer", strconv.Itoa(j)}, "")
			// 生成组织子项目根信息
			testChild(leagueDomain, orgName, orgDomain, childName, false, org.CertBytes, org.PriKeyBytes, org.TlsCertBytes, org.TlsPriKeyBytes, t)
		}
		for j := 0; j < 3; j++ {
			var childName string
			if j == 0 {
				childName = "Admin"
			} else {
				childName = strings.Join([]string{"User", strconv.Itoa(j)}, "")
			}
			// 生成组织子项目根信息
			testChild(leagueDomain, orgName, orgDomain, childName, true, org.CertBytes, org.PriKeyBytes, org.TlsCertBytes, org.TlsPriKeyBytes, t)
		}
	}
}

func testStoreOrg(leagueDomain, orgName, orgDomain string, orc *ca.RespRootCrypto, t *testing.T) {
	orgRootFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."))
	certFileName := strings.Join([]string{"ca.", orgName, ".", orgDomain, "-cert.pem"}, "")
	priKeyFileName := "ca.key"
	pubKeyFileName := "ca.pub"
	caCertFileName := "ca.crt"
	tlsPriKeyFileName := "tls.key"
	tlsPubKeyFileName := "tls.pub"
	tlsCaCertFileName := "tls.crt"
	tlsCertFileName := strings.Join([]string{"tlsca.", orgName, ".", orgDomain, "-cert.pem"}, "")
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, priKeyFileName), orc.PriKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, pubKeyFileName), orc.PubKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, certFileName), orc.CertBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, caCertFileName), orc.CertBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, tlsPriKeyFileName), orc.TlsPriKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, tlsPubKeyFileName), orc.TlsPubKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, tlsCertFileName), orc.TlsCertBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, tlsCaCertFileName), orc.TlsCertBytes, true); nil != err {
		t.Fatal(err)
	}
}

func testChild(leagueDomain, orgName, orgDomain, childName string, isUser bool, rootCertBytes, priParentBytes, rootTlsCertBytes, tlsPriParentBytes []byte, t *testing.T) {
	childRootFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."), childName)
	// ca
	crypto, err := generateCrypto(&ca.ReqCrypto{
		Config: &ca.CryptoConfig{
			CryptoType:    ca.CryptoType_ECDSA,
			Algorithm:     algorithm,
			SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
		},
	})
	if nil != err {
		t.Fatal(err)
	}
	t.Log(crypto)
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "ca.key"), crypto.PriKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "ca.pub"), crypto.PubKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	// tls ca
	tlsCrypto, err := generateCrypto(&ca.ReqCrypto{
		Config: &ca.CryptoConfig{
			CryptoType:    ca.CryptoType_ECDSA,
			Algorithm:     algorithm,
			SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
		},
	})
	if nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "tls.key"), tlsCrypto.PriKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "tls.pub"), tlsCrypto.PubKeyBytes, true); nil != err {
		t.Fatal(err)
	}

	// 签名 ca 证书
	testSignCA(leagueDomain, orgName, orgDomain, childName, isUser, false, rootCertBytes, priParentBytes, crypto.PubKeyBytes, t)
	// 签名 tls ca 证书
	testSignCA(leagueDomain, orgName, orgDomain, childName, isUser, true, rootTlsCertBytes, tlsPriParentBytes, tlsCrypto.PubKeyBytes, t)
}

func testSignCA(leagueDomain, orgName, orgDomain, childName string, isUser, isTls bool, rootTlsCertBytes, tlsPriParentBytes, tlsPubBytes []byte, t *testing.T) {
	var (
		certFileName string
		respSC       *ca.RespSignCertificate
		err          error
	)
	if respSC, err = signCertificate(&ca.ReqSignCertificate{
		OrgName:         orgName,
		OrgDomain:       orgDomain,
		ChildName:       childName,
		IsUser:          isUser,
		ParentCertBytes: rootTlsCertBytes,
		ParentPriBytes:  tlsPriParentBytes,
		PubBytes:        tlsPubBytes,
		Subject: &ca.Subject{
			Country:  "CN",
			Province: "Beijing",
			Locality: "Beijing",
			OrgUnit:  childName,
		},
		SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
	}); nil != err {
		t.Error(err)
	}
	t.Log(string(respSC.CertBytes))
	childRootFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."), childName)
	if isTls {
		certFileName = "tls.crt"
	} else {
		certFileName = "ca.crt"
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, certFileName), respSC.CertBytes, true); nil != err {
		t.Fatal(err)
	}
}
