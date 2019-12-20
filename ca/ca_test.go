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
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/aberic/fabric-client-go/grpc/proto/ca"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"io/ioutil"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var (
	fabricCaURL = "https://127.0.0.1:7054"
	enrollID    = "admin"
	secret      = "adminpw"
	//caName      = "ca"
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
	if _, err := gnomon.File().Append(filepath.Join(orgRootFilePath, orc.SkName), orc.PriKeyBytes, true); nil != err {
		t.Fatal(err)
	}
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
	kc := &keyConfig{}
	skName, priKeyBytes, pubKeyBytes, err := kc.generateCryptoCA(childName)
	if nil != err {
		t.Fatal(err)
	}
	t.Log(skName)
	t.Log(string(priKeyBytes))
	t.Log(string(pubKeyBytes))
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, skName), priKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "ca.key"), priKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "ca.pub"), pubKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	// tls ca
	tlsPriKeyBytes, tlsPubKeyBytes, err := generateCryptoTlsCa(&ca.CryptoConfig{
		CryptoType:    ca.CryptoType_ECDSA,
		Algorithm:     algorithm,
		SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
	})
	if nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "tls.key"), tlsPriKeyBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "tls.pub"), tlsPubKeyBytes, true); nil != err {
		t.Fatal(err)
	}

	// 签名 ca 证书
	testSignCA1(leagueDomain, orgName, orgDomain, childName, isUser, rootCertBytes, priParentBytes, pubKeyBytes, t)
	// 签名 tls ca 证书
	testSignTlsCA(leagueDomain, orgName, orgDomain, childName, isUser, rootTlsCertBytes, tlsPriParentBytes, tlsPubKeyBytes, t)
}

func testSignCA(leagueDomain, orgName, orgDomain, childName string, isUser bool, pubBytes []byte, t *testing.T) {
	var (
		commonName, certFileName string
		cc                       = &CertConfig{}
	)
	caRootPath := path.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."))
	if isUser {
		commonName = utils.CertUserCANameWithOutCert(orgName, orgDomain, childName)
		certFileName = utils.CertUserCAName(orgName, orgDomain, childName)
	} else {
		commonName = utils.CertNodeCANameWithOutCert(orgName, orgDomain, childName)
		certFileName = utils.CertNodeCAName(orgName, orgDomain, childName)
	}
	pubKey, err := gnomon.CryptoECC().LoadPubPem([]byte(pubBytes))
	if nil != err {
		t.Fatal(err)
	}
	certBytes, err := cc.signCertificateCA(commonName, cc.getCA(caRootPath, &ca.Subject{
		Country:       "US",
		Province:      "Hebei",
		Locality:      "Yichun",
		OrgUnit:       childName,
		StreetAddress: "Sheng road",
		PostalCode:    "443002",
	}), pubKey)
	if nil != err {
		t.Fatal(err)
	}
	t.Log(string(certBytes))
	childRootFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."), childName)
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, certFileName), certBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "ca.crt"), certBytes, true); nil != err {
		t.Fatal(err)
	}
}

func testSignCA1(leagueDomain, orgName, orgDomain, childName string, isUser bool, rootTlsCertBytes, tlsPriParentBytes, tlsPubBytes []byte, t *testing.T) {
	var (
		commonName, certFileName string
		certBytes                []byte
		cc                       = &CertConfig{}
		err                      error
	)
	if isUser {
		commonName = utils.CertUserCANameWithOutCert(orgName, orgDomain, childName)
		certFileName = utils.CertUserCAName(orgName, orgDomain, childName)
	} else {
		commonName = utils.CertNodeCANameWithOutCert(orgName, orgDomain, childName)
		certFileName = utils.CertNodeCAName(orgName, orgDomain, childName)
	}
	if certBytes, err = cc.generateCryptoChildCrt(rootTlsCertBytes, tlsPriParentBytes, tlsPubBytes, pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{orgName},
		OrganizationalUnit: []string{childName},
		Locality:           []string{"Beijing"},
		Province:           []string{"Beijing"},
		CommonName:         commonName,
	}, x509.ECDSAWithSHA256); nil != err {
		t.Error(err)
	}
	t.Log(string(certBytes))
	childRootFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."), childName)
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, certFileName), certBytes, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "ca.crt"), certBytes, true); nil != err {
		t.Fatal(err)
	}
}

func testSignTlsCA(leagueDomain, orgName, orgDomain, childName string, isUser bool, rootTlsCertBytes, tlsPriParentBytes, tlsPubBytes []byte, t *testing.T) {
	var (
		commonName string
		certBytes  []byte
		cc         = &CertConfig{}
		err        error
	)
	if isUser {
		commonName = utils.CertUserCANameWithOutCert(orgName, orgDomain, childName)
	} else {
		commonName = utils.CertNodeCANameWithOutCert(orgName, orgDomain, childName)
	}
	if certBytes, err = cc.generateCryptoChildCrt(rootTlsCertBytes, tlsPriParentBytes, tlsPubBytes, pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{orgName},
		OrganizationalUnit: []string{childName},
		Locality:           []string{"Beijing"},
		Province:           []string{"Beijing"},
		CommonName:         commonName,
	}, x509.ECDSAWithSHA256); nil != err {
		t.Error(err)
	}
	t.Log(string(certBytes))
	childRootFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."), childName)
	if _, err := gnomon.File().Append(filepath.Join(childRootFilePath, "tls.crt"), certBytes, true); nil != err {
		t.Fatal(err)
	}
}

//func Test_generateCa(t *testing.T) {
//	//var (
//	//	priTlsParentBytes, rootTlsCaCertBytes []byte
//	//	resp                                  *ca.RespCreateOrgChildTlsCa
//	//	err                                   error
//	//)
//	leagueDomain := "example.com"
//	//tlsPriKey, tlsPubKey, _, _ := testGC(leagueDomain, "ca", "root", "client", false, true, t)
//	//if priTlsParentBytes, err = ioutil.ReadFile(filepath.Join(utils.ObtainDataPath(), "ca", "resource", "tlsca.key")); nil != err {
//	//	t.Fatal(err)
//	//}
//	//if rootTlsCaCertBytes, err = ioutil.ReadFile(filepath.Join(utils.ObtainDataPath(), "ca", "resource", "tlsca.cert")); nil != err {
//	//	t.Fatal(err)
//	//}
//	//if resp, err = generateOrgChildTlsCaCrt(&ca.ReqCreateOrgChildTlsCa{
//	//	PubTlsBytes:        tlsPubKey,
//	//	PriTlsParentBytes:  priTlsParentBytes,
//	//	RootTlsCaCertBytes: rootTlsCaCertBytes,
//	//	SignAlgorithm:      ca.SignAlgorithm_ECDSAWithSHA256,
//	//	Csr: &ca.CSR{
//	//		Country:      []string{"CN"},
//	//		Organization: []string{"root"},
//	//		Locality:     []string{"Beijing"},
//	//		Province:     []string{"Beijing"},
//	//		CommonName:   "client",
//	//	},
//	//}); nil != err {
//	//	t.Fatal(err)
//	//}
//	//confBytes := testCaConfig(leagueDomain, enrollID, secret, fabricCaURL, tlsPriKey, resp.TlsCert, t)
//	testGCKey(leagueDomain, 10, 10, 5, 3, t)
//}
//
//func testCaConfig(leagueDomain, enrollID, enrollSecret, fabricCaURL string, tlsKey, tlsCert []byte, t *testing.T) (confBytes []byte) {
//	var (
//		orgName                             = "orgName"
//		rootCaCertBytes, rootTlsCaCertBytes []byte
//		err                                 error
//	)
//	if rootCaCertBytes, err = ioutil.ReadFile(filepath.Join(utils.ObtainDataPath(), "ca", "resource", "ca.cert")); nil != err {
//		t.Fatal(err)
//	}
//	if rootTlsCaCertBytes, err = ioutil.ReadFile(filepath.Join(utils.ObtainDataPath(), "ca", "resource", "tlsca.cert")); nil != err {
//		t.Fatal(err)
//	}
//	conf, err := config.JustCA(&config.CaCrypto{
//		EnrollID:         enrollID,
//		EnrollSecret:     enrollSecret,
//		LeagueDomain:     leagueDomain,
//		OrgDomain:        "orgDomain",
//		OrgName:          orgName,
//		Username:         "user",
//		IsAdmin:          true,
//		CaName:           caName,
//		URL:              fabricCaURL,
//		RootCertBytes:    []byte(rootCaCertBytes),
//		RootTlsCertBytes: []byte(rootTlsCaCertBytes),
//		Crypto: &config2.Crypto{
//			Key:     []byte(priParentBytes),
//			Cert:    []byte(rootCertBytes),
//			TlsKey:  tlsKey,
//			TlsCert: tlsCert,
//		},
//	})
//	confBytes, err = yaml.Marshal(&conf)
//	if err != nil {
//		t.Error("yaml", err)
//	}
//	return confBytes
//}
//
//func testAddAffiliation(orgName, affiliationName string, confBytes []byte, t *testing.T) {
//	sdk, err := core.SDK(confBytes)
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer sdk.Close()
//	resp, err := addAffiliation(orgName, &msp.AffiliationRequest{
//		Name:   affiliationName, // Name of the affiliation, org1/peer0.org1.example.com/enrollID
//		Force:  true,            // Creates parent affiliations if they do not exist
//		CAName: caName,          // Name of the CA
//	}, sdk)
//	t.Log(resp)
//}
//
//func testGCKey(leagueDomain string, order, org, peer, user int, t *testing.T) {
//	orderDomain := "order.com"
//	orderName := "order"
//	for i := 0; i < order; i++ {
//		childName := strings.Join([]string{"order", strconv.Itoa(i)}, "")
//		testGenerateCryptoCA(leagueDomain, orderDomain, orderName, childName, false, t)
//		testGenerateCryptoTlsCA(leagueDomain, orderDomain, orderName, childName, false, t)
//		//_, _, csrBytes, csr := testGC(leagueDomain, orderDomain, orderName, childName, false, false, t)
//		//_, pubKeyBytes, _, _ := testGC(leagueDomain, orderDomain, orderName, childName, false, true, t)
//		//testAddAffiliation(orderName, childName, confBytes, t)
//		//testGOCC(leagueDomain, orderName, childName, pubKeyBytes, csrBytes, csr, t)
//
//		childName = strings.Join([]string{"user", strconv.Itoa(i)}, "")
//		testGenerateCryptoCA(leagueDomain, orderDomain, orderName, childName, true, t)
//		testGenerateCryptoTlsCA(leagueDomain, orderDomain, orderName, childName, true, t)
//	}
//	for i := 0; i < org; i++ {
//		orgDomain := strings.Join([]string{"g", strconv.Itoa(i), ".com"}, "")
//		orgName := strings.Join([]string{"org", strconv.Itoa(i)}, "")
//		for j := 0; j < peer; j++ {
//			childName := strings.Join([]string{"peer", strconv.Itoa(j)}, "")
//			testGenerateCryptoCA(leagueDomain, orgDomain, orgName, childName, false, t)
//			testGenerateCryptoTlsCA(leagueDomain, orgDomain, orgName, childName, false, t)
//		}
//		for k := 0; k < user; k++ {
//			childName := strings.Join([]string{"user", strconv.Itoa(k)}, "")
//			testGenerateCryptoCA(leagueDomain, orgDomain, orgName, childName, true, t)
//			testGenerateCryptoTlsCA(leagueDomain, orgDomain, orgName, childName, true, t)
//		}
//	}
//}
//
//func testGenerateCryptoCA(leagueDomain, orgDomain, orgName, childName string, isUser bool, t *testing.T) {
//	tmpPath, skFileName, certFileName, skFileBytes, certFileBytes, err := generateCryptoCA(&ca.ReqCa{
//		OrgName:       orgName,
//		OrgDomain:     orgDomain,
//		ChildName:     childName, // User1@org1.example.com/peer1.org1.example.com
//		Country:       "CN",
//		Province:      "Hubei",
//		Locality:      "Yichang",
//		OrgUnit:       "IT",
//		StreetAddress: "Shengli road",
//		PostalCode:    "443000",
//		IsUser:        isUser,
//	})
//	if nil != err {
//		t.Fatal(err)
//	}
//	t.Log(tmpPath)
//	t.Log(skFileName)
//	t.Log(certFileName)
//	t.Log(skFileBytes)
//	t.Log(certFileBytes)
//	skFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, orgName, childName, skFileName)
//	certFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, orgName, childName, certFileName)
//	if _, err := gnomon.File().Append(skFilePath, skFileBytes, true); nil != err {
//		t.Fatal(err)
//	}
//	if _, err := gnomon.File().Append(certFilePath, certFileBytes, true); nil != err {
//		t.Fatal(err)
//	}
//}
//
//func testGenerateCryptoTlsCA(leagueDomain, orgDomain, orgName, childName string, isUser bool, t *testing.T) (priKeyBytes, pubKeyBytes, csrBytes []byte, csr *ca.CSR) {
//	var (
//		resp                           *ca.RespKeyConfig
//		priKeyFilePath, pubKeyFilePath string
//		err                            error
//	)
//	if resp, err = generateCrypto(&ca.ReqKeyConfig{
//		CryptoType: ca.CryptoType_ECDSA,
//		Algorithm:  algorithm,
//	}); nil != err {
//		t.Fatal(err)
//	}
//	t.Log(resp)
//	priKeyFilePath = filepath.Join(utils.ObtainDataPath(), leagueDomain, orgName, childName, strings.Join([]string{childName, "tls.key"}, ""))
//	pubKeyFilePath = filepath.Join(utils.ObtainDataPath(), leagueDomain, orgName, childName, strings.Join([]string{childName, "tls.pub"}, ""))
//	if _, err := gnomon.File().Append(priKeyFilePath, resp.PriKeyBytes, true); nil != err {
//		t.Fatal(err)
//	}
//	if _, err := gnomon.File().Append(pubKeyFilePath, resp.PubKeyBytes, true); nil != err {
//		t.Fatal(err)
//	}
//	return resp.PriKeyBytes, resp.PubKeyBytes, csrBytes, csr
//}

func testGOCS(leagueDomain, orgDomain, orgName, childName string, priKeyBytes []byte, isUser bool, t *testing.T) (csrBytes []byte, csr *ca.CSR) {
	var (
		resp       *ca.RespCreateCsr
		commonName string
		err        error
	)
	if isUser {
		commonName = utils.CertUserCAName(orgName, orgDomain, childName)
	} else {
		commonName = utils.CertNodeCAName(orgName, orgDomain, childName)
	}
	csr = &ca.CSR{
		Country:      []string{"CN"},
		Organization: []string{orgName},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   commonName,
	}
	if resp, err = generateOrgChildCsr(&ca.ReqCreateCsr{
		LeagueDomain:  leagueDomain,
		ChildName:     childName,
		OrgDomain:     orgDomain,
		PriKeyBytes:   priKeyBytes,
		Csr:           csr,
		SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
	}); nil != err {
		t.Fatal(err)
	}
	t.Log(resp)
	csrFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, orgName, strings.Join([]string{childName, ".csr"}, ""))
	if _, err := gnomon.File().Append(csrFilePath, resp.CsrBytes, true); nil != err {
		t.Fatal(err)
	}
	return resp.CsrBytes, csr
}

func testGOCC(leagueDomain, orgName, childName string, pubTlsBytes, csrBytes []byte, csr *ca.CSR, t *testing.T) {
	var (
		resp                                  *ca.RespCreateOrgChild
		priTlsParentBytes, rootTlsCaCertBytes []byte
		err                                   error
	)
	if priTlsParentBytes, err = ioutil.ReadFile(filepath.Join(utils.ObtainDataPath(), "ca", "resource", "tlsca.key")); nil != err {
		t.Fatal(err)
	}
	if rootTlsCaCertBytes, err = ioutil.ReadFile(filepath.Join(utils.ObtainDataPath(), "ca", "resource", "tlsca.cert")); nil != err {
		t.Fatal(err)
	}
	if resp, err = generateOrgChildCrt(&ca.ReqCreateOrgChild{
		PubTlsBytes:        pubTlsBytes,
		PriTlsParentBytes:  []byte(priTlsParentBytes),
		RootTlsCaCertBytes: []byte(rootTlsCaCertBytes),
		SignAlgorithm:      ca.SignAlgorithm_ECDSAWithSHA256,
		EnrollInfo: &ca.EnrollInfo{
			CsrPemBytes:       csrBytes,
			FabricCaServerURL: fabricCaURL,
			NotBefore:         0,
			NotAfter:          5000,
			EnrollRequest: &ca.EnrollRequest{
				EnrollID: enrollID,
				Secret:   secret,
				Csr:      csr,
				Hosts:    []string{csr.GetCommonName()},
			},
		},
	}); nil != err {
		t.Fatal(err)
	}
	t.Log(resp)
	certFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, orgName, strings.Join([]string{childName, ".cert"}, ""))
	tlsCertFilePath := filepath.Join(utils.ObtainDataPath(), leagueDomain, orgName, strings.Join([]string{childName, "tls.cert"}, ""))
	if _, err := gnomon.File().Append(certFilePath, resp.Cert, true); nil != err {
		t.Fatal(err)
	}
	if _, err := gnomon.File().Append(tlsCertFilePath, resp.TlsCert, true); nil != err {
		t.Fatal(err)
	}
}

func Test_generateOrgChildCrt(t *testing.T) {

}

//func Test_(t *testing.T) {
//
//}
