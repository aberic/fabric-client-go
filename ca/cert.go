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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	"io/ioutil"
	random "math/rand"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CertConfig 证书配置结构
type CertConfig struct{}

func (cc *CertConfig) generateCsr(PriBytes []byte, subject pkix.Name, signatureAlgorithm x509.SignatureAlgorithm) (csrBytes []byte, err error) {
	var (
		asn1Subj, csrData []byte
		priKey            interface{}
	)
	if subject.CommonName == "" {
		return nil, errors.New("missing commonName")
	}
	rawSubj := subject.ToRDNSequence()

	if asn1Subj, err = asn1.Marshal(rawSubj); err != nil {
		return nil, err
	}

	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: signatureAlgorithm,
		DNSNames:           []string{subject.CommonName},
	}

	if priKey, err = cc.getPriKeyFromBytes(PriBytes); nil != err {
		return nil, err
	}
	csrData, err = x509.CreateCertificateRequest(rand.Reader, &template, priKey)
	if err != nil {
		return nil, err
	}
	// 将block的PEM编码写入
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrData}), nil
}

func (cc *CertConfig) generateCryptoRootCrt(priKeyBytes []byte, subject pkix.Name,
	signatureAlgorithm x509.SignatureAlgorithm, filePath string) (certBytes []byte, err error) {
	var (
		priKey   crypto.Signer
		certData []byte
	)
	if priKey, err = cc.getPriKey(priKeyBytes); nil != err {
		return nil, err
	}
	if certData, err = gnomon.CA().GenerateCertificateSelf(&gnomon.CertSelf{
		CertificateFilePath:   filePath,
		Subject:               subject,
		ParentPrivateKey:      priKey,
		PublicKey:             priKey.Public(),
		NotAfterDays:          time.Now().Add(5000 * 24 * time.Hour),
		NotBeforeDays:         time.Now(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDataEncipherment,
		SignatureAlgorithm:    signatureAlgorithm,
	}); nil != err {
		return nil, err
	}
	// 将block的PEM编码写入
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certData}), nil
}

// generateCryptoOrgChildTlsCaCrt 生成组织子节点/用户tls证书
func (cc *CertConfig) generateCryptoChildCrt(rootCertBytes, priParentBytes, pubBytes []byte, subject pkix.Name, signatureAlgorithm x509.SignatureAlgorithm) (cert []byte, err error) {
	var (
		parentTLSCert *x509.Certificate
		certData      []byte
	)
	if nil == rootCertBytes || len(rootCertBytes) <= 0 {
		return nil, errors.New("root cert bytes can't be empty")
	}
	parentCertData, _ := pem.Decode(rootCertBytes)
	if parentTLSCert, err = x509.ParseCertificate(parentCertData.Bytes); nil != err {
		return nil, err
	}
	priTLSParentKey, pubTLSKey, err := cc.getCertKey(priParentBytes, pubBytes)
	if nil != err {
		return nil, err
	}
	if certData, err = gnomon.CA().GenerateCertificate(&gnomon.Cert{
		ParentCert: parentTLSCert,
		CertSelf: gnomon.CertSelf{
			CertificateFilePath:   filepath.Join("/tmp", strconv.Itoa(random.Int()), "tls", "tmp.crt"),
			Subject:               subject,
			ParentPrivateKey:      priTLSParentKey,
			PublicKey:             pubTLSKey,
			NotAfterDays:          time.Now().Add(5000 * 24 * time.Hour),
			NotBeforeDays:         time.Now(),
			BasicConstraintsValid: true,
			IsCA:                  false,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDataEncipherment,
			SignatureAlgorithm:    signatureAlgorithm,
		},
	}); nil != err {
		return nil, err
	}
	// 将block的PEM编码写入
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certData}), nil
}

func (cc *CertConfig) enroll(gcr generateCertificateRequest, fabricCaServerURL, enrollID, secret string) (cert []byte, err error) {
	crm, err := json.Marshal(gcr)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, strings.Join([]string{fabricCaServerURL, "api/v1/enroll"}, "/"), bytes.NewBuffer(crm))
	if nil != err {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(enrollID, secret)

	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		enrResp := new(enrollmentResponse)
		if err := json.Unmarshal(body, enrResp); err != nil {
			return nil, err
		}
		if !enrResp.Success {
			return nil, enrResp.error()
		}
		return base64.StdEncoding.DecodeString(enrResp.Result.Cert)
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

func (cc *CertConfig) stringToCert(data string) (*x509.Certificate, error) {
	rawCert, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	pemResult, _ := pem.Decode(rawCert)
	return x509.ParseCertificate(pemResult.Bytes)
}

func (cc *CertConfig) getPriKeyFromBytes(priKeyData []byte) (priKey interface{}, err error) {
	var priEccKey *ecdsa.PrivateKey
	if priEccKey, err = gnomon.CryptoECC().LoadPriPem(priKeyData); nil != err {
		var (
			priRsaKey *rsa.PrivateKey
			pks       gnomon.PKSCType
		)
		pks = gnomon.CryptoRSA().PKSC8()
		if priRsaKey, err = gnomon.CryptoRSA().LoadPri(priKeyData, pks); nil != err {
			pks = gnomon.CryptoRSA().PKSC1()
			if priRsaKey, err = gnomon.CryptoRSA().LoadPri(priKeyData, pks); nil != err {
				return nil, errors.New("private key is not support")
			}
		}
		priKey = priRsaKey
	} else {
		priKey = priEccKey

	}
	return
}

func (cc *CertConfig) getPriKey(priKeyData []byte) (crypto.Signer, error) {
	var (
		priEccKey *ecdsa.PrivateKey
		priKey    crypto.Signer
		err       error
	)
	if priEccKey, err = gnomon.CryptoECC().LoadPriPem(priKeyData); nil != err {
		var (
			priRsaKey *rsa.PrivateKey
			pks       gnomon.PKSCType
		)
		pks = gnomon.CryptoRSA().PKSC8()
		if priRsaKey, err = gnomon.CryptoRSA().LoadPri(priKeyData, pks); nil != err {
			pks = gnomon.CryptoRSA().PKSC1()
			if priRsaKey, err = gnomon.CryptoRSA().LoadPri(priKeyData, pks); nil != err {
				return nil, errors.New("private key is not support")
			}
		}
		priKey = priRsaKey
	} else {
		priKey = priEccKey
	}
	return priKey, nil
}

func (cc *CertConfig) getCertKey(priParentKeyData, pubKeyData []byte) (priParentKey crypto.Signer, pubKey interface{}, err error) {
	if priParentKey, err = gnomon.CryptoECC().LoadPriPem(priParentKeyData); nil != err {
		if priParentKey, err = gnomon.CryptoRSA().LoadPri(priParentKeyData, gnomon.CryptoRSA().PKSC8()); nil != err {
			if priParentKey, err = gnomon.CryptoRSA().LoadPri(priParentKeyData, gnomon.CryptoRSA().PKSC1()); nil != err {
				err = errors.New("private key is not support")
				return
			}
		}
	}
	if pubKey, err = gnomon.CryptoECC().LoadPubPem(pubKeyData); nil != err {
		if pubKey, err = gnomon.CryptoRSA().LoadPub(pubKeyData); nil != err {
			err = errors.New("public key is not support")
			return
		}
	}
	return
}

func (cc *CertConfig) getRootCA(leagueDomain string) (caPath, caFileName, tlsCaPath, tlsCaFileName string) {
	caPath = utils.CryptoRootCATmpPath(leagueDomain)
	caFileName = utils.RootCACertFileName(leagueDomain)
	tlsCaPath = utils.CryptoRootTLSCATmpPath(leagueDomain)
	tlsCaFileName = utils.RootTLSCACertFileName(leagueDomain)
	return
}

func (cc *CertConfig) ski(priKeyFilePath string) string {
	priKey, _, _ := csp.GeneratePrivateKey(priKeyFilePath)
	return hex.EncodeToString(priKey.SKI()) + "_sk"
}
