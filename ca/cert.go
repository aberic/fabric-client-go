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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	random "math/rand"
	"path/filepath"
	"strconv"
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
