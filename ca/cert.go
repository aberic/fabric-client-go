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
	ca2 "github.com/aberic/fabric-client-go/grpc/proto/ca"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"github.com/hyperledger/fabric/common/tools/cryptogen/ca"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	"io/ioutil"
	random "math/rand"
	"os"
	"path"
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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    signatureAlgorithm,
	}); nil != err {
		return nil, err
	}
	// 将block的PEM编码写入
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certData}), nil
}

func (cc *CertConfig) signCertificateCA(commonName string, ca *ca.CA, pubKey *ecdsa.PublicKey) (certBytes []byte, err error) {
	tmpPath := path.Join(os.TempDir(), strconv.FormatInt(time.Now().UnixNano(), 10))
	if err = os.MkdirAll(tmpPath, 0755); nil != err && !gnomon.File().PathExists(tmpPath) {
		return nil, err
	}
	if _, err := ca.SignCertificate(tmpPath, commonName, nil, []string{commonName}, pubKey,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}); nil != err {
		return nil, err
	}
	return ioutil.ReadFile(filepath.Join(tmpPath, strings.Join([]string{commonName, "cert.pem"}, "-")))
}

func (cc *CertConfig) getCA(rootCaDir string, subject *ca2.Subject) *ca.CA {
	_, signer, _ := csp.LoadPrivateKey(rootCaDir)
	cert, _ := ca.LoadCertificateECDSA(rootCaDir)

	return &ca.CA{
		Signer:             signer,
		SignCert:           cert,
		Country:            subject.Country,
		Province:           subject.Province,
		Locality:           subject.Locality,
		OrganizationalUnit: subject.OrgUnit,
		StreetAddress:      subject.StreetAddress,
		PostalCode:         subject.PostalCode,
	}
}

// generateCryptoOrgChildTlsCaCrt 生成组织子节点/用户tls证书
func (cc *CertConfig) generateCryptoChildCrt(rootCertBytes, priParentBytes, pubBytes []byte, subject pkix.Name, signatureAlgorithm x509.SignatureAlgorithm) (cert []byte, err error) {
	var (
		parentCert *x509.Certificate
		certData   []byte
	)
	if nil == rootCertBytes || len(rootCertBytes) <= 0 {
		return nil, errors.New("root cert bytes can't be empty")
	}
	parentCertData, _ := pem.Decode(rootCertBytes)
	if parentCert, err = x509.ParseCertificate(parentCertData.Bytes); nil != err {
		return nil, err
	}
	priParentKey, pubKey, err := cc.getCertKey(priParentBytes, pubBytes)
	if nil != err {
		return nil, err
	}
	if certData, err = gnomon.CA().GenerateCertificate(&gnomon.Cert{
		ParentCert: parentCert,
		CertSelf: gnomon.CertSelf{
			CertificateFilePath: filepath.Join(os.TempDir(), strconv.Itoa(random.Int()), "tmp.crt"),
			Subject:             subject,
			ParentPrivateKey:    priParentKey,
			PublicKey:           pubKey,
			NotAfterDays:        time.Now().Add(5000 * 24 * time.Hour),
			NotBeforeDays:       time.Now(),
			ExtKeyUsage:         []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			KeyUsage:            x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SignatureAlgorithm:  signatureAlgorithm,
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
