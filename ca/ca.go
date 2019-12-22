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
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func generateRootCrypto(org *ca.ReqRootCrypto) (*ca.RespRootCrypto, error) {
	var (
		caCommonName           = utils.CertOrgCaNameWithOutCert(org.Name, org.Domain)
		tlscaCommonName        = utils.CertOrgTlsCaNameWithOutCert(org.Name, org.Domain)
		crypto, tlsCrypto      *ca.RespCrypto
		certBytes, tlsCertByte []byte
		cc                     = &CertConfig{}
		err                    error
	)
	// ca
	if crypto, err = generateCrypto(&ca.ReqCrypto{Config: org.Config}); nil != err {
		return nil, err
	}
	// ca cert
	if certBytes, err = cc.generateCryptoRootCrt(crypto.PriKeyBytes, getSub(org.Name, caCommonName, org.Subject),
		getSignAlgorithm(org.Config.SignAlgorithm), filepath.Join(os.TempDir(), strconv.FormatInt(time.Now().UnixNano(), 10))); nil != err {
		return &ca.RespRootCrypto{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	// tls ca
	if tlsCrypto, err = generateCrypto(&ca.ReqCrypto{Config: org.TlsConfig}); nil != err {
		return nil, err
	}
	// tls ca cert
	if tlsCertByte, err = cc.generateCryptoRootCrt(tlsCrypto.PriKeyBytes, getSub(org.Name, tlscaCommonName, org.Subject),
		getSignAlgorithm(org.TlsConfig.SignAlgorithm), filepath.Join(os.TempDir(), strconv.FormatInt(time.Now().UnixNano(), 10))); nil != err {
		return &ca.RespRootCrypto{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &ca.RespRootCrypto{
		Code:           ca.Code_Success,
		PriKeyBytes:    crypto.PriKeyBytes,
		PubKeyBytes:    crypto.PubKeyBytes,
		CertBytes:      certBytes,
		TlsPriKeyBytes: tlsCrypto.PriKeyBytes,
		TlsPubKeyBytes: tlsCrypto.PubKeyBytes,
		TlsCertBytes:   tlsCertByte,
	}, nil
}

// generateCrypto 生成密钥对
func generateCrypto(crypto *ca.ReqCrypto) (*ca.RespCrypto, error) {
	kc := &keyConfig{}
	cryptoType, cryptoAlgorithm := generateCryptoParams(crypto.Config)
	priKeyBytes, pubKeyBytes, err := kc.generateCrypto(cryptoType, cryptoAlgorithm)
	if nil != err {
		return &ca.RespCrypto{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &ca.RespCrypto{Code: ca.Code_Success, PriKeyBytes: priKeyBytes, PubKeyBytes: pubKeyBytes}, nil
}

// signCertificate 签名证书
func signCertificate(rsc *ca.ReqSignCertificate) (*ca.RespSignCertificate, error) {
	var (
		commonName string
		certBytes  []byte
		cc         = &CertConfig{}
		err        error
	)
	if rsc.IsUser {
		commonName = utils.CertUserCANameWithOutCert(rsc.OrgName, rsc.OrgDomain, rsc.ChildName)
	} else {
		commonName = utils.CertNodeCANameWithOutCert(rsc.OrgName, rsc.OrgDomain, rsc.ChildName)
	}
	if certBytes, err = cc.generateCryptoChildCrt(rsc.ParentCertBytes, rsc.ParentPriBytes, rsc.PubBytes,
		getSub(rsc.OrgName, commonName, rsc.Subject), getSignAlgorithm(rsc.SignAlgorithm)); nil != err {
		return &ca.RespSignCertificate{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &ca.RespSignCertificate{Code: ca.Code_Success, CertBytes: certBytes}, nil
}

func generateCryptoParams(config *ca.CryptoConfig) (ct cryptoType, cal cryptoAlgorithm) {
	switch config.CryptoType {
	default:
		ct = 0
	case ca.CryptoType_ECDSA:
		ct = cryptoECC
		switch config.GetEccAlgorithm() {
		default:
			cal = 0
		case ca.EccAlgorithm_p256:
			cal = p256
		case ca.EccAlgorithm_p384:
			cal = p384
		case ca.EccAlgorithm_p521:
			cal = p521
		}
	case ca.CryptoType_RSA:
		ct = cryptoRSA
		switch config.GetRsaAlgorithm() {
		default:
			cal = 0
		case ca.RsaAlgorithm_r2048:
			cal = r2048
		case ca.RsaAlgorithm_r4096:
			cal = r4096
		}
	}
	return
}

// getSignAlgorithm 获取x509签名算法
func getSignAlgorithm(signAlgorithm ca.SignAlgorithm) x509.SignatureAlgorithm {
	switch signAlgorithm {
	default:
		return x509.ECDSAWithSHA256
	case ca.SignAlgorithm_ECDSAWithSHA256:
		return x509.ECDSAWithSHA256
	case ca.SignAlgorithm_ECDSAWithSHA384:
		return x509.ECDSAWithSHA384
	case ca.SignAlgorithm_ECDSAWithSHA512:
		return x509.ECDSAWithSHA512
	case ca.SignAlgorithm_SHA256WithRSA:
		return x509.SHA256WithRSA
	case ca.SignAlgorithm_SHA512WithRSA:
		return x509.SHA512WithRSA
	}
}

func getSub(orgName, commonName string, subject *ca.Subject) pkix.Name {
	return pkix.Name{
		Country:            []string{subject.Country},
		Organization:       []string{orgName},
		OrganizationalUnit: []string{subject.OrgUnit},
		Locality:           []string{subject.Locality},
		Province:           []string{subject.Province},
		StreetAddress:      []string{subject.StreetAddress},
		PostalCode:         []string{subject.PostalCode},
		CommonName:         commonName,
	}
}
