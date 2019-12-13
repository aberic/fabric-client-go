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
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"
)

type cryptoType int

type cryptoAlgorithm int

const (
	priKeyFileDefaultName                 = "pri.key" // 证书私钥文件文件默认名称
	pubKeyFileDefaultName                 = "pub.key" // 证书公钥文件文件默认名称
	cryptoECC             cryptoType      = 1
	cryptoRSA             cryptoType      = 2
	p256                  cryptoAlgorithm = 1
	p384                  cryptoAlgorithm = 2
	p521                  cryptoAlgorithm = 3
	r2048                 cryptoAlgorithm = 4
	r4096                 cryptoAlgorithm = 5
)

// keyConfig 证书生成配置结构
type keyConfig struct{}

// generateCrypto 生成密钥对
//
// cryptoType 密钥类型，ECC=1；RSA=2；
func (kc *keyConfig) generateCrypto(cryptoType cryptoType, bits cryptoAlgorithm) (priFileBytes, pubFileBytes []byte, err error) {
	switch cryptoType {
	default:
		return nil, nil, errors.New("crypto type error")
	case cryptoECC:
		return kc.cryptoECC(bits)
	case cryptoRSA:
		return kc.cryptoRSA(bits)
	}
}

func (kc *keyConfig) generateCryptoCA() (skName string, priKeyBytes, pubKeyBytes []byte, err error) {
	tmpPath := path.Join(os.TempDir(), strconv.FormatInt(time.Now().UnixNano(), 10))
	priKey, _, err := csp.GeneratePrivateKey(tmpPath)
	if nil != err {
		return
	}
	skName = utils.ObtainSKI(priKey)
	if priKeyBytes, err = ioutil.ReadFile(filepath.Join(tmpPath, skName)); nil != err {
		return
	}
	pubKey, err := csp.GetECPublicKey(priKey)
	if nil != err {
		return
	}
	// 将公钥序列化为der编码的PKIX格式
	derPkiX, err := x509.MarshalPKIXPublicKey(pubKey)
	if nil != err {
		return
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkiX,
	}
	pubKeyBytes = pem.EncodeToMemory(block)
	return
}

// cryptoRSA 生成rsa密钥对
func (kc *keyConfig) cryptoRSA(bits cryptoAlgorithm) (priFileBytes, pubFileBytes []byte, err error) {
	var long int
	if long, err = kc.cryptoRSABits(bits); nil != err {
		return nil, nil, err
	}
	storePath := path.Join("/tmp", strconv.FormatInt(time.Now().UnixNano(), 10))
	priFilePath := filepath.Join(storePath, priKeyFileDefaultName)
	pubFilePath := filepath.Join(storePath, pubKeyFileDefaultName)
	if err = gnomon.CryptoRSA().GenerateKey(long, storePath, priKeyFileDefaultName, pubKeyFileDefaultName, gnomon.CryptoRSA().PKSC8()); nil != err {
		return nil, nil, err
	}
	return kc.cryptoBytes(priFilePath, pubFilePath)
}

// cryptoECC 生成ecc密钥对
func (kc *keyConfig) cryptoECC(bits cryptoAlgorithm) (priFileBytes, pubFileBytes []byte, err error) {
	var curve elliptic.Curve
	if curve, err = kc.cryptoECCCurve(bits); nil != err {
		return nil, nil, err
	}
	storePath := path.Join("/tmp", strconv.Itoa(time.Now().Nanosecond()))
	priFilePath := filepath.Join(storePath, priKeyFileDefaultName)
	pubFilePath := filepath.Join(storePath, pubKeyFileDefaultName)
	if err = gnomon.CryptoECC().GeneratePemKey(storePath, priKeyFileDefaultName, pubKeyFileDefaultName, curve); nil != err {
		return nil, nil, err
	}
	return kc.cryptoBytes(priFilePath, pubFilePath)
}

// cryptoBytes 将密钥对所在路径文件内容读出并返回
func (kc *keyConfig) cryptoBytes(priFilePath, pubFilePath string) (priFileBytes, pubFileBytes []byte, err error) {
	if priFileBytes, err = ioutil.ReadFile(priFilePath); nil != err {
		return nil, nil, err
	}
	if pubFileBytes, err = ioutil.ReadFile(pubFilePath); nil != err {
		return nil, nil, err
	}
	return
}

func (kc *keyConfig) cryptoRSABits(bits cryptoAlgorithm) (long int, err error) {
	switch bits {
	default:
		return 0, errors.New("rsa algorithm type error")
	case r2048:
		return 2048, nil
	case r4096:
		return 4096, nil
	}
}

func (kc *keyConfig) cryptoECCCurve(bits cryptoAlgorithm) (curve elliptic.Curve, err error) {
	switch bits {
	default:
		return nil, errors.New("ecc algorithm type error")
	case p256:
		return elliptic.P256(), nil
	case p384:
		return elliptic.P384(), nil
	case p521:
		return elliptic.P521(), nil
	}
}
