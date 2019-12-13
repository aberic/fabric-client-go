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
	"testing"
)

func TestGenerateCrypto(t *testing.T) {
	generateCryptoFailTest(t)
	generateCryptoRSA2048Test(t)
	generateCryptoRSA4096Test(t)
	generateCryptoRSAFailTest(t)
	generateCryptoECC256Test(t)
	generateCryptoECC384Test(t)
	generateCryptoECC521Test(t)
	generateCryptoECCFailTest(t)
}

func TestGenerateCryptoECC256(t *testing.T) {
	kc := &keyConfig{}
	priBytes, pubBytes, err := kc.generateCrypto(cryptoECC, p256)
	if nil != err {
		t.Error(err)
	}
	t.Log(string(priBytes))
	t.Log(string(pubBytes))
}

func TestGenerateCryptoCA(t *testing.T) {
	kc := &keyConfig{}
	skName, priKeyBytes, pubKeyBytes, err := kc.generateCryptoCA()
	if nil != err {
		t.Fatal(err)
	}
	t.Log(skName)
	t.Log(string(priKeyBytes))
	t.Log(string(pubKeyBytes))
}

func generateCryptoFailTest(t *testing.T) {
	kc := &keyConfig{}
	t.Log(kc.generateCrypto(0, 0))
}

func generateCryptoRSA2048Test(t *testing.T) {
	kc := &keyConfig{}
	t.Log(kc.generateCrypto(cryptoRSA, r2048))
}

func generateCryptoRSA4096Test(t *testing.T) {
	kc := &keyConfig{}
	t.Log(kc.generateCrypto(cryptoRSA, r4096))
}

func generateCryptoRSAFailTest(t *testing.T) {
	kc := &keyConfig{}
	t.Log(kc.generateCrypto(cryptoRSA, 0))
}

func generateCryptoECC256Test(t *testing.T) {
	kc := &keyConfig{}
	t.Log(kc.generateCrypto(cryptoECC, p256))
}

func generateCryptoECC384Test(t *testing.T) {
	kc := &keyConfig{}
	t.Log(kc.generateCrypto(cryptoECC, p384))
}

func generateCryptoECC521Test(t *testing.T) {
	kc := &keyConfig{}
	t.Log(kc.generateCrypto(cryptoECC, p521))
}

func generateCryptoECCFailTest(t *testing.T) {
	kc := &keyConfig{}
	t.Log(kc.generateCrypto(cryptoECC, 0))
}
