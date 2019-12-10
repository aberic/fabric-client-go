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
	"testing"
)

var (
	fabricCaURL = "127.0.0.1:7054"
	enrollID    = "admin"
	secret      = "adminpw"
	algorithm   = &ca.ReqKeyConfig_EccAlgorithm{
		EccAlgorithm: ca.EccAlgorithm_p256,
	}
)

func Test_generateCrypto(t *testing.T) {
	if resp, err := generateCrypto(&ca.ReqKeyConfig{
		CryptoType: ca.CryptoType_ECDSA,
		Algorithm:  algorithm,
	}); nil != err {
		t.Error(err)
	} else {
		t.Log(resp)
	}
}

func gcKey(index int, t *testing.T) {
	if resp, err := generateCrypto(&ca.ReqKeyConfig{
		CryptoType: ca.CryptoType_ECDSA,
		Algorithm:  algorithm,
	}); nil != err {
		t.Error(err)
	} else {
		t.Log(resp)
	}

}

func Test_generateLeagueCrt(t *testing.T) {

}

func Test_generateOrgChildCsr(t *testing.T) {

}

func Test_generateOrgChildCrt(t *testing.T) {

}

//func Test_(t *testing.T) {
//
//}
