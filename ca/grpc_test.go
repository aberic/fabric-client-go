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
 *
 */

package ca

import (
	"github.com/aberic/fabric-client-go/grpc/proto/ca"
	"testing"
)

// TestGrpcGenerateCrypto 生成密钥对
func TestGrpcGenerateCrypto(t *testing.T) {
	gs := GenerateServer{}
	if respKeyConfig, err := gs.GenerateCrypto(nil, &ca.ReqKeyConfig{
		CryptoType: ca.CryptoType_ECDSA,
		Algorithm:  algorithm,
	}); nil != err {
		t.Error(err)
	} else {
		t.Log(respKeyConfig)
	}
}

// TestGrpcGenerateLeagueCrt 生成联盟根证书
func TestGrpcGenerateLeagueCrt(t *testing.T) {
	gs := GenerateServer{}
	if respCreateLeague, err := gs.GenerateLeagueCrt(nil, &ca.ReqCreateLeague{
		Domain:         "example.com",
		PriKeyBytes:    []byte(priParentBytes),
		PriTlsKeyBytes: []byte(priParentBytes),
		Csr: &ca.CSR{
			Country:      []string{"CN"},
			Organization: []string{"league"},
			Locality:     []string{"Beijing"},
			Province:     []string{"Beijing"},
			CommonName:   "example.com",
		},
		SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
	}); nil != err {
		t.Error(err)
	} else {
		t.Log(respCreateLeague)
	}
}

// TestGrpcGenerateOrgChildCsr 生成CA请求证书文件
func TestGrpcGenerateOrgChildCsr(t *testing.T) {
	gs := GenerateServer{}
	if respCreateCsr, err := gs.GenerateOrgChildCsr(nil, &ca.ReqCreateCsr{
		LeagueDomain: "example.com",
		ChildName:    "peer0",
		OrgDomain:    "org1.example.com",
		PriKeyBytes:  []byte(priParentBytes),
		Csr: &ca.CSR{
			Country:      []string{"CN"},
			Organization: []string{"league"},
			Locality:     []string{"Beijing"},
			Province:     []string{"Beijing"},
			CommonName:   "example.com",
		},
		SignAlgorithm: ca.SignAlgorithm_ECDSAWithSHA256,
	}); nil != err {
		t.Error(err)
	} else {
		t.Log(respCreateCsr)
	}
}

// TestGrpcGenerateOrgChildCrt 生成组织下子节点/用户证书
func TestGrpcGenerateOrgChildCrt(t *testing.T) {
	gs := GenerateServer{}
	if respCreateOrgChild, err := gs.GenerateOrgChildCrt(nil, &ca.ReqCreateOrgChild{
		PubTlsBytes:        []byte(pubBytes),
		PriTlsParentBytes:  []byte(priParentBytes),
		RootTlsCaCertBytes: []byte(rootCertBytes),
		SignAlgorithm:      ca.SignAlgorithm_ECDSAWithSHA256,
		EnrollInfo:         &ca.EnrollInfo{},
	}); nil != err {
		t.Error(err)
	} else {
		t.Log(respCreateOrgChild)
	}
}

//// grpcGenerateCrypto grpcGenerateCrypto
//func grpcGenerateCrypto(url string, req *ca.ReqKeyConfig) (interface{}, error) {
//	return rpc.Request(url, func(conn *grpc.ClientConn) (interface{}, error) {
//		var (
//			result *ca.RespKeyConfig
//			err    error
//		)
//		// 创建grpc客户端
//		c := ca.NewGenerateClient(conn)
//		// 客户端向grpc服务端发起请求
//		if result, err = c.GenerateCrypto(context.Background(), req); nil != err {
//			return nil, err
//		}
//		return result, nil
//	})
//}
//
//// grpcGenerateLeagueCrt grpcGenerateLeagueCrt
//func grpcGenerateLeagueCrt(url string, req *ca.ReqCreateLeague) (interface{}, error) {
//	return rpc.Request(url, func(conn *grpc.ClientConn) (interface{}, error) {
//		var (
//			result *ca.RespCreateLeague
//			err    error
//		)
//		// 创建grpc客户端
//		c := ca.NewGenerateClient(conn)
//		// 客户端向grpc服务端发起请求
//		if result, err = c.GenerateLeagueCrt(context.Background(), req); nil != err {
//			return nil, err
//		}
//		return result, nil
//	})
//}
//
//// grpcGenerateOrgChildCsr grpcGenerateOrgChildCsr
//func grpcGenerateOrgChildCsr(url string, req *ca.ReqCreateCsr) (interface{}, error) {
//	return rpc.Request(url, func(conn *grpc.ClientConn) (interface{}, error) {
//		var (
//			result *ca.RespCreateCsr
//			err    error
//		)
//		// 创建grpc客户端
//		c := ca.NewGenerateClient(conn)
//		// 客户端向grpc服务端发起请求
//		if result, err = c.GenerateOrgChildCsr(context.Background(), req); nil != err {
//			return nil, err
//		}
//		return result, nil
//	})
//}
//
//// grpcGenerateOrgChildCrt grpcGenerateOrgChildCrt
//func grpcGenerateOrgChildCrt(url string, req *ca.ReqCreateOrgChild) (interface{}, error) {
//	return rpc.Request(url, func(conn *grpc.ClientConn) (interface{}, error) {
//		var (
//			result *ca.RespCreateOrgChild
//			err    error
//		)
//		// 创建grpc客户端
//		c := ca.NewGenerateClient(conn)
//		// 客户端向grpc服务端发起请求
//		if result, err = c.GenerateOrgChildCrt(context.Background(), req); nil != err {
//			return nil, err
//		}
//		return result, nil
//	})
//}
