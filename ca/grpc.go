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

// GenerateServer grpc生成服务结构
type GenerateServer struct{}

// GenerateCrypto 生成密钥对
//func (gc *GenerateServer) GenerateRootCrypto(ctx context.Context, req *ca.ReqRootCrypto) (*ca.RespRootCrypto, error) {
//	return generateCrypto(req)
//}

//// GenerateLeagueCrt 生成联盟根证书
//func (gc *GenerateServer) GenerateLeagueCrt(ctx context.Context, league *ca.ReqCreateLeague) (*ca.RespCreateLeague, error) {
//	return generateLeagueCrt(league)
//}
//
//// GenerateOrgChildCsr 生成CA请求证书文件
//func (gc *GenerateServer) GenerateOrgChildCsr(ctx context.Context, csr *ca.ReqCreateCsr) (*ca.RespCreateCsr, error) {
//	return generateOrgChildCsr(csr)
//}
//
//// GenerateOrgChildCrt 生成组织下子节点/用户证书
//func (gc *GenerateServer) GenerateOrgChildCrt(ctx context.Context, child *ca.ReqCreateOrgChild) (*ca.RespCreateOrgChild, error) {
//	return generateOrgChildCrt(child)
//}
//
//// GenerateOrgChildCrt 生成组织下子节点/用户证书
//func (gc *GenerateServer) GenerateOrgChildCrtCa(ctx context.Context, child *ca.ReqCreateOrgChildCa) (*ca.RespCreateOrgChildCa, error) {
//	return generateOrgChildCaCrt(child)
//}
//
//// GenerateOrgChildCrt 生成组织下子节点/用户证书
//func (gc *GenerateServer) GenerateOrgChildCrtTlsCa(ctx context.Context, child *ca.ReqCreateOrgChildTlsCa) (*ca.RespCreateOrgChildTlsCa, error) {
//	return generateOrgChildTlsCaCrt(child)
//}
