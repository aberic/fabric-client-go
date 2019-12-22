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
	"context"
	"github.com/aberic/fabric-client-go/grpc/proto/ca"
)

// GenerateServer grpc生成服务结构
type GenerateServer struct{}

// GenerateRootCrypto 生成联盟根证书
func (gc *GenerateServer) GenerateRootCrypto(ctx context.Context, req *ca.ReqRootCrypto) (*ca.RespRootCrypto, error) {
	return generateRootCrypto(req)
}

// GenerateCrypto 生成密钥对
func (gc *GenerateServer) GenerateCrypto(ctx context.Context, league *ca.ReqCrypto) (*ca.RespCrypto, error) {
	return generateCrypto(league)
}

// SignCertificate 生成组织下子节点/用户证书
func (gc *GenerateServer) SignCertificate(ctx context.Context, child *ca.ReqSignCertificate) (*ca.RespSignCertificate, error) {
	return signCertificate(child)
}
