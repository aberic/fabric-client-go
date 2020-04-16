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
	"github.com/aberic/gnomon/grope"
	"net/http"
)

func Router(hs *grope.GHttpServe) {
	// 仓库相关路由设置
	route := hs.Group("/ca")
	route.Post("/generate/crypto/root", &ca.ReqRootCrypto{}, routerGenerateRootCrypto)
	route.Post("/generate/crypto", &ca.ReqCrypto{}, routerGenerateCrypto)
	route.Post("/sign/crt", &ca.ReqSignCertificate{}, routerSignCertificate)
}

func routerGenerateRootCrypto(_ http.ResponseWriter, _ *http.Request, reqModel interface{}, _ map[string]string) (respModel interface{}, custom bool) {
	serviceModel := reqModel.(*ca.ReqRootCrypto)
	resp, _ := generateRootCrypto(serviceModel)
	return resp, false
}

func routerGenerateCrypto(_ http.ResponseWriter, _ *http.Request, reqModel interface{}, _ map[string]string) (respModel interface{}, custom bool) {
	serviceModel := reqModel.(*ca.ReqCrypto)
	resp, _ := generateCrypto(serviceModel)
	return resp, false
}

func routerSignCertificate(_ http.ResponseWriter, _ *http.Request, reqModel interface{}, _ map[string]string) (respModel interface{}, custom bool) {
	serviceModel := reqModel.(*ca.ReqSignCertificate)
	resp, _ := signCertificate(serviceModel)
	return resp, false
}
