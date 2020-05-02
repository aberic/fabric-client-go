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
	route.Post("/generate/crypto/root", routerGenerateRootCrypto)
	route.Post("/generate/crypto", routerGenerateCrypto)
	route.Post("/sign/crt", routerSignCertificate)
}

func routerGenerateRootCrypto(ctx *grope.Context) {
	serviceModel := &ca.ReqRootCrypto{}
	if err := ctx.ReceiveJSON(&ca.ReqRootCrypto{}); nil != err {
		_ = ctx.ResponseText(http.StatusOK, err.Error())
	} else {
		resp, _ := generateRootCrypto(serviceModel)
		_ = ctx.ResponseJSON(http.StatusOK, resp)
	}
}

func routerGenerateCrypto(ctx *grope.Context) {
	serviceModel := &ca.ReqCrypto{}
	if err := ctx.ReceiveJSON(&ca.ReqCrypto{}); nil != err {
		_ = ctx.ResponseText(http.StatusOK, err.Error())
	} else {
		resp, _ := generateCrypto(serviceModel)
		_ = ctx.ResponseJSON(http.StatusOK, resp)
	}
}

func routerSignCertificate(ctx *grope.Context) {
	serviceModel := &ca.ReqSignCertificate{}
	if err := ctx.ReceiveJSON(&ca.ReqSignCertificate{}); nil != err {
		_ = ctx.ResponseText(http.StatusOK, err.Error())
	} else {
		resp, _ := signCertificate(serviceModel)
		_ = ctx.ResponseJSON(http.StatusOK, resp)
	}
}
