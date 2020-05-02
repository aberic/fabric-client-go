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

package genesis

import (
	"github.com/aberic/fabric-client-go/grpc/proto/genesis"
	"github.com/aberic/gnomon/grope"
	"net/http"
)

func Router(hs *grope.GHttpServe) {
	// 仓库相关路由设置
	route := hs.Group("/genesis")
	route.Post("/block", routerCreateGenesisBlock)
	route.Post("/channel", routerCreateChannelTx)
}

func routerCreateGenesisBlock(ctx *grope.Context) {
	serviceModel := &genesis.ReqGenesisBlock{}
	if err := ctx.ReceiveJSON(&genesis.ReqGenesisBlock{}); nil != err {
		_ = ctx.ResponseText(http.StatusOK, err.Error())
	} else {
		resp, _ := createGenesisBlock(serviceModel)
		_ = ctx.ResponseJSON(http.StatusOK, resp)
	}
}

func routerCreateChannelTx(ctx *grope.Context) {
	serviceModel := &genesis.ReqChannelTx{}
	if err := ctx.ReceiveJSON(&genesis.ReqChannelTx{}); nil != err {
		_ = ctx.ResponseText(http.StatusOK, err.Error())
	} else {
		resp, _ := createChannelTx(serviceModel)
		_ = ctx.ResponseJSON(http.StatusOK, resp)
	}
}
