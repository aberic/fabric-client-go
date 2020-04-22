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

package config

import (
	"github.com/aberic/fabric-client-go/grpc/proto/config"
	"github.com/aberic/gnomon/grope"
	"net/http"
)

func Router(hs *grope.GHttpServe) {
	// 仓库相关路由设置
	route := hs.Group("/config")
	route.Post("/set", routerConfigSet)
	route.Post("/obtain", routerConfigObtain)
	route.Post("/list", routerConfigList)
	route.Post("/delete", routerConfigDelete)
}

func routerConfigSet(ctx *grope.Context) {
	serviceModel, _ := ctx.ReceiveJson(&config.ReqConfigSet{})
	resp, _ := setConfig(serviceModel.(*config.ReqConfigSet))
	_ = ctx.ResponseJson(http.StatusOK, resp)
}

func routerConfigObtain(ctx *grope.Context) {
	serviceModel, _ := ctx.ReceiveJson(&config.ReqConfigObtain{})
	resp, _ := obtainConfig(serviceModel.(*config.ReqConfigObtain))
	_ = ctx.ResponseJson(http.StatusOK, resp)
}

func routerConfigList(ctx *grope.Context) {
	serviceModel, _ := ctx.ReceiveJson(&config.ReqConfigList{})
	resp, _ := listConfig(serviceModel.(*config.ReqConfigList))
	_ = ctx.ResponseJson(http.StatusOK, resp)
}

func routerConfigDelete(ctx *grope.Context) {
	serviceModel, _ := ctx.ReceiveJson(&config.ReqConfigDelete{})
	resp, _ := deleteConfig(serviceModel.(*config.ReqConfigDelete))
	_ = ctx.ResponseJson(http.StatusOK, resp)
}
