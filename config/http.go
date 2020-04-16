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
	route.Post("/set", &config.ReqConfigSet{}, routerConfigSet)
	route.Post("/obtain", &config.ReqConfigObtain{}, routerConfigObtain)
	route.Post("/list", &config.ReqConfigList{}, routerConfigList)
	route.Post("/delete", &config.ReqConfigDelete{}, routerConfigDelete)
}

func routerConfigSet(_ http.ResponseWriter, _ *http.Request, reqModel interface{}, _ map[string]string) (respModel interface{}, custom bool) {
	serviceModel := reqModel.(*config.ReqConfigSet)
	resp, _ := setConfig(serviceModel)
	return resp, false
}

func routerConfigObtain(_ http.ResponseWriter, _ *http.Request, reqModel interface{}, _ map[string]string) (respModel interface{}, custom bool) {
	serviceModel := reqModel.(*config.ReqConfigObtain)
	resp, _ := obtainConfig(serviceModel)
	return resp, false
}

func routerConfigList(_ http.ResponseWriter, _ *http.Request, reqModel interface{}, _ map[string]string) (respModel interface{}, custom bool) {
	serviceModel := reqModel.(*config.ReqConfigList)
	resp, _ := listConfig(serviceModel)
	return resp, false
}

func routerConfigDelete(_ http.ResponseWriter, _ *http.Request, reqModel interface{}, _ map[string]string) (respModel interface{}, custom bool) {
	serviceModel := reqModel.(*config.ReqConfigDelete)
	resp, _ := deleteConfig(serviceModel)
	return resp, false
}
