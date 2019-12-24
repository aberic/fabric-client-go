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
	"context"
	"github.com/aberic/fabric-client-go/grpc/proto/config"
)

// ConfServer fabric组织访问相关配置服务
type ConfServer struct{}

// ConfigSet 设置新的组织配置信息，用于访问fabric网络
func (cs *ConfServer) ConfigSet(ctx context.Context, req *config.ReqConfigSet) (*config.RespConfigSet, error) {
	return setConfig(req)
}

// ConfigObtain 获取组织配置信息详情
func (cs *ConfServer) ConfigObtain(ctx context.Context, req *config.ReqConfigObtain) (*config.RespConfigObtain, error) {
	return obtainConfig(req)
}

// ConfigList 列出已有组织信息集合
func (cs *ConfServer) ConfigList(ctx context.Context, req *config.ReqConfigList) (*config.RespConfigList, error) {
	return listConfig(req)
}

// ConfigDelete 删除指定组织配置信息
func (cs *ConfServer) ConfigDelete(ctx context.Context, req *config.ReqConfigDelete) (*config.RespConfigDelete, error) {
	return deleteConfig(req)
}
