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

package utils

import (
	"github.com/aberic/gnomon"
	"strings"
)

var (
	GRPCPort int
	HttpPort int
	// dataPath 项目工作目录
	dataPath string
)

// 环境变量
const (
	GPort = "GRPC_PORT"
	HPort = "HTTP_PORT"
	// DataPath 项目工作目录 [template]
	DataPath = "DATA_PATH"
)

func init() {
	GRPCPort = gnomon.Env().GetIntD(GPort, 9872)
	HttpPort = gnomon.Env().GetIntD(HPort, 9865)
	dataPath = strings.Join([]string{gnomon.Env().GetD(DataPath, "/home"), "data"}, "/")
}
