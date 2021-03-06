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
	"os"
)

var (
	// dataPath 项目工作目录
	dataPath string
	// RaftStatus 是否启用raft
	RaftStatus bool
	// LogFileDir 日志文件目录
	LogFileDir string
	// LogFileMaxSize 每个日志文件保存的最大尺寸 单位：M
	LogFileMaxSize int
	// LogFileMaxAge 文件最多保存多少天
	LogFileMaxAge int
	// LogUtc CST & UTC 时间
	LogUtc bool
	// LogLevel 日志级别(debugLevel/infoLevel/warnLevel/ErrorLevel/panicLevel/fatalLevel)
	LogLevel string
	// LogProduction 是否生产环境，在生产环境下控制台不会输出任何日志
	LogProduction bool
)

// 环境变量
const (
	DataPath          = "DATA_PATH"              // DataPath 项目工作目录 [template]
	raftStatusEnv     = "RAFT"                   // RAFT=true启用raft，否则不启用
	K8sEnv            = "RAFT_K8S"               // K8S=true
	BrokerIDEnv       = "RAFT_BROKER_ID"         // BROKER_ID=1
	NodeAddrEnv       = "RAFT_NODE_ADDRESS"      // NODE_ADDRESS=example.com NODE_ADDRESS=127.0.0.1:19865:19877
	ClusterEnv        = "RAFT_CLUSTER"           // CLUSTER=1=127.0.0.1:19865:19877,2=127.0.0.2:19865:19877,3=127.0.0.3:19865:19877
	TimeHeartbeatEnv  = "RAFT_TIME_HEARTBEAT"    // raft心跳定时时间ms
	TimeCheckEnv      = "RAFT_TIME_CHECK"        // raft心跳定时检查超时时间ms
	TimeoutEnv        = "RAFT_TIMEOUT"           // raft心跳超时ms
	PortEnv           = "RAFT_PORT"              // raft服务开放端口号，默认19877
	LogDirEnv         = "RAFT_LOG_DIR"           // 日志文件目录
	LogFileMaxSizeEnv = "RAFT_LOG_FILE_MAX_SIZE" // 每个日志文件保存的最大尺寸 单位：M
	LogFileMaxAgeEnv  = "RAFT_LOG_FILE_MAX_AGE"  // 文件最多保存多少天
	LogUtcEnv         = "RAFT_LOG_UTC"           // CST & UTC 时间
	LogLevelEnv       = "RAFT_LOG_LEVEL"         // 日志级别(debugLevel/infoLevel/warnLevel/ErrorLevel/panicLevel/fatalLevel)
	LogProductionEnv  = "RAFT_LOG_PRODUCTION"    // 是否生产环境，在生产环境下控制台不会输出任何日志
)

func init() {
	// self
	dataPath = gnomon.EnvGetD(DataPath, gnomon.StringBuild(gnomon.EnvGet("GOPATH"), "/src/github.com/aberic/fabric-client-go/example"))
	RaftStatus = gnomon.EnvGetBool(raftStatusEnv)
	LogFileDir = gnomon.EnvGetD(LogDirEnv, os.TempDir())
	LogFileMaxSize = gnomon.EnvGetIntD(LogFileMaxSizeEnv, 1024)
	LogFileMaxAge = gnomon.EnvGetIntD(LogFileMaxAgeEnv, 7)
	LogUtc = gnomon.EnvGetBool(LogUtcEnv)
	LogLevel = gnomon.EnvGetD(LogLevelEnv, "Debug")
	LogProduction = gnomon.EnvGetBool(LogProductionEnv)
}

// ObtainDataPath 项目工作目录
func ObtainDataPath() string {
	return dataPath
}
