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
	"strings"
)

var (
	GRPCPort       int
	HttpPort       int
	dataPath       string // dataPath 项目工作目录
	RaftStatus     bool   // 是否启用raft
	LogFileDir     string // 日志文件目录
	LogFileMaxSize int    // 每个日志文件保存的最大尺寸 单位：M
	LogFileMaxAge  int    // 文件最多保存多少天
	LogUtc         bool   // CST & UTC 时间
	LogLevel       string // 日志级别(debugLevel/infoLevel/warnLevel/ErrorLevel/panicLevel/fatalLevel)
	LogProduction  bool   // 是否生产环境，在生产环境下控制台不会输出任何日志
)

// 环境变量
const (
	GRPCPortEnv       = "GRPC_PORT"              // gRPC 开放端口
	HTTPPortEnv       = "HTTP_PORT"              // http 开放端口
	DataPath          = "DATA_PATH"              // DataPath 项目工作目录 [template]
	raftStatusEnv     = "RAFT"                   // RAFT=true启用raft，否则不启用
	k8sEnv            = "RAFT_K8S"               // K8S=true
	brokerID          = "RAFT_BROKER_ID"         // BROKER_ID=1
	nodeAddr          = "RAFT_NODE_ADDRESS"      // NODE_ADDRESS=example.com NODE_ADDRESS=127.0.0.1:19865:19877
	cluster           = "RAFT_CLUSTER"           // CLUSTER=1=127.0.0.1:19865:19877,2=127.0.0.2:19865:19877,3=127.0.0.3:19865:19877
	timeCheckEnv      = "RAFT_TIME_CHECK"        // raft心跳定时检查超时时间
	timeoutEnv        = "RAFT_TIMEOUT"           // raft心跳定时/超时ms
	portEnv           = "RAFT_PORT"              // raft服务开放端口号，默认19877
	logDirEnv         = "RAFT_LOG_DIR"           // 日志文件目录
	logFileMaxSizeEnv = "RAFT_LOG_FILE_MAX_SIZE" // 每个日志文件保存的最大尺寸 单位：M
	logFileMaxAgeEnv  = "RAFT_LOG_FILE_MAX_AGE"  // 文件最多保存多少天
	logUtcEnv         = "RAFT_LOG_UTC"           // CST & UTC 时间
	logLevelEnv       = "RAFT_LOG_LEVEL"         // 日志级别(debugLevel/infoLevel/warnLevel/ErrorLevel/panicLevel/fatalLevel)
	logProductionEnv  = "RAFT_LOG_PRODUCTION"    // 是否生产环境，在生产环境下控制台不会输出任何日志
)

func init() {
	// self
	GRPCPort = gnomon.Env().GetIntD(GRPCPortEnv, 9877)
	HttpPort = gnomon.Env().GetIntD(HTTPPortEnv, 9865)
	defaultDataPath := "/home/go/src/github.com/aberic/fabric-client-go/example"
	dataPath = gnomon.Env().GetD(DataPath, defaultDataPath)
	RaftStatus = gnomon.Env().GetBool(raftStatusEnv)
	// self & raft log
	LogFileDir = gnomon.Env().GetD(logDirEnv, os.TempDir())
	LogFileMaxSize = gnomon.Env().GetIntD(logFileMaxSizeEnv, 1024)
	LogFileMaxAge = gnomon.Env().GetIntD(logFileMaxAgeEnv, 7)
	LogUtc = gnomon.Env().GetBool(logUtcEnv)
	LogLevel = gnomon.Env().GetD(logLevelEnv, "Debug")
	LogProduction = gnomon.Env().GetBool(logProductionEnv)
}

func InitLog() error {
	if err := gnomon.Log().Init(LogFileDir, LogFileMaxSize, LogFileMaxAge, LogUtc); nil != err {
		return err
	}
	var level gnomon.Level
	switch strings.ToLower(LogLevel) {
	case "debug":
		level = gnomon.Log().DebugLevel()
	case "info":
		level = gnomon.Log().InfoLevel()
	case "warn":
		level = gnomon.Log().WarnLevel()
	case "error":
		level = gnomon.Log().ErrorLevel()
	case "panic":
		level = gnomon.Log().PanicLevel()
	case "fatal":
		level = gnomon.Log().FatalLevel()
	default:
		level = gnomon.Log().DebugLevel()
	}
	gnomon.Log().Set(level, LogProduction)
	return nil
}

func ObtainDataPath() string {
	return dataPath
}
