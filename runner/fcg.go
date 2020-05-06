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

package main

import (
	"github.com/aberic/fabric-client-go/ca"
	"github.com/aberic/fabric-client-go/config"
	"github.com/aberic/fabric-client-go/core"
	"github.com/aberic/fabric-client-go/genesis"
	gCa "github.com/aberic/fabric-client-go/grpc/proto/ca"
	gConfig "github.com/aberic/fabric-client-go/grpc/proto/config"
	gCore "github.com/aberic/fabric-client-go/grpc/proto/core"
	gGenesis "github.com/aberic/fabric-client-go/grpc/proto/genesis"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"github.com/aberic/gnomon/grope"
	"github.com/aberic/gnomon/log"
	"github.com/aberic/raft4go"
	"google.golang.org/grpc"
	"net"
	"strings"
)

func main() {
	log.Fit(utils.LogLevel, utils.LogFileDir, utils.LogFileMaxSize, utils.LogFileMaxAge, utils.LogUtc, utils.LogProduction)
	if utils.RaftStatus {
		raft4go.RaftStart(params())
		go httpListener()
		go gRPCListener()
	} else {
		go httpListener()
		gRPCListener()
	}
}

// params raft环境变量初始化
func params() *raft4go.Params {
	p := &raft4go.Params{
		Node:          &raft4go.Node{},
		Nodes:         []*raft4go.Node{},
		TimeHeartbeat: gnomon.EnvGetInt64D(utils.TimeHeartbeatEnv, 1000),
		TimeCheckReq:  gnomon.EnvGetInt64D(utils.TimeCheckEnv, 1500),
		TimeoutReq:    gnomon.EnvGetInt64D(utils.TimeoutEnv, 2000),
		PortReq:       gnomon.EnvGetD(utils.PortEnv, "19877"),
		Log: &raft4go.Log{
			Level:       utils.LogLevel,
			Dir:         utils.LogFileDir,
			FileMaxSize: utils.LogFileMaxSize,
			FileMaxAge:  utils.LogFileMaxAge,
			Utc:         utils.LogUtc,
			Production:  utils.LogProduction,
		},
	}
	// 仅测试用
	//_ = os.Setenv(brokerID, "1")
	//_ = os.Setenv(nodeAddr, "127.0.0.1:19880")
	//_ = os.Setenv(cluster, "1=127.0.0.1:19877,2=127.0.0.1:19878,3=127.0.0.1:19879")
	if k8s := gnomon.EnvGetBool(utils.K8sEnv); k8s {
		if p.Node.Url = gnomon.EnvGet("HOSTNAME"); gnomon.StringIsEmpty(p.Node.Url) {
			log.Error("raft", log.Field("describe", "init with k8s fail"),
				log.Field("addr", p.Node.Url))
			return nil
		}
		p.Node.Id = strings.Split(p.Node.Url, "-")[1]
		log.Info("raft", log.Field("describe", "init with k8s"),
			log.Field("addr", p.Node.Url), log.Field("id", p.Node.Id))
	} else {
		if p.Node.Url = gnomon.EnvGet(utils.NodeAddrEnv); gnomon.StringIsEmpty(p.Node.Url) {
			log.Error("raft", log.Field("describe", "init with env fail"),
				log.Errs("NODE_ADDRESS is empty"))
			return nil
		}
		if p.Node.Id = gnomon.EnvGet(utils.BrokerIDEnv); gnomon.StringIsEmpty(p.Node.Id) {
			log.Error("raft", log.Field("describe", "init with env fail"),
				log.Errs("broker id is not appoint"))
			return nil
		}
		log.Info("raft", log.Field("describe", "init with env"),
			log.Field("addr", p.Node.Url), log.Field("id", p.Node.Id))
	}
	p.Node.UnusualTimes = -1
	initCluster(p)
	return p
}

// initCluster 初始化集群节点
func initCluster(p *raft4go.Params) {
	nodesStr := gnomon.EnvGet(utils.ClusterEnv)
	log.Info("raft", log.Field("node cluster", nodesStr))
	if gnomon.StringIsNotEmpty(nodesStr) {
		clusterArr := strings.Split(nodesStr, ",")
		for _, cluster := range clusterArr {
			clusterSplit := strings.Split(cluster, "=")
			id := clusterSplit[0]
			if gnomon.StringIsEmpty(id) {
				log.Error("raft", log.Field("describe", "init with env fail"),
					log.Errs("one of cluster's broker id is nil"))
				continue
			}
			if id == p.Node.Id {
				continue
			}
			nodeURL := clusterSplit[1]
			p.Nodes = append(p.Nodes, &raft4go.Node{Id: id, Url: nodeURL, UnusualTimes: 0})
		}
	}
}

// setupRouter 设置路由器相关选项
func httpListener() {
	httpServe := grope.NewHTTPServe()
	ca.Router(httpServe)
	config.Router(httpServe)
	genesis.Router(httpServe)
	grope.ListenAndServe(strings.Join([]string{":", utils.HTTPPort}, ""), httpServe)
}

func gRPCListener() {
	var (
		listener net.Listener
		err      error
	)
	//  创建server端监听端口
	if listener, err = net.Listen("tcp", strings.Join([]string{":", utils.GRPCPort}, "")); nil != err {
		panic(err)
	}
	//  创建grpc的server
	rpcServer := grpc.NewServer()

	//  注册服务
	gCa.RegisterGenerateServer(rpcServer, &ca.GenerateServer{})
	gConfig.RegisterConfigServer(rpcServer, &config.ConfServer{})
	gGenesis.RegisterGenesisServer(rpcServer, &genesis.BlockServer{})
	gCore.RegisterPeerServer(rpcServer, &core.Peer{})
	gCore.RegisterChannelServer(rpcServer, &core.Channel{})
	gCore.RegisterChaincodeServer(rpcServer, &core.ChainCode{})

	log.Info(strings.Join([]string{"main gRPC listener start with port ", utils.GRPCPort}, ""))
	//  启动grpc服务
	if err = rpcServer.Serve(listener); nil != err {
		log.Panic("main gRPC listener", log.Err(err))
	}
}
