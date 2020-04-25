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
	"github.com/aberic/fabric-client-go/genesis"
	gCa "github.com/aberic/fabric-client-go/grpc/proto/ca"
	gConfig "github.com/aberic/fabric-client-go/grpc/proto/config"
	gGenesis "github.com/aberic/fabric-client-go/grpc/proto/genesis"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/fabric-client-go/utils/log"
	"github.com/aberic/gnomon/grope"
	"github.com/aberic/raft4go"
	"google.golang.org/grpc"
	"net"
	"strings"
)

func main() {
	if utils.RaftStatus {
		raft4go.RaftStart()
		go httpListener()
		go gRPCListener()
	} else {
		go httpListener()
		gRPCListener()
	}
}

// setupRouter 设置路由器相关选项
func httpListener() {
	httpServe := grope.NewHttpServe()
	ca.Router(httpServe)
	config.Router(httpServe)
	genesis.Router(httpServe)
	grope.ListenAndServe(strings.Join([]string{":", utils.HttpPort}, ""), httpServe)
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

	log.Info(strings.Join([]string{"main gRPC listener start with port ", utils.GRPCPort}, ""))
	//  启动grpc服务
	if err = rpcServer.Serve(listener); nil != err {
		log.Panic("main gRPC listener", log.Err(err))
	}
}
