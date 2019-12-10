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
	gCa "github.com/aberic/fabric-client-go/grpc/proto/ca"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"net"
	"strconv"
	"strings"
)

func main() {
	go httpListener()
	grpcListener()
}

// setupRouter 设置路由器相关选项
func httpListener() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	ca.Router(router)
	port := strconv.Itoa(utils.HttpPort)
	gnomon.Log().Info(strings.Join([]string{"main http listener start with port ", port}, ""))
	if err := router.Run(strings.Join([]string{":", port}, "")); nil != err {
		gnomon.Log().Panic("main http listener", gnomon.Log().Err(err))
	}
}

func grpcListener() {
	var (
		listener net.Listener
		port     = strconv.Itoa(utils.GRPCPort)
		err      error
	)
	//  创建server端监听端口
	if listener, err = net.Listen("tcp", strings.Join([]string{":", port}, "")); nil != err {
		panic(err)
	}
	//  创建grpc的server
	rpcServer := grpc.NewServer()

	//  注册服务
	gCa.RegisterGenerateServer(rpcServer, &ca.GenerateServer{})

	gnomon.Log().Info(strings.Join([]string{"main grpc listener start with port ", port}, ""))
	//  启动grpc服务
	if err = rpcServer.Serve(listener); nil != err {
		gnomon.Log().Panic("main grpc listener", gnomon.Log().Err(err))
	}
}