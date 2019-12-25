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
	"github.com/aberic/fabric-client-go/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Router(r *gin.Engine) {
	// 仓库相关路由设置
	vRepo := r.Group("/genesis")
	vRepo.POST("/block", routerCreateGenesisBlock)
	vRepo.POST("/channel", routerCreateChannelTx)
}

// routerCreateGenesisBlock 生成创世区块
func routerCreateGenesisBlock(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(genesis.ReqGenesisBlock)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := createGenesisBlock(serviceModel)
	c.JSON(http.StatusOK, resp)
}

// routerCreateChannelTx 生成通道/账本初始区块
func routerCreateChannelTx(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(genesis.ReqChannelTx)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := createChannelTx(serviceModel)
	c.JSON(http.StatusOK, resp)
}
