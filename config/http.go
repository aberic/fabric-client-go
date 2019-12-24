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
	"github.com/aberic/fabric-client-go/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Router(r *gin.Engine) {
	// 仓库相关路由设置
	vRepo := r.Group("/config")
	vRepo.POST("/set", routerConfigSet)
	vRepo.POST("/obtain", routerConfigObtain)
	vRepo.POST("/list", routerConfigList)
	vRepo.POST("/delete", routerConfigDelete)
}

// routerConfigSet 设置新的组织配置信息，用于访问fabric网络
func routerConfigSet(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(config.ReqConfigSet)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := setConfig(serviceModel)
	c.JSON(http.StatusOK, resp)
}

// routerConfigObtain 获取组织配置信息详情
func routerConfigObtain(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(config.ReqConfigObtain)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := obtainConfig(serviceModel)
	c.JSON(http.StatusOK, resp)
}

// routerConfigList 列出已有组织信息集合
func routerConfigList(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(config.ReqConfigList)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := listConfig(serviceModel)
	c.JSON(http.StatusOK, resp)
}

// routerConfigDelete 删除指定组织配置信息
func routerConfigDelete(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(config.ReqConfigDelete)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := deleteConfig(serviceModel)
	c.JSON(http.StatusOK, resp)
}
