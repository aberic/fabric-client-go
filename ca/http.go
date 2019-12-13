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

package ca

import (
	"github.com/aberic/fabric-client-go/grpc/proto/ca"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Router(r *gin.Engine) {
	// 仓库相关路由设置
	vRepo := r.Group("/ca")
	//vRepo.POST("/generate/crypto", routerGenerateCrypto)
	vRepo.POST("/generate/crt/league", routerGenerateLeagueCrt)
	vRepo.POST("/generate/csr/child", routerGenerateOrgChildCsr)
	vRepo.POST("/generate/crt/child", routerGenerateOrgChildCrt)
}

// routerGenerateCrypto 生成密钥对
//func routerGenerateCrypto(c *gin.Context) {
//	defer utils.CatchAllErr(c)
//	serviceModel := new(ca.ReqKeyConfig)
//	if err := c.ShouldBindJSON(serviceModel); err != nil {
//		resp := &utils.RespImpl{}
//		resp.Fail(err.Error())
//		c.JSON(http.StatusOK, resp)
//		return
//	}
//	resp, _ := generateCrypto(serviceModel)
//	c.JSON(http.StatusOK, resp)
//}

// routerGenerateLeagueCrt 生成联盟根证书
func routerGenerateLeagueCrt(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(ca.ReqCreateLeague)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := generateLeagueCrt(serviceModel)
	c.JSON(http.StatusOK, resp)
}

// routerGenerateOrgChildCsr 生成CA请求证书文件
func routerGenerateOrgChildCsr(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(ca.ReqCreateCsr)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := generateOrgChildCsr(serviceModel)
	c.JSON(http.StatusOK, resp)
}

// routerGenerateOrgChildCrt 生成组织下子节点/用户证书
func routerGenerateOrgChildCrt(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(ca.ReqCreateOrgChild)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := generateOrgChildCrt(serviceModel)
	c.JSON(http.StatusOK, resp)
}
