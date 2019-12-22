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
	vRepo.POST("/generate/crypto/root", routerGenerateRootCrypto)
	vRepo.POST("/generate/crypto", routerGenerateCrypto)
	vRepo.POST("/sign/crt", routerSignCertificate)
}

// routerGenerateRootCrypto 生成联盟根证书
func routerGenerateRootCrypto(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(ca.ReqRootCrypto)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := generateRootCrypto(serviceModel)
	c.JSON(http.StatusOK, resp)
}

// routerGenerateCrypto 生成密钥对
func routerGenerateCrypto(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(ca.ReqCrypto)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := generateCrypto(serviceModel)
	c.JSON(http.StatusOK, resp)
}

// routerSignCertificate 生成组织下子节点/用户证书
func routerSignCertificate(c *gin.Context) {
	defer utils.CatchAllErr(c)
	serviceModel := new(ca.ReqSignCertificate)
	if err := c.ShouldBindJSON(serviceModel); err != nil {
		resp := &utils.RespImpl{}
		resp.Fail(err.Error())
		c.JSON(http.StatusOK, resp)
		return
	}
	resp, _ := signCertificate(serviceModel)
	c.JSON(http.StatusOK, resp)
}
