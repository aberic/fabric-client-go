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
	"encoding/hex"
	"fmt"
	"github.com/aberic/gnomon"
	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	"net/http"
	"path"
	"strings"
)

var (
	Version     = "1.0"
	dataTmpPath string
)

func init() {
	dataTmpPath = path.Join("/tmp", "data")
}

// CatchAllErr 捕获所有异常信息并放入json到context，便于controller直接调用
func CatchAllErr(c *gin.Context) {
	if r := recover(); r != nil {
		//fmt.Printf("捕获到的错误：%s\n", r)
		resp := &RespImpl{}
		resp.Fail(fmt.Sprintf("An error occurred:%v \n", r))
		gnomon.Log().Error("catch all err", gnomon.Log().Field("recover", r))
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
}

func SKI(priKeyBytes []byte) (string, error) {
	if _, err := gnomon.File().Append("/tmp/ski.key", priKeyBytes, true); nil != err {
		return "", err
	}
	priKey, _, _ := csp.GeneratePrivateKey("/tmp/ski.key")
	return strings.Join([]string{hex.EncodeToString(priKey.SKI()), "sk"}, "_"), nil
}

func SKIFromFP(priKeyFilePath string) string {
	priKey, _, _ := csp.GeneratePrivateKey(priKeyFilePath)
	return strings.Join([]string{hex.EncodeToString(priKey.SKI()), "sk"}, "_")
}
