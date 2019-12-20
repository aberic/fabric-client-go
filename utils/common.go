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
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	"net/http"
	"os"
	"path"
	"path/filepath"
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

func SKI(leagueDomain, orgDomain, orgName, childName string, isUser bool, priKeyBytes []byte) (string, error) {
	symbol := "node"
	if isUser {
		symbol = "user"
	}
	fileName := strings.Join([]string{childName, "sk"}, "_")
	tmpPath := path.Join(os.TempDir(), leagueDomain, orgDomain, orgName, symbol)
	filePath := filepath.Join(os.TempDir(), leagueDomain, orgDomain, orgName, symbol, fileName)
	if _, err := gnomon.File().Append(filePath, priKeyBytes, true); nil != err {
		return "", err
	}
	return LoadPrivateKey(tmpPath)
}

func LoadPrivateKey(tmpPath string) (string, error) {
	priKey, _, err := csp.LoadPrivateKey(tmpPath)
	if nil != err {
		return "", err
	}
	return ObtainSKI(priKey)
}

func ObtainSKI(priKey bccsp.Key) (string, error) {
	return strings.Join([]string{hex.EncodeToString(priKey.SKI()), "sk"}, "_"), nil
}
