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

type RespImpl struct {
	// 请求返回结果：success=0；fail=1
	Code int `json:"code,omitempty"`
	// 当且仅当返回码为1时，此处包含错误信息
	ErrMsg string `json:"errMsg,omitempty"`
}

func (r *RespImpl) Reset() {
	r.Code = 0
	r.ErrMsg = ""
}

func (r *RespImpl) GetErrMsg() string {
	return r.ErrMsg
}

func (r *RespImpl) Fail(errMsg string) {
	r.Code = 1
	r.ErrMsg = errMsg
}
