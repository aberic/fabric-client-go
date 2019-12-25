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
	"context"
	"github.com/aberic/fabric-client-go/grpc/proto/genesis"
)

// BlockServer fabric创世相关操作
type BlockServer struct{}

// CreateGenesisBlock 生成创世区块
func (bs *BlockServer) CreateGenesisBlock(ctx context.Context, req *genesis.ReqGenesisBlock) (*genesis.RespGenesisBlock, error) {
	return createGenesisBlock(req)
}

// CreateChannelTx 生成通道/账本初始区块
func (bs *BlockServer) CreateChannelTx(ctx context.Context, req *genesis.ReqChannelTx) (*genesis.RespChannelTx, error) {
	return createChannelTx(req)
}
