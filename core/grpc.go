/*
 * Copyright (c) 2020. Aberic - All Rights Reserved.
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

package core

import (
	"context"
	"github.com/aberic/fabric-client-go/grpc/proto/core"
)

type Peer struct{}

func (p *Peer) Installed(ctx context.Context, req *core.ReqPeerInstalled) (*core.RespPeerInstalled, error) {
	return PeerQueryInstalled(req)
}

func (p *Peer) Instantiated(ctx context.Context, req *core.ReqPeerInstantiated) (*core.RespPeerInstantiated, error) {
	return PeerQueryInstantiated(req)
}

type Channel struct{}

func (c *Channel) Create(ctx context.Context, req *core.ReqChannelCreate) (*core.RespChannelCreate, error) {
	return ChannelCreate(req)
}

func (c *Channel) Join(ctx context.Context, req *core.ReqChannelJoin) (*core.RespChannelJoin, error) {
	return ChannelJoin(req)
}

func (c *Channel) List(ctx context.Context, req *core.ReqChannelList) (*core.RespChannelList, error) {
	return ChannelList(req)
}

func (c *Channel) Config(ctx context.Context, req *core.ReqChannelConfigBlock) (*core.RespChannelConfigBlock, error) {
	return ChannelConfigBlock(req)
}

func (c *Channel) Update(ctx context.Context, req *core.ReqChannelUpdateBlock) (*core.RespChannelUpdateBlock, error) {
	return ChannelUpdateConfigBlock(req)
}

func (c *Channel) Sign(ctx context.Context, req *core.ReqChannelSign) (*core.RespChannelSign, error) {
	return ChannelSign(req)
}

type ChainCode struct{}

func (c *ChainCode) Install(ctx context.Context, req *core.ReqChainCodeInstall) (*core.RespChainCodeInstall, error) {
	return ChainCodeInstall(req)
}

func (c *ChainCode) Instantiate(ctx context.Context, req *core.ReqChainCodeInstantiate) (*core.RespChainCodeInstantiate, error) {
	return ChainCodeInstantiate(req)
}

func (c *ChainCode) Upgrade(ctx context.Context, req *core.ReqChainCodeUpgrade) (*core.RespChainCodeUpgrade, error) {
	return ChainCodeUpgrade(req)
}

func (c *ChainCode) Invoke(ctx context.Context, req *core.ReqChainCodeInvoke) (*core.RespChainCodeInvoke, error) {
	return ChainCodeInvoke(req)
}

func (c *ChainCode) Query(ctx context.Context, req *core.ReqChainCodeQuery) (*core.RespChainCodeQuery, error) {
	return ChainCodeQuery(req)
}
