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

// Peer Peer
type Peer struct{}

// Installed Installed
func (p *Peer) Installed(_ context.Context, req *core.ReqPeerInstalled) (*core.RespPeerInstalled, error) {
	return PeerQueryInstalled(req)
}

// Instantiated Instantiated
func (p *Peer) Instantiated(_ context.Context, req *core.ReqPeerInstantiated) (*core.RespPeerInstantiated, error) {
	return PeerQueryInstantiated(req)
}

// Channel Channel
type Channel struct{}

// Create Create
func (c *Channel) Create(_ context.Context, req *core.ReqChannelCreate) (*core.RespChannelCreate, error) {
	return ChannelCreate(req)
}

// Join Join
func (c *Channel) Join(_ context.Context, req *core.ReqChannelJoin) (*core.RespChannelJoin, error) {
	return ChannelJoin(req)
}

// List List
func (c *Channel) List(_ context.Context, req *core.ReqChannelList) (*core.RespChannelList, error) {
	return ChannelList(req)
}

// Config Config
func (c *Channel) Config(_ context.Context, req *core.ReqChannelConfigBlock) (*core.RespChannelConfigBlock, error) {
	return ChannelConfigBlock(req)
}

// Update Update
func (c *Channel) Update(_ context.Context, req *core.ReqChannelUpdateBlock) (*core.RespChannelUpdateBlock, error) {
	return ChannelUpdateConfigBlock(req)
}

// Sign Sign
func (c *Channel) Sign(_ context.Context, req *core.ReqChannelSign) (*core.RespChannelSign, error) {
	return ChannelSign(req)
}

// ChainCode ChainCode
type ChainCode struct{}

// Install Install
func (c *ChainCode) Install(_ context.Context, req *core.ReqChainCodeInstall) (*core.RespChainCodeInstall, error) {
	return ChainCodeInstall(req)
}

// Instantiate Instantiate
func (c *ChainCode) Instantiate(_ context.Context, req *core.ReqChainCodeInstantiate) (*core.RespChainCodeInstantiate, error) {
	return ChainCodeInstantiate(req)
}

// Upgrade Upgrade
func (c *ChainCode) Upgrade(_ context.Context, req *core.ReqChainCodeUpgrade) (*core.RespChainCodeUpgrade, error) {
	return ChainCodeUpgrade(req)
}

// Invoke Invoke
func (c *ChainCode) Invoke(_ context.Context, req *core.ReqChainCodeInvoke) (*core.RespChainCodeInvoke, error) {
	return ChainCodeInvoke(req)
}

// Query Query
func (c *ChainCode) Query(_ context.Context, req *core.ReqChainCodeQuery) (*core.RespChainCodeQuery, error) {
	return ChainCodeQuery(req)
}
