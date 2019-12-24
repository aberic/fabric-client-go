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

package core

import (
	"bytes"
	"fmt"
	"github.com/aberic/fabric-client-go/config"
	"github.com/aberic/fabric-client-go/grpc/proto/core"
	"github.com/hyperledger/fabric-protos-go/peer"
	"gopkg.in/yaml.v2"
)

func ChannelCreate(req *core.ReqChannelCreate) (resp *core.RespChannelCreate, err error) {
	var (
		conf     *config.Config
		confData []byte
		txID     string
		errs     error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChannelCreate{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return &core.RespChannelCreate{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	buf := bytes.NewBuffer(req.ChannelTxBytes)
	orders, orgs := conf.ObtainOrders()
	for _, order := range orders {
		for _, org := range orgs {
			if txID, err = channelCreate(order.OrgName, order.UserName, org.OrgName, org.UserName, req.ChannelID, buf, confData); nil == err {
				return &core.RespChannelCreate{Code: core.Code_Success, TxId: txID}, nil
			} else {
				errs = fmt.Errorf("error: %w", err)
			}
		}
	}
	return &core.RespChannelCreate{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func ChannelJoin(req *core.ReqChannelJoin) (resp *core.RespChannelJoin, err error) {
	var (
		conf     *config.Config
		confData []byte
		errs     error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChannelJoin{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return
	}
	_, orgs := conf.ObtainOrders()
	for _, org := range orgs {
		if err = channelJoin(org.OrgName, org.UserName, req.ChannelID, req.PeerName, confData); nil == err {
			return &core.RespChannelJoin{Code: core.Code_Success}, nil
		} else {
			errs = fmt.Errorf("error: %w", err)
		}
	}
	return &core.RespChannelJoin{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func ChannelList(req *core.ReqChannelList) (resp *core.RespChannelList, err error) {
	var (
		conf     *config.Config
		confData []byte
		chInfos  []*peer.ChannelInfo
		errs     error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChannelList{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return
	}
	_, orgs := conf.ObtainOrders()
	for _, org := range orgs {
		if chInfos, err = channelList(org.OrgName, org.UserName, req.PeerName, confData); nil == err {
			var chIDs []string
			for _, chInfo := range chInfos {
				chIDs = append(chIDs, chInfo.ChannelId)
			}
			return &core.RespChannelList{Code: core.Code_Success, ChannelIDs: chIDs}, nil
		} else {
			errs = fmt.Errorf("error: %w", err)
		}
	}
	return &core.RespChannelList{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}
