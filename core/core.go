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
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"gopkg.in/yaml.v2"
)

//////////////////////////////// channel start ////////////////////////////////

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
		return &core.RespChannelJoin{Code: core.Code_Fail, ErrMsg: err.Error()}, err
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

func ChannelConfigBlock(req *core.ReqChannelConfigBlock) (resp *core.RespChannelConfigBlock, err error) {
	var (
		conf           *config.Config
		confData, data []byte
		block          *common.Block
		errs           error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChannelConfigBlock{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return
	}
	_, orgs := conf.ObtainOrders()
	for _, org := range orgs {
		if block, err = channelConfigBlockFromOrderer(req.ChannelID, org.OrgName, org.UserName, req.PeerName, confData); nil == err {
			if data, err = proto.Marshal(block); nil == err {
				return &core.RespChannelConfigBlock{Code: core.Code_Success, GenesisBlockBytes: data}, nil
			}
			errs = fmt.Errorf("error: %w", err)
		} else {
			errs = fmt.Errorf("error: %w", err)
		}
	}
	return &core.RespChannelConfigBlock{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func ChannelUpdateConfigBlock(req *core.ReqChannelUpdateBlock) (resp *core.RespChannelUpdateBlock, err error) {
	var (
		conf                    *config.Config
		confData, envelopeBytes []byte
		errs                    error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChannelUpdateBlock{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return
	}
	_, orgs := conf.ObtainOrders()
	for _, org := range orgs {
		if envelopeBytes, err = channelUpdateConfigBlock(req.ChannelID, req.Consortium, org.OrgName, org.UserName, req.PeerName, req.NewOrgName, confData, req.GenesisBlockBytes); nil == err {
			return &core.RespChannelUpdateBlock{Code: core.Code_Success, EnvelopeBytes: envelopeBytes}, nil
		} else {
			errs = fmt.Errorf("error: %w", err)
		}
	}
	return &core.RespChannelUpdateBlock{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func ChannelSign(req *core.ReqChannelSign) (resp *core.RespChannelSign, err error) {
	var (
		conf                    *config.Config
		confData, envelopeBytes []byte
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChannelSign{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return
	}
	if envelopeBytes, err = channelSign(req.OrgName, req.OrgUser, req.ChannelID, confData, req.EnvelopeBytes); nil == err {
		return &core.RespChannelSign{Code: core.Code_Success, EnvelopeBytes: envelopeBytes}, nil
	}
	return &core.RespChannelSign{Code: core.Code_Fail, ErrMsg: err.Error()}, err
}

//////////////////////////////// channel end ////////////////////////////////

//////////////////////////////// chaincode start ////////////////////////////////

func ChainCodeInstall(req *core.ReqChainCodeInstall) (resp *core.RespChainCodeInstall, err error) {
	var (
		conf         *config.Config
		confData     []byte
		target, info string
		errs         error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChainCodeInstall{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return &core.RespChainCodeInstall{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if target, info, err = ccInstall(req.OrgName, req.OrgUser, req.PeerName, req.CcName, req.GoPath, req.CcPath, req.Version, confData); nil == err {
		return &core.RespChainCodeInstall{Code: core.Code_Success, Data: &core.InstallData{Target: target, Info: info}}, nil
	} else {
		errs = fmt.Errorf("error: %w", err)
	}
	return &core.RespChainCodeInstall{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func ChainCodeInstantiate(req *core.ReqChainCodeInstantiate) (resp *core.RespChainCodeInstantiate, err error) {
	var (
		conf     *config.Config
		confData []byte
		msg      string
		errs     error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChainCodeInstantiate{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return &core.RespChainCodeInstantiate{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if msg, err = ccInstantiate(req.OrgName, req.OrgUser, req.PeerName, req.ChannelID, req.CcName, req.CcPath, req.Version, req.OrgPolicies, req.Args, confData); nil == err {
		return &core.RespChainCodeInstantiate{Code: core.Code_Success, TxId: msg}, nil
	} else {
		errs = fmt.Errorf("error: %w", err)
	}
	return &core.RespChainCodeInstantiate{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func ChainCodeUpgrade(req *core.ReqChainCodeUpgrade) (resp *core.RespChainCodeUpgrade, err error) {
	var (
		conf     *config.Config
		confData []byte
		msg      string
		errs     error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChainCodeUpgrade{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return &core.RespChainCodeUpgrade{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if msg, err = ccUpgrade(req.OrgName, req.OrgUser, req.PeerName, req.ChannelID, req.CcName, req.CcPath, req.Version, req.OrgPolicies, req.Args, confData); nil == err {
		return &core.RespChainCodeUpgrade{Code: core.Code_Success, TxId: msg}, nil
	} else {
		errs = fmt.Errorf("error: %w", err)
	}
	return &core.RespChainCodeUpgrade{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func ChainCodeInvoke(req *core.ReqChainCodeInvoke) (resp *core.RespChainCodeInvoke, err error) {
	var (
		conf          *config.Config
		confData      []byte
		payload, txID string
		errs          error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChainCodeInvoke{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return &core.RespChainCodeInvoke{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if payload, txID, err = ccInvoke(req.OrgName, req.OrgUser, req.PeerName, req.ChannelID, req.CcName, req.Fcn, req.Args, confData); nil == err {
		return &core.RespChainCodeInvoke{Code: core.Code_Success, Data: &core.CCData{Payload: payload, TxId: txID}}, nil
	} else {
		errs = fmt.Errorf("error: %w", err)
	}
	return &core.RespChainCodeInvoke{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func ChainCodeQuery(req *core.ReqChainCodeQuery) (resp *core.RespChainCodeQuery, err error) {
	var (
		conf          *config.Config
		confData      []byte
		payload, txID string
		errs          error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespChainCodeQuery{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return &core.RespChainCodeQuery{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if payload, txID, err = ccQuery(req.OrgName, req.OrgUser, req.PeerName, req.ChannelID, req.CcID, req.Fcn, req.Args, confData); nil == err {
		return &core.RespChainCodeQuery{Code: core.Code_Success, Data: &core.CCData{Payload: payload, TxId: txID}}, nil
	} else {
		errs = fmt.Errorf("error: %w", err)
	}
	return &core.RespChainCodeQuery{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

//////////////////////////////// chaincode end ////////////////////////////////

//////////////////////////////// peer start ////////////////////////////////

func PeerQueryInstalled(req *core.ReqPeerInstalled) (resp *core.RespPeerInstalled, err error) {
	var (
		conf     *config.Config
		confData []byte
		errs     error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespPeerInstalled{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return &core.RespPeerInstalled{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	ccIs, err := peerQueryInstalled(req.OrgName, req.OrgUser, req.PeerName, confData)
	if nil == err {
		var ccInfos []*core.ChainCodeInfo
		for _, cci := range ccIs {
			ccInfos = append(ccInfos, &core.ChainCodeInfo{
				Name:    cci.Name,
				Version: cci.Version,
				Path:    cci.Path,
				Input:   cci.Input,
				Escc:    cci.Escc,
				Vscc:    cci.Vscc,
				Id:      cci.Id,
			})
		}
		return &core.RespPeerInstalled{Code: core.Code_Success, CcInfos: ccInfos}, nil
	} else {
		errs = fmt.Errorf("error: %w", err)
	}
	return &core.RespPeerInstalled{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

func PeerQueryInstantiated(req *core.ReqPeerInstantiated) (resp *core.RespPeerInstantiated, err error) {
	var (
		conf     *config.Config
		confData []byte
		errs     error
	)
	if conf, err = config.Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &core.RespPeerInstantiated{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	if confData, err = yaml.Marshal(&conf); nil != err {
		return &core.RespPeerInstantiated{Code: core.Code_Fail, ErrMsg: err.Error()}, err
	}
	ccIs, err := peerQueryInstantiated(req.OrgName, req.OrgUser, req.PeerName, req.ChannelID, confData)
	if nil == err {
		var ccInfos []*core.ChainCodeInfo
		for _, cci := range ccIs {
			ccInfos = append(ccInfos, &core.ChainCodeInfo{
				Name:    cci.Name,
				Version: cci.Version,
				Path:    cci.Path,
				Input:   cci.Input,
				Escc:    cci.Escc,
				Vscc:    cci.Vscc,
				Id:      cci.Id,
			})
		}
		return &core.RespPeerInstantiated{Code: core.Code_Success, CcInfos: ccInfos}, nil
	} else {
		errs = fmt.Errorf("error: %w", err)
	}
	return &core.RespPeerInstantiated{Code: core.Code_Fail, ErrMsg: errs.Error()}, errs
}

//////////////////////////////// peer end ////////////////////////////////
