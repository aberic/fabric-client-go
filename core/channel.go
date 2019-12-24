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
	"github.com/aberic/gnomon"
	"github.com/hyperledger/fabric-protos-go/peer"
	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/pkg/errors"
	"io"
)

// setupAndRun enables testing an end-to-end scenario against the supplied SDK options
// the createChannel flag will be used to either create a channel and the example CC or not(ie run the tests with existing ch and CC)
func channelCreate(orderOrgName, orderOrgUser, orgName, orgUser, channelID string, channelConfig io.Reader, configBytes []byte,
	sdkOpts ...fabsdk.Option) (txID string, err error) {
	var (
		//clientCtx     context.ClientProvider
		//ctx           context.Client
		resMgmtClient *resmgmt.Client
		sdk           *fabsdk.FabricSDK
		mspClient     *mspclient.Client
		adminIdentity msp.SigningIdentity
		scResp        resmgmt.SaveChannelResponse
	)
	// Resource management client is responsible for managing channels (create/update channel)
	// Supply user that has privileges to create channel (in this case orderer admin)
	if _, resMgmtClient, sdk, err = resmgmtClient(orderOrgName, orderOrgUser, configBytes, sdkOpts...); nil != err {
		gnomon.Log().Error("Create", gnomon.Log().Err(err))
		return
	}
	//if ctx, err = clientCtx();nil!=err {
	//	return
	//}
	//ordererCfg, found := ctx.EndpointConfig().OrdererConfig(orderChildName)
	//if !found {
	//	return "", errors.Errorf("orderer not found for url : %s", orderChildName)
	//}
	//orderer, err := ctx.InfraProvider().CreateOrdererFromConfig(ordererCfg)
	//if err != nil {
	//	return "", errors.WithMessage(err, "creating orderer from config failed")
	//}
	defer sdk.Close()
	if mspClient, err = mspclient.New(sdk.Context(), mspclient.WithOrg(orgName)); nil != err {
		return
	}
	if adminIdentity, err = mspClient.GetSigningIdentity(orgUser); nil != err {
		return
	}
	req := resmgmt.SaveChannelRequest{
		ChannelID:         channelID,
		ChannelConfig:     channelConfig,
		SigningIdentities: []msp.SigningIdentity{adminIdentity},
	}
	if scResp, err = resMgmtClient.SaveChannel(req); nil != err {
		gnomon.Log().Error("createChannel", gnomon.Log().Err(err))
		return "", errors.Errorf("error should be nil. %v", err)
	}
	return string(scResp.TransactionID), nil
}

func channelJoin(orgName, orgUser, channelID, peerName string, configBytes []byte) error {
	var (
		resMgmtClient *resmgmt.Client
		err           error
	)
	if _, resMgmtClient, _, err = resmgmtClient(orgName, orgUser, configBytes); nil != err {
		gnomon.Log().Error("Create", gnomon.Log().Err(err))
		return err
	}
	// Org peers join channel
	if err := resMgmtClient.JoinChannel(channelID, resmgmt.WithTargetEndpoints(peerName)); err != nil {
		gnomon.Log().Error("joinChannel", gnomon.Log().Err(err))
		return errors.Errorf("Org peers failed to JoinChannel:  %v", err)
	}
	return nil
}

func channelList(orgName, orgUser, peerName string, configBytes []byte) ([]*peer.ChannelInfo, error) {
	sdk, err := obtainSDK(configBytes)
	if err != nil {
		gnomon.Log().Error("Channels", gnomon.Log().Err(err))
		return nil, err
	}
	defer sdk.Close()
	//prepare context
	adminContext := sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))
	// Org resource management client
	orgResMgmt, err := resmgmt.New(adminContext)
	if err != nil {
		gnomon.Log().Error("queryChannels", gnomon.Log().Err(err))
		return nil, errors.Errorf("Failed to query channels:  %v", err)
	} else {
		if nil != orgResMgmt {
			qcResponse, err := orgResMgmt.QueryChannels(resmgmt.WithTargetEndpoints(peerName))
			if err != nil {
				gnomon.Log().Error("queryChannels", gnomon.Log().Err(err))
				return nil, errors.Errorf("Failed to query channels: peer cannot be nil.  %v", err)
			}
			if nil == qcResponse {
				gnomon.Log().Error("queryChannels", gnomon.Log().Err(err))
				return nil, errors.Errorf("qcResponse error should be nil. ")
			} else {
				return qcResponse.Channels, nil
			}
		} else {
			gnomon.Log().Error("queryChannels", gnomon.Log().Err(err))
			return nil, errors.Errorf("orgResMgmt error should be nil. ")
		}
	}
}
