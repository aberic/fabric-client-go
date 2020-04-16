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
	"github.com/aberic/fabric-client-go/utils/log"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

// peer 参见peer.go Peer
func peerQueryInstalled(orgName, orgUser, peerName string, configBytes []byte, sdkOpts ...fabsdk.Option) ([]*peer.ChaincodeInfo, error) {
	var (
		resMgmtClient *resmgmt.Client
		err           error
	)
	if _, resMgmtClient, _, err = resmgmtClient(orgName, orgUser, configBytes, sdkOpts...); nil != err {
		log.Error("queryInstalled", log.Err(err))
		return nil, err
	}
	qiResponse, err := resMgmtClient.QueryInstalledChaincodes(resmgmt.WithTargetEndpoints(peerName))
	if err != nil {
		log.Error("queryInstalled", log.Err(err))
		return nil, err
	} else {
		return qiResponse.Chaincodes, nil
	}
}

// peer 参见peer.go Peer
func peerQueryInstantiated(orgName, orgUser, peerName, channelID string, configBytes []byte, sdkOpts ...fabsdk.Option) ([]*peer.ChaincodeInfo, error) {
	var (
		resMgmtClient *resmgmt.Client
		err           error
	)
	if _, resMgmtClient, _, err = resmgmtClient(orgName, orgUser, configBytes, sdkOpts...); nil != err {
		log.Error("queryInstantiated", log.Err(err))
		return nil, err
	}
	qiResponse, err := resMgmtClient.QueryInstantiatedChaincodes(channelID, resmgmt.WithTargetEndpoints(peerName))
	if err != nil {
		log.Error("queryInstantiated", log.Err(err))
		return nil, err
	} else {
		return qiResponse.Chaincodes, nil
	}
}

func peerQueryCollectionsConfig(orgName, orgUser, peerName, channelID, chaincodeID string, configBytes []byte, sdkOpts ...fabsdk.Option) (*common.CollectionConfigPackage, error) {
	var (
		resMgmtClient *resmgmt.Client
		err           error
	)
	if _, resMgmtClient, _, err = resmgmtClient(orgName, orgUser, configBytes, sdkOpts...); nil != err {
		log.Error("queryCollectionsConfig", log.Err(err))
		return nil, err
	}
	return resMgmtClient.QueryCollectionsConfig(channelID, chaincodeID, resmgmt.WithTargetEndpoints(peerName))
}
