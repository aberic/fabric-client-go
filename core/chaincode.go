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
 *
 */

package core

import (
	"github.com/aberic/gnomon"
	"github.com/aberic/gnomon/log"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/cauthdsl"
	"net/http"
)

// ccInstall 安装智能合约
func ccInstall(orgName, orgUser, peerName, ccName, goPath, ccPath, version string, configBytes []byte,
	sdkOpts ...fabsdk.Option) (string, string, error) {
	var (
		ccPkg         *resource.CCPackage
		resMgmtClient *resmgmt.Client
		err           error
	)
	if ccPkg, err = gopackager.NewCCPackage(ccPath, goPath); err != nil {
		log.Error("install", log.Err(err))
		return "", "", err
	}
	if _, resMgmtClient, _, err = resmgmtClient(orgName, orgUser, configBytes, sdkOpts...); nil != err {
		log.Error("install", log.Err(err))
		return "", "", err
	}
	// Install example cc to org peers
	installCCReq := resmgmt.InstallCCRequest{Name: ccName, Path: ccPath, Version: version, Package: ccPkg}
	respList, err := resMgmtClient.InstallCC(
		installCCReq,
		resmgmt.WithRetry(retry.DefaultResMgmtOpts),
		resmgmt.WithTargetEndpoints(peerName),
	)
	if err != nil {
		log.Error("install", log.Err(err))
		return "", "", err
	}
	for _, resp := range respList {
		if resp.Status == http.StatusOK {
			return resp.Target, resp.Info, nil
		}
	}
	return "", "", err
}

// args [][]byte{[]byte(coll1), []byte("key"), []byte("value")}
func ccInstantiate(ordererName, orgName, orgUser, peerName, channelID, ccName, ccPath, version string, orgPolicies []string, args [][]byte,
	configBytes []byte, sdkOpts ...fabsdk.Option) (string, error) {
	var (
		resMgmtClient *resmgmt.Client
		resp          resmgmt.InstantiateCCResponse
		err           error
	)
	if _, resMgmtClient, _, err = resmgmtClient(orgName, orgUser, configBytes, sdkOpts...); nil != err {
		log.Error("instantiate", log.Err(err))
		return "", err
	}
	ccPolicy := cauthdsl.SignedByAnyMember(orgPolicies)
	options := []resmgmt.RequestOption{resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(peerName)}
	if !gnomon.StringIsEmpty(ordererName) {
		options = append(options, resmgmt.WithOrdererEndpoint(ordererName))
	}
	// Org resource manager will instantiate 'example_cc' on channel
	if resp, err = resMgmtClient.InstantiateCC(
		channelID,
		resmgmt.InstantiateCCRequest{Name: ccName, Path: ccPath, Version: version, Args: args, Policy: ccPolicy},
		options...,
	); err != nil {
		log.Error("instantiate", log.Err(err))
		return "", err
	}
	return string(resp.TransactionID), nil
}

// args [][]byte{[]byte(coll1), []byte("key"), []byte("value")}
func ccUpgrade(ordererName, orgName, orgUser, peerName, channelID, ccName, ccPath, version string, orgPolicies []string, args [][]byte,
	configBytes []byte, sdkOpts ...fabsdk.Option) (string, error) {
	var (
		resMgmtClient *resmgmt.Client
		resp          resmgmt.UpgradeCCResponse
		err           error
	)
	if _, resMgmtClient, _, err = resmgmtClient(orgName, orgUser, configBytes, sdkOpts...); nil != err {
		log.Error("upgrade", log.Err(err))
		return "", err
	}
	ccPolicy := cauthdsl.SignedByAnyMember(orgPolicies)
	options := []resmgmt.RequestOption{resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(peerName)}
	if !gnomon.StringIsEmpty(ordererName) {
		options = append(options, resmgmt.WithOrdererEndpoint(ordererName))
	}
	// Org resource manager will instantiate 'example_cc' on channel
	if resp, err = resMgmtClient.UpgradeCC(
		channelID,
		resmgmt.UpgradeCCRequest{Name: ccName, Path: ccPath, Version: version, Args: args, Policy: ccPolicy},
		options...,
	); err != nil {
		log.Error("upgrade", log.Err(err))
		return "", err
	}
	return string(resp.TransactionID), nil
}

// fcn invoke
// args [][]byte{[]byte(coll1), []byte("key"), []byte("value")}
func ccInvoke(orgName, orgUser, peerName, channelID, ccName, fcn string, args [][]byte, configBytes []byte, sdkOpts ...fabsdk.Option) (string, string, error) {
	var (
		chClient *channel.Client
		err      error
	)
	if chClient, err = channelClient(orgName, orgUser, channelID, configBytes, sdkOpts...); nil != err {
		log.Error("invoke", log.Err(err))
		return "", "", err
	}
	resp, err := chClient.Execute(channel.Request{
		ChaincodeID: ccName,
		Fcn:         fcn,
		Args:        args,
	}, channel.WithRetry(retry.DefaultChannelOpts), channel.WithTargetEndpoints(peerName))
	if err != nil {
		log.Error("invoke", log.Err(err))
		return "", "", err
	}
	return string(resp.Payload), string(resp.TransactionID), nil
}

// fcn query
// args [][]byte{[]byte(coll1), []byte("key"), []byte("value")}
func ccQuery(orgName, orgUser, peerName, channelID, chaincodeID, fcn string, args [][]byte, configBytes []byte, sdkOpts ...fabsdk.Option) (string, string, error) {
	var (
		chClient *channel.Client
		err      error
	)
	if chClient, err = channelClient(orgName, orgUser, channelID, configBytes, sdkOpts...); nil != err {
		log.Error("query", log.Err(err))
		return "", "", err
	}
	resp, err := chClient.Query(channel.Request{
		ChaincodeID: chaincodeID,
		Fcn:         fcn,
		Args:        args,
	}, channel.WithRetry(retry.DefaultChannelOpts), channel.WithTargetEndpoints(peerName))
	if err != nil {
		log.Error("query", log.Err(err))
		return "", "", err
	}
	return string(resp.Payload), string(resp.TransactionID), nil
}
