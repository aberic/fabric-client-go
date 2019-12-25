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
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/cauthdsl"
	"net/http"
)

// install 安装智能合约
func install(peerName, name, goPath, chainCodePath, version string, client *resmgmt.Client) (string, error) {
	ccPkg, err := gopackager.NewCCPackage(chainCodePath, goPath)
	if err != nil {
		gnomon.Log().Error("install", gnomon.Log().Err(err))
		return "", err
	}
	// Install example cc to org peers
	installCCReq := resmgmt.InstallCCRequest{Name: name, Path: chainCodePath, Version: version, Package: ccPkg}
	respList, err := client.InstallCC(installCCReq, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(peerName))
	if err != nil {
		gnomon.Log().Error("install", gnomon.Log().Err(err))
		return "", err
	}
	for _, resp := range respList {
		if resp.Status == http.StatusOK {
			return resp.Info, nil
		}
	}
	return "", err
}

type ChainCodeInfoArr struct {
	ChainCodes []*peer.ChaincodeInfo `json:"chaincodes"`
}

// args [][]byte{[]byte(coll1), []byte("key"), []byte("value")}
func instantiate(peerName, channelID, name, path, version string, orgPolicies []string, args [][]byte, client *resmgmt.Client) (string, error) {
	ccPolicy := cauthdsl.SignedByAnyMember(orgPolicies)
	// Org resource manager will instantiate 'example_cc' on channel
	resp, err := client.InstantiateCC(
		channelID,
		resmgmt.InstantiateCCRequest{Name: name, Path: path, Version: version, Args: args, Policy: ccPolicy},
		resmgmt.WithRetry(retry.DefaultResMgmtOpts),
		resmgmt.WithTargetEndpoints(peerName),
	)
	if err != nil {
		gnomon.Log().Error("instantiate", gnomon.Log().Err(err))
		return "", err
	}
	return string(resp.TransactionID), nil
}

// args [][]byte{[]byte(coll1), []byte("key"), []byte("value")}
func upgrade(peerName, channelID, name, path, version string, orgPolicies []string, args [][]byte, client *resmgmt.Client) (string, error) {
	ccPolicy := cauthdsl.SignedByAnyMember(orgPolicies)
	// Org resource manager will instantiate 'example_cc' on channel
	resp, err := client.UpgradeCC(
		channelID,
		resmgmt.UpgradeCCRequest{Name: name, Path: path, Version: version, Args: args, Policy: ccPolicy},
		resmgmt.WithRetry(retry.DefaultResMgmtOpts),
		resmgmt.WithTargetEndpoints(peerName),
	)
	if err != nil {
		gnomon.Log().Error("upgrade", gnomon.Log().Err(err))
		return "", err
	}
	return string(resp.TransactionID), nil
}

// peer 参见peer.go Peer
func queryInstalled(orgName, orgUser, peerName string, sdk *fabsdk.FabricSDK) ([]*peer.ChaincodeInfo, error) {
	//prepare context
	adminContext := sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))
	// Org resource management client
	orgResMgmt, err := resmgmt.New(adminContext)
	if err != nil {
		gnomon.Log().Error("queryInstalled", gnomon.Log().Err(err))
		return nil, err
	} else {
		if nil != orgResMgmt {
			qiResponse, err := orgResMgmt.QueryInstalledChaincodes(resmgmt.WithTargetEndpoints(peerName))
			if err != nil {
				gnomon.Log().Error("queryInstalled", gnomon.Log().Err(err))
				return nil, err
			} else {
				return qiResponse.Chaincodes, nil
			}
		} else {
			gnomon.Log().Error("queryInstalled", gnomon.Log().Err(err))
			return nil, err
		}
	}
}

// peer 参见peer.go Peer
func queryInstantiated(orgName, orgUser, channelID, peerName string, sdk *fabsdk.FabricSDK) ([]*peer.ChaincodeInfo, error) {
	//prepare context
	adminContext := sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))
	// Org resource management client
	orgResMgmt, err := resmgmt.New(adminContext)
	if err != nil {
		gnomon.Log().Error("queryInstantiated", gnomon.Log().Err(err))
		return nil, err
	} else {
		if nil != orgResMgmt {
			qiResponse, err := orgResMgmt.QueryInstantiatedChaincodes(channelID, resmgmt.WithTargetEndpoints(peerName))
			if err != nil {
				gnomon.Log().Error("queryInstantiated", gnomon.Log().Err(err))
				return nil, err
			} else {
				return qiResponse.Chaincodes, nil
			}
		} else {
			gnomon.Log().Error("queryInstantiated", gnomon.Log().Err(err))
			return nil, err
		}
	}
}

// fcn invoke
// args [][]byte{[]byte(coll1), []byte("key"), []byte("value")}
func invoke(chaincodeID, fcn string, args [][]byte, client *channel.Client, targetEndpoints ...string) ([]byte, string, error) {
	resp, err := client.Execute(channel.Request{
		ChaincodeID: chaincodeID,
		Fcn:         fcn,
		Args:        args,
	}, channel.WithRetry(retry.DefaultChannelOpts), channel.WithTargetEndpoints(targetEndpoints...))
	if err != nil {
		gnomon.Log().Error("invoke", gnomon.Log().Err(err))
		return nil, "", err
	}
	return resp.Payload, string(resp.TransactionID), nil
}

// fcn query
// args [][]byte{[]byte(coll1), []byte("key"), []byte("value")}
func query(chaincodeID, fcn string, args [][]byte, client *channel.Client, targetEndpoints ...string) ([]byte, string, error) {
	resp, err := client.Query(channel.Request{
		ChaincodeID: chaincodeID,
		Fcn:         fcn,
		Args:        args,
	}, channel.WithRetry(retry.DefaultChannelOpts), channel.WithTargetEndpoints(targetEndpoints...))
	if err != nil {
		gnomon.Log().Error("query", gnomon.Log().Err(err))
		return nil, "", err
	}
	return resp.Payload, string(resp.TransactionID), nil
}

func queryCollectionsConfig(orgName, orgUser, peerName, channelID, chaincodeID string, sdk *fabsdk.FabricSDK) (*common.CollectionConfigPackage, error) {
	//prepare context
	adminContext := sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))
	// Org resource management client
	orgResMgmt, err := resmgmt.New(adminContext)
	if err != nil {
		gnomon.Log().Error("queryCollectionsConfig", gnomon.Log().Err(err))
		return nil, err
	} else {
		if nil != orgResMgmt {
			coll, err := orgResMgmt.QueryCollectionsConfig(channelID, chaincodeID, resmgmt.WithTargetEndpoints(peerName))
			if err != nil {
				gnomon.Log().Error("queryCollectionsConfig", gnomon.Log().Err(err))
				return nil, err
			}
			return coll, nil
		} else {
			gnomon.Log().Error("queryCollectionsConfig", gnomon.Log().Err(err))
			return nil, err
		}
	}
}
