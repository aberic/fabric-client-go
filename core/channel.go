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
	"fmt"
	"github.com/aberic/gnomon/log"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/pkg/errors"
	"io"
	"time"
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
		log.Error("Create", log.Err(err))
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
		log.Error("createChannel", log.Err(err))
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
		log.Error("Create", log.Err(err))
		return err
	}
	// Org peers join channel
	if err := resMgmtClient.JoinChannel(channelID, resmgmt.WithTargetEndpoints(peerName)); err != nil {
		log.Error("joinChannel", log.Err(err))
		return errors.Errorf("Org peers failed to JoinChannel:  %v", err)
	}
	return nil
}

func channelList(orgName, orgUser, peerName string, configBytes []byte) ([]*peer.ChannelInfo, error) {
	sdk, err := obtainSDK(configBytes)
	if err != nil {
		log.Error("Channels", log.Err(err))
		return nil, err
	}
	defer sdk.Close()
	//prepare context
	adminContext := sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))
	// Org resource management client
	orgResMgmt, err := resmgmt.New(adminContext)
	if err != nil {
		log.Error("queryChannels", log.Err(err))
		return nil, errors.Errorf("Failed to query channels:  %v", err)
	}
	if nil != orgResMgmt {
		qcResponse, err := orgResMgmt.QueryChannels(resmgmt.WithTargetEndpoints(peerName))
		if err != nil {
			log.Error("queryChannels", log.Err(err))
			return nil, errors.Errorf("Failed to query channels: peer cannot be nil.  %v", err)
		}
		if nil == qcResponse {
			log.Error("queryChannels", log.Err(err))
			return nil, errors.Errorf("qcResponse error should be nil. ")
		}
		return qcResponse.Channels, nil
	}
	log.Error("queryChannels", log.Err(err))
	return nil, errors.Errorf("orgResMgmt error should be nil. ")
}

func channelConfigBlockFromOrderer(channelID, orgName, orgUser, peerName string, configBytes []byte) (block *common.Block, err error) {
	sdk, err := obtainSDK(configBytes)
	if err != nil {
		log.Error("Channels", log.Err(err))
		return nil, err
	}
	defer sdk.Close()
	//prepare context
	adminContext := sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))
	// Org resource management client
	orgResMgmt, err := resmgmt.New(adminContext)
	if err != nil {
		log.Error("queryChannels", log.Err(err))
		return nil, errors.Errorf("Failed to query channels:  %v", err)
	}
	if nil != orgResMgmt {
		return orgResMgmt.QueryConfigBlockFromOrderer(channelID, resmgmt.WithTargetEndpoints(peerName))
	}
	log.Error("queryChannels", log.Err(err))
	return nil, errors.Errorf("orgResMgmt error should be nil. ")
}

func channelUpdateConfigBlock(channelID, consortium, orgName, orgUser, peerName, newOrgName string, configBytes, genesisBlockBytes []byte) ([]byte, error) {
	originalBlock, err := channelConfigBlockFromOrderer(channelID, orgName, orgUser, peerName, configBytes)
	if nil != err {
		return nil, err
	}
	return addOrg(channelID, consortium, newOrgName, originalBlock, genesisBlockBytes)
}

// envelopeBytes为类mychannel_update.pb性质文件直接读取值，是通道比对后的更新文件
func channelSign(orgName, orgUser, channelID string, configBytes, envelopeBytes []byte) ([]byte, error) {
	var (
		envelope                                                                  *common.Envelope
		payload                                                                   *common.Payload
		ch                                                                        *common.ChannelHeader
		configUpdateEnv                                                           *common.ConfigUpdateEnvelope
		ctx                                                                       context.Client
		configSig, payloadSig                                                     *common.ConfigSignature
		configUpdateBytes, channelHeaderBytes, signatureHeaderBytes, payloadBytes []byte
		newEnvelopeBytes                                                          []byte
		err                                                                       error
	)
	// 根据本次操作用户及所属组织信息，通过全局配置获取其操作具体客户端上下文
	clientContext, _ := clientContext(orgName, orgUser, configBytes)
	if ctx, err = clientContext(); nil != err {
		return nil, err
	}
	// 签名数据获取签名结果 common.ConfigSignature
	if configSig, _, err = sign(ctx, envelopeBytes); nil != err {
		return nil, err
	}

	// 解析结构为 common.Envelope
	if envelope, err = unmarshalEnvelope(envelopeBytes); nil != err {
		return nil, err
	}
	// 解析结构为 common.Payload
	if payload, err = extractPayload(envelope); nil != err {
		return nil, err
	}
	// 判空
	if payload.Header == nil || payload.Header.ChannelHeader == nil {
		return nil, fmt.Errorf("bad header error: %e", err)
	}
	// 解析结构为 common.ChannelHeader
	if ch, err = unmarshalChannelHeader(payload.Header.ChannelHeader); err != nil {
		return nil, fmt.Errorf("could not unmarshall channel header error: %e", err)
	}
	// 判定本次通道执行类型
	if ch.Type != int32(common.HeaderType_CONFIG_UPDATE) {
		return nil, fmt.Errorf("bad type error: %e", err)
	}
	// 判定本次执行通道名称是否为空
	if ch.ChannelId == "" {
		return nil, fmt.Errorf("empty channel id error: %e", err)
	}
	// 判定本次执行通道名称是否与待执行通道名称一致
	if ch.ChannelId != channelID {
		return nil, errors.New(fmt.Sprintf("mismatched channel ID %s != %s", ch.ChannelId, channelID))
	}
	// 解析结构为 common.ConfigUpdateEnvelope
	if configUpdateEnv, err = unmarshalConfigUpdateEnvelope(payload.Data); err != nil {
		return nil, fmt.Errorf("bad config update env error: %e", err)
	}
	// 将开头执行的签名结果追加到 envelope 的签名集合中
	configUpdateEnv.Signatures = append(configUpdateEnv.Signatures, configSig)
	if configUpdateBytes, err = proto.Marshal(configUpdateEnv); nil != err {
		return nil, err
	}
	// 拼接新的payload
	channelHeader := &common.ChannelHeader{
		Type:    ch.Type,
		Version: 0,
		Timestamp: &timestamp.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos:   0,
		},
		ChannelId: channelID,
		Epoch:     0,
	}
	if channelHeaderBytes, err = proto.Marshal(channelHeader); nil != err {
		return nil, err
	}
	if _, signatureHeaderBytes, err = getSignatureHeader(ctx); nil != err {
		return nil, err
	}
	payload.Data = configUpdateBytes
	payload.Header = &common.Header{
		ChannelHeader:   channelHeaderBytes,
		SignatureHeader: signatureHeaderBytes,
	}
	if payloadBytes, err = proto.Marshal(payload); nil != err {
		return nil, err
	}
	// 签名数据获取签名结果 common.Payload
	if payloadSig, _, err = sign(ctx, payloadBytes); nil != err {
		return nil, err
	}
	newEnvelope := &common.Envelope{
		Payload:   payloadBytes,
		Signature: payloadSig.Signature,
	}
	if newEnvelopeBytes, err = proto.Marshal(newEnvelope); nil != err {
		return nil, err
	}
	return newEnvelopeBytes, nil
}
