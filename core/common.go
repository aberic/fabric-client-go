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
	"errors"
	"fmt"
	"github.com/aberic/gnomon/log"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

// SDK fabsdk.FabricSDK
func obtainSDK(configBytes []byte, sdkOpts ...fabsdk.Option) (*fabsdk.FabricSDK, error) {
	configOpt := config.FromRaw(configBytes, "yaml")
	sdk, err := fabsdk.New(configOpt, sdkOpts...)
	if err != nil {
		return nil, err
	}
	if nil == sdk {
		return nil, fmt.Errorf("sdk error should be nil")
	}
	return sdk, nil
}

// ClientContext context.ClientProvider
func clientContext(orgName, orgUser string, configBytes []byte,
	sdkOpts ...fabsdk.Option) (context.ClientProvider, *fabsdk.FabricSDK) {
	sdk, err := obtainSDK(configBytes, sdkOpts...)
	if err != nil {
		return nil, nil
	}
	//clientContext allows creation of transactions using the supplied identity as the credential.
	return sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName)), sdk
}

// ResmgmtClient resmgmt.Client
func resmgmtClient(orgName, orgUser string, configBytes []byte,
	sdkOpts ...fabsdk.Option) (context.ClientProvider, *resmgmt.Client, *fabsdk.FabricSDK, error) {
	sdk, err := obtainSDK(configBytes, sdkOpts...)
	if err != nil {
		return nil, nil, nil, err
	}
	//clientContext allows creation of transactions using the supplied identity as the credential.
	clientContext := sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))

	// Org resource management client
	orgResMgmt, err := resmgmt.New(clientContext)
	if err != nil {
		return nil, nil, nil, err
	}
	return clientContext, orgResMgmt, sdk, nil
}

func channelClient(orgName, orgUser, channelID string, configBytes []byte, sdkOpts ...fabsdk.Option) (*channel.Client, error) {
	sdk, err := obtainSDK(configBytes, sdkOpts...)
	if err != nil {
		return nil, err
	}
	//prepare channel client context using client context
	ctxChannelProvider := sdk.ChannelContext(channelID, fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))
	// Channel client is used to query and execute transactions (Org1 is default org)
	client, err := channel.New(ctxChannelProvider)
	if err != nil {
		log.Error("channelClient", log.Err(err))
		return nil, err
	}
	return client, nil
}

func sign(ctx context.Client, message []byte) (*common.ConfigSignature, *common.SignatureHeader, error) {
	var (
		cfd resource.ConfigSignatureData
		err error
	)
	if cfd, err = resource.GetConfigSignatureData(ctx, message); err != nil {
		return nil, nil, err
	}
	signingMgr := ctx.SigningManager()
	signature, err := signingMgr.Sign(cfd.SigningBytes, ctx.PrivateKey())
	return &common.ConfigSignature{
		SignatureHeader: cfd.SignatureHeaderBytes,
		Signature:       signature,
	}, &cfd.SignatureHeader, err
}

func getSignatureHeader(ctx context.Client) (signatureHeader *common.SignatureHeader, signatureHeaderBytes []byte, err error) {
	creatorBytes, err := ctx.Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user context's identity error: %e", err)
	}
	// generate a random nonce
	nonce, err := getRandomNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("nonce creation failed error: %e", err)
	}
	signatureHeader = &common.SignatureHeader{
		Creator: creatorBytes,
		Nonce:   nonce,
	}
	if signatureHeaderBytes, err = proto.Marshal(signatureHeader); nil != err {
		return nil, nil, err
	}
	return
}

// addOrg 新增org group
//
// originalBlock 通过channelConfigBlock方法从fabric网络中获取
//
// newGenesisBlockBytes 是通过createGenesisBlock方法新生成的创世区块，改区块理论上只新增了组织信息
func addOrg(channelID, consortium, orgName string, originalBlock *common.Block, newGenesisBlockBytes []byte) ([]byte, error) {
	updateBlock := &common.Block{}
	if err := proto.Unmarshal(newGenesisBlockBytes, updateBlock); nil != err {
		return nil, err
	}
	configUpdateEnvBytes, err := add(originalBlock, updateBlock, channelID, consortium, orgName) // "org3"
	if nil != err {
		return nil, err
	}
	return createConfigUpdateBytes(configUpdateEnvBytes, channelID)
}

func add(originalBlock, updateBlock *common.Block, channelID, consortium, orgName string) ([]byte, error) {
	var (
		originalConfig                                             *common.Config
		orgGroup                                                   *common.ConfigGroup
		configUpdateEnvBytes, configUpdateBytes, updateConfigBytes []byte
		err                                                        error
	)
	if originalConfig, err = getPayloadConfig(originalBlock); nil != err {
		return nil, err
	}
	// updateConfig基础数据来自originalConfig，更新数据来自updateBlock中application里新增的groupName
	updateConfig := &common.Config{}
	if updateConfigBytes, err = proto.Marshal(originalConfig); nil != err {
		return nil, err
	}
	if err = proto.Unmarshal(updateConfigBytes, updateConfig); nil != err {
		return nil, err
	}
	if orgGroup, err = getGroup(updateBlock, consortium, orgName); nil != err {
		return nil, err
	}
	updateConfig.ChannelGroup.Groups["Application"].Groups[orgName] = orgGroup

	configUpdate, err := compute(originalConfig, updateConfig)
	if nil != err {
		return nil, err
	}
	configUpdate.ChannelId = channelID
	log.Info("AddGroup", log.Field("configUpdate", configUpdate))

	if configUpdateBytes, err = proto.Marshal(configUpdate); nil != err {
		return nil, err
	}

	configUpdateEnv := &common.ConfigUpdateEnvelope{}
	configUpdateEnv.ConfigUpdate = configUpdateBytes

	if configUpdateEnvBytes, err = proto.Marshal(configUpdateEnv); nil != err {
		return nil, err
	}

	return configUpdateEnvBytes, nil
}

func getPayloadConfig(block *common.Block) (*common.Config, error) {
	var (
		envelope       *common.Envelope
		payload        *common.Payload
		configEnvelope *common.ConfigEnvelope
		err            error
	)
	if envelope, err = marshalCommonEnvelope(block); nil != err {
		return nil, err
	}
	if payload, err = marshalCommonPayload(envelope); nil != err {
		return nil, err
	}
	if configEnvelope, err = marshalCommonConfigEnvelope(payload); nil != err {
		return nil, err
	}
	if nil == configEnvelope.Config.ChannelGroup.Groups["Application"] {
		return nil, errors.New("config group is nil")
	}
	return configEnvelope.Config, nil
}

func getGroup(block *common.Block, consortium, orgName string) (*common.ConfigGroup, error) {
	var (
		envelope                               *common.Envelope
		payload                                *common.Payload
		configEnvelope                         *common.ConfigEnvelope
		configGroup, consortiumGroup, orgGroup *common.ConfigGroup
		err                                    error
	)
	if envelope, err = marshalCommonEnvelope(block); nil != err {
		return nil, err
	}
	if payload, err = marshalCommonPayload(envelope); nil != err {
		return nil, err
	}
	if configEnvelope, err = marshalCommonConfigEnvelope(payload); nil != err {
		return nil, err
	}
	if configGroup = configEnvelope.Config.ChannelGroup.Groups["Consortiums"]; nil == configGroup {
		return nil, errors.New("config group consortiums is nil")
	}
	if consortiumGroup = configGroup.Groups[consortium]; nil == consortiumGroup {
		return nil, errors.New("config group consortium is nil")
	}
	if orgGroup = consortiumGroup.Groups[orgName]; nil == orgGroup {
		return nil, errors.New("config group org is nil")
	}

	return orgGroup, nil
}

func createConfigUpdateBytes(configUpdateEnvBytes []byte, channelID string) ([]byte, error) {
	var (
		envelope *common.Envelope
		err      error
	)
	if envelope, err = createConfigEnvelopeReader(configUpdateEnvBytes, channelID); nil != err {
		return nil, err
	}
	return proto.Marshal(envelope)
}

func createConfigEnvelopeReader(configUpdateEnvBytes []byte, channelID string) (*common.Envelope, error) {
	var (
		payloadBytes, payloadChannelHeaderBytes []byte
		err                                     error
	)
	envelope := &common.Envelope{}

	payload := &common.Payload{}
	//if err = proto.Unmarshal(envelope.Payload, payload); nil != err {
	//	return nil, err
	//}

	payload.Data = configUpdateEnvBytes

	payloadChannelHeader := &common.ChannelHeader{}
	payloadChannelHeader.ChannelId = channelID
	payloadChannelHeader.Type = 2
	if payloadChannelHeaderBytes, err = proto.Marshal(payloadChannelHeader); nil != err {
		return nil, err
	}

	header := &common.Header{}
	header.ChannelHeader = payloadChannelHeaderBytes

	payload.Header = header

	if payloadBytes, err = proto.Marshal(payload); nil != err {
		return nil, err
	}

	envelope.Payload = payloadBytes
	return envelope, nil
}

func marshalCommonEnvelope(block *common.Block) (*common.Envelope, error) {
	envelope := &common.Envelope{}
	err := proto.Unmarshal(block.Data.Data[0], envelope)
	return envelope, err
}

func marshalCommonPayload(envelope *common.Envelope) (*common.Payload, error) {
	payload := &common.Payload{}
	err := proto.Unmarshal(envelope.Payload, payload)
	return payload, err
}

func marshalCommonConfigEnvelope(payload *common.Payload) (*common.ConfigEnvelope, error) {
	configEnvelope := &common.ConfigEnvelope{}
	err := proto.Unmarshal(payload.Data, configEnvelope)
	return configEnvelope, err
}

// unmarshalEnvelope unmarshals bytes to an Envelope structure
func unmarshalEnvelope(encoded []byte) (*common.Envelope, error) {
	envelope := &common.Envelope{}
	err := proto.Unmarshal(encoded, envelope)
	return envelope, err
}

// extractPayload retrieves the payload of a given envelope and unmarshals it.
func extractPayload(envelope *common.Envelope) (*common.Payload, error) {
	payload := &common.Payload{}
	err := proto.Unmarshal(envelope.Payload, payload)
	return payload, err
}

// unmarshalChannelHeader returns a ChannelHeader from bytes
func unmarshalChannelHeader(bytes []byte) (*common.ChannelHeader, error) {
	chdr := &common.ChannelHeader{}
	err := proto.Unmarshal(bytes, chdr)
	return chdr, err
}

// unmarshalConfigUpdateEnvelope attempts to unmarshal bytes to a *cb.ConfigUpdate
func unmarshalConfigUpdateEnvelope(data []byte) (*common.ConfigUpdateEnvelope, error) {
	configUpdateEnvelope := &common.ConfigUpdateEnvelope{}
	err := proto.Unmarshal(data, configUpdateEnvelope)
	if err != nil {
		return nil, err
	}
	return configUpdateEnvelope, nil
}
