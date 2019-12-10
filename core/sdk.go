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
	"github.com/aberic/gnomon"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

// SDK fabsdk.FabricSDK
func SDK(configBytes []byte, sdkOpts ...fabsdk.Option) (*fabsdk.FabricSDK, error) {
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
func ClientContext(orgName, orgUser string, configBytes []byte,
	sdkOpts ...fabsdk.Option) (context.ClientProvider, *fabsdk.FabricSDK) {
	sdk, err := SDK(configBytes, sdkOpts...)
	if err != nil {
		return nil, nil
	}
	//clientContext allows creation of transactions using the supplied identity as the credential.
	return sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName)), sdk
}

// ResmgmtClient resmgmt.Client
func ResmgmtClient(orgName, orgUser string, configBytes []byte,
	sdkOpts ...fabsdk.Option) (*resmgmt.Client, *fabsdk.FabricSDK, error) {
	sdk, err := SDK(configBytes, sdkOpts...)
	if err != nil {
		return nil, nil, err
	}
	//clientContext allows creation of transactions using the supplied identity as the credential.
	clientContext := sdk.Context(fabsdk.WithUser(orgUser), fabsdk.WithOrg(orgName))

	// Org resource management client
	orgResMgmt, err := resmgmt.New(clientContext)
	if err != nil {
		gnomon.Log().Error("resMgmtOrgClient", gnomon.Log().Err(err))
		return nil, nil, fmt.Errorf("Failed to create new resource management client: " + err.Error())
	}
	return orgResMgmt, sdk, nil
}
