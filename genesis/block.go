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

package genesis

import (
	"github.com/aberic/fabric-client-go/grpc/proto/genesis"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"github.com/hyperledger/fabric-protos-go/orderer/etcdraft"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource/genesisconfig"
	"path/filepath"
	"strings"
	"time"
)

func createGenesisBlock(genesisBlock *genesis.ReqGenesisBlock) (*genesis.RespGenesisBlock, error) {
	cs, _, err := initBlock(genesisBlock.League.Domain, genesisBlock.Consortiums)
	if nil != err {
		return &genesis.RespGenesisBlock{Code: genesis.Code_Fail, ErrMsg: err.Error()}, err
	}
	os, err := orderOrganizations(genesisBlock)
	if nil != err {
		return &genesis.RespGenesisBlock{Code: genesis.Code_Fail, ErrMsg: err.Error()}, err
	}
	orderer := orderer(genesisBlock.League, genesisBlock.Orderer, os)
	data, err := resource.CreateGenesisBlock(genesisBlockConfigProfile(orderer, cs), genesisBlock.DefaultChannelID)
	if nil != err {
		return &genesis.RespGenesisBlock{Code: genesis.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &genesis.RespGenesisBlock{Code: genesis.Code_Success, BlockData: data}, nil
}

func createChannelTx(channelTx *genesis.ReqChannelTx) (*genesis.RespChannelTx, error) {
	peers, err := peerOrganizations(channelTx.League.Domain, channelTx.PeerOrgs)
	if nil != err {
		return &genesis.RespChannelTx{Code: genesis.Code_Fail, ErrMsg: err.Error()}, err
	}
	data, err := resource.CreateChannelCreateTx(genesisChannelTxConfigProfile(channelTx.Consortium, channelTx.League, peers), nil, channelTx.ChannelID)
	if nil != err {
		return &genesis.RespChannelTx{Code: genesis.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &genesis.RespChannelTx{Code: genesis.Code_Success, ChannelTxData: data}, nil
}

func initBlock(leagueDomain string, consortiums []*genesis.Consortium) (map[string]*genesisconfig.Consortium, []*genesisconfig.Organization, error) {
	var pos []*genesisconfig.Organization
	cs := make(map[string]*genesisconfig.Consortium)
	for _, consortium := range consortiums {
		peerOrganizations, err := peerOrganizations(leagueDomain, consortium.PeerOrgs)
		if nil != err {
			return nil, nil, err
		}
		cs[consortium.Name] = &genesisconfig.Consortium{Organizations: peerOrganizations}
		pos = append(pos, peerOrganizations...)
	}
	return cs, pos, nil
}

func orgPolicies(mspID string) map[string]*genesisconfig.Policy {
	return map[string]*genesisconfig.Policy{
		"Readers": {
			Type: "Signature",
			Rule: strings.Join([]string{"OR('", mspID, ".member')"}, ""),
		},
		"Writers": {
			Type: "Signature",
			Rule: strings.Join([]string{"OR('", mspID, ".member')"}, ""),
		},
		"Admins": {
			Type: "Signature",
			Rule: strings.Join([]string{"OR('", mspID, ".admin')"}, ""),
		},
		"Endorsement": {
			Type: "Signature",
			Rule: strings.Join([]string{"OR('", mspID, ".member')"}, ""),
		},
	}
}

func orderOrganizations(genesisBlock *genesis.ReqGenesisBlock) (orders []*genesisconfig.Organization, err error) {
	for _, ordererOrg := range genesisBlock.OrdererOrgs {
		var (
			mspDir string
			mspID  = utils.MspID(ordererOrg.Name)
		)
		if mspDir, err = mspExec(genesisBlock.League.Domain, ordererOrg.Name, ordererOrg.Domain, ordererOrg.Cert, false); nil != err {
			return
		}
		organization := &genesisconfig.Organization{
			Name:           ordererOrg.Name,
			ID:             mspID,
			MSPDir:         mspDir,
			MSPType:        "bccsp",
			Policies:       orgPolicies(mspID),
			AdminPrincipal: "Role.ADMIN",
		}
		orders = append(orders, organization)
	}
	return
}

func peerOrganizations(leagueDomain string, peerOrgs []*genesis.PeerOrg) (peers []*genesisconfig.Organization, err error) {
	for _, peerOrg := range peerOrgs {
		var (
			mspDir string
			mspID  = utils.MspID(peerOrg.Name)
		)
		if mspDir, err = mspExec(leagueDomain, peerOrg.Name, peerOrg.Domain, peerOrg.Cert, true); nil != err {
			return
		}
		var anchorPeers []*genesisconfig.AnchorPeer
		for _, peer := range peerOrg.AnchorPeers {
			anchorPeers = append(anchorPeers, &genesisconfig.AnchorPeer{Host: peer.Host, Port: int(peer.Port)})
		}
		organization := &genesisconfig.Organization{
			Name:           peerOrg.Name,
			ID:             mspID,
			MSPDir:         mspDir,
			MSPType:        "bccsp",
			Policies:       orgPolicies(mspID),
			AdminPrincipal: "Role.ADMIN",
			AnchorPeers:    anchorPeers,
		}
		peers = append(peers, organization)
	}
	return
}

// mspExec msp临时操作，传入证书将存入临时目录，用于解析生成对应区块结构
func mspExec(leagueDomain, orgName, orgDomain string, cert *genesis.MspCert, isPeer bool) (mspDir string, err error) {
	mspDir = utils.CryptoGenesisOrgMspPath(leagueDomain, orgDomain, orgName, isPeer)
	adminCertFilePath := filepath.Join(mspDir, "admincerts", utils.CertUserCAName(orgName, orgDomain, "Admin"))
	caCertFilePath := filepath.Join(mspDir, "cacerts", utils.RootOrgCACertFileName(orgName, orgDomain))
	tlsCaCertFilePath := filepath.Join(mspDir, "tlscacerts", utils.RootOrgTLSCACertFileName(orgName, orgDomain))
	if _, err = gnomon.File().Append(adminCertFilePath, cert.AdminCert, true); nil != err {
		return
	}
	if _, err = gnomon.File().Append(caCertFilePath, cert.CaCert, true); nil != err {
		return
	}
	if _, err = gnomon.File().Append(tlsCaCertFilePath, cert.TlsCaCert, true); nil != err {
		return
	}
	return
}

// applicationCapabilities 应用功能集
//
// 应用程序功能只应用于 peer 网络，并且可以安全地与以前的版本 orderers 一起使用。
//
// 将功能的值设置为true以满足需要。
//
// 注意，将后面的应用程序版本功能设置为true也将隐式地将前面的应用程序版本功能设置为true。不需要将每个版本功能设置为true(此示例中保留了以前的版本功能，仅提供有效值列表)。
func applicationCapabilities(league *genesis.League) map[string]bool {
	switch league.Version {
	default:
		return map[string]bool{
			"V1_4_2": true,
		}
	case genesis.Version_V1_1:
		return map[string]bool{
			"V1_1": true, // 启用了新的非向后兼容特性和fabric V1.1的特征
		}
	case genesis.Version_V1_2:
		return map[string]bool{
			"V1_2": true, // 启用了新的非向后兼容特性和fabric V1.2的特征
		}
	case genesis.Version_V1_3:
		return map[string]bool{
			"V1_3": true, // 启用了新的非向后兼容特性和fabric V1.3的特征
		}
	case genesis.Version_V1_4:
		return map[string]bool{
			"V1_4_2": true, // 启用了新的非向后兼容特性和fabric V1.4.2的特征
		}
	case genesis.Version_V2_0:
		return map[string]bool{
			"V2_0": true, // Application的V2.0支持新的非向后兼容特性和fabric V2.0的补丁。在启用V2.0定序器功能之前，请确保通道上的所有定序器都处于v2.0.0或更高版本
		}
	}
}

func applications(league *genesis.League, peerOrganizations []*genesisconfig.Organization) *genesisconfig.Application {
	//rule := strings.Join([]string{"OR('", adminOrgMspID, ".admin')"}, "")
	return &genesisconfig.Application{
		Organizations: peerOrganizations,
		Capabilities:  applicationCapabilities(league),
		Policies: map[string]*genesisconfig.Policy{
			"LifecycleEndorsement": {
				Rule: "MAJORITY Endorsement",
				Type: "ImplicitMeta",
			},
			"Endorsement": {
				Rule: "MAJORITY Endorsement",
				Type: "ImplicitMeta",
			},
			"Readers": {
				Rule: "ANY Readers",
				Type: "ImplicitMeta",
			},
			"Writers": {
				Rule: "ANY Writers",
				Type: "ImplicitMeta",
			},
			"Admins": {
				Rule: "MAJORITY Admins",
				Type: "ImplicitMeta",
			},
			//"ChannelCreate": {
			//	Type: "Signature",
			//	Rule: rule,
			//},
		},
		ACLs: map[string]string{
			"_lifecycle/CommitChaincodeDefinition": "/Channel/Application/Writers",
			"_lifecycle/QueryChaincodeDefinition":  "/Channel/Application/Readers",
			"_lifecycle/QueryNamespaceDefinitions": "/Channel/Application/Readers",
			"lscc/ChaincodeExists":                 "/Channel/Application/Readers",
			"lscc/GetDeploymentSpec":               "/Channel/Application/Readers",
			"lscc/GetChaincodeData":                "/Channel/Application/Readers",
			"lscc/GetInstantiatedChaincodes":       "/Channel/Application/Readers",
			"qscc/GetChainInfo":                    "/Channel/Application/Readers",
			"qscc/GetBlockByNumber":                "/Channel/Application/Readers",
			"qscc/GetBlockByHash":                  "/Channel/Application/Readers",
			"qscc/GetTransactionByID":              "/Channel/Application/Readers",
			"qscc/GetBlockByTxID":                  "/Channel/Application/Readers",
			"cscc/GetConfigBlock":                  "/Channel/Application/Readers",
			"cscc/GetConfigTree":                   "/Channel/Application/Readers",
			"cscc/SimulateConfigTreeUpdate":        "/Channel/Application/Readers",
			"peer/Propose":                         "/Channel/Application/Writers",
			"peer/ChaincodeToChaincode":            "/Channel/Application/Readers",
			"event/Block":                          "/Channel/Application/Readers",
			"event/FilteredBlock":                  "/Channel/Application/Readers",
		},
	}
}

func ordererCapabilities(league *genesis.League) map[string]bool {
	switch league.Version {
	default:
		return map[string]bool{
			"V1_4_2": true,
		}
	case genesis.Version_V1_1:
		return map[string]bool{
			"V1_1": true, // 启用了新的非向后兼容特性和fabric V1.1的特征
		}
	case genesis.Version_V1_2:
		return map[string]bool{
			"V1_2": true, // 启用了新的非向后兼容特性和fabric V1.2的特征
		}
	case genesis.Version_V1_3:
		return map[string]bool{
			"V1_3": true, // 启用了新的非向后兼容特性和fabric V1.3的特征
		}
	case genesis.Version_V1_4:
		return map[string]bool{
			"V1_4_2": true, // 启用了新的非向后兼容特性和fabric V1.4.2的特征
		}
	case genesis.Version_V2_0:
		return map[string]bool{
			"V2_0": true, // Application的V2.0支持新的非向后兼容特性和fabric V2.0的补丁。在启用V2.0定序器功能之前，请确保通道上的所有定序器都处于v2.0.0或更高版本
		}
	}
}

func orderer(league *genesis.League, orderer *genesis.Orderer, orderOrganizations []*genesisconfig.Organization) *genesisconfig.Orderer {
	var consenters []*etcdraft.Consenter
	for _, consenter := range orderer.EtcdRaft.Consenters {
		c := &etcdraft.Consenter{
			Host:          consenter.Host,
			Port:          consenter.Port,
			ClientTlsCert: consenter.ClientTlsCert,
			ServerTlsCert: consenter.ServerTlsCert,
		}
		consenters = append(consenters, c)
	}
	return &genesisconfig.Orderer{
		OrdererType:  "etcdraft",
		Addresses:    orderer.Addresses, // []string{"orderer.example.org:7050"}
		BatchTimeout: time.Duration(time.Duration(orderer.BatchTimeout) * time.Second),
		BatchSize: genesisconfig.BatchSize{
			MaxMessageCount:   orderer.BatchSize.MaxMessageCount,   // 500
			AbsoluteMaxBytes:  orderer.BatchSize.AbsoluteMaxBytes,  //10 * 1024 * 1024
			PreferredMaxBytes: orderer.BatchSize.PreferredMaxBytes, //2 * 1024 * 1024
		},
		EtcdRaft: &etcdraft.ConfigMetadata{
			Consenters: consenters,
			Options: &etcdraft.Options{
				TickInterval:         orderer.EtcdRaft.Options.TickInterval,
				ElectionTick:         orderer.EtcdRaft.Options.ElectionTick,
				HeartbeatTick:        orderer.EtcdRaft.Options.HeartbeatTick,
				MaxInflightBlocks:    orderer.EtcdRaft.Options.MaxInflightBlocks,
				SnapshotIntervalSize: orderer.EtcdRaft.Options.SnapshotIntervalSize,
			},
		},
		Organizations: orderOrganizations,
		MaxChannels:   orderer.MaxChannels, // 1000
		// Policies defines the set of policies at this level of the config tree
		// For Orderer policies, their canonical path is
		// /Channel/Orderer/<PolicyName>
		Policies: map[string]*genesisconfig.Policy{
			"Readers": {
				Type: "ImplicitMeta",
				Rule: "ANY Readers",
			},
			"Writers": {
				Type: "ImplicitMeta",
				Rule: "ANY Writers",
			},
			"Admins": {
				Type: "ImplicitMeta",
				Rule: "MAJORITY Admins",
			},
			"BlockValidation": {
				Type: "ImplicitMeta",
				Rule: "ANY Writers",
			},
		},
		Capabilities: ordererCapabilities(league),
	}
}

func channelDefaults() map[string]*genesisconfig.Policy {
	// Policies defines the set of policies at this level of the config tree
	// For Channel policies, their canonical path is
	// /Channel/<PolicyName>
	policies := map[string]*genesisconfig.Policy{
		"Admins": {
			Type: "ImplicitMeta",
			Rule: "MAJORITY Admins",
		},
		"Readers": {
			Type: "ImplicitMeta",
			Rule: "ANY Readers",
		},
		"Writers": {
			Type: "ImplicitMeta",
			Rule: "ANY Writers",
		},
	}
	return policies
}

func genesisBlockConfigProfile(orderer *genesisconfig.Orderer, consortiums map[string]*genesisconfig.Consortium) *genesisconfig.Profile {
	profile := &genesisconfig.Profile{
		Orderer:     orderer,
		Consortiums: consortiums,
		Policies:    channelDefaults(),
	}
	return profile
}

func genesisChannelTxConfigProfile(consortium string, league *genesis.League, peerOrganizations []*genesisconfig.Organization) *genesisconfig.Profile {
	profile := &genesisconfig.Profile{
		Consortium:  consortium,
		Application: applications(league, peerOrganizations),
		Policies:    channelDefaults(),
	}
	return profile
}
