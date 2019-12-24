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

type Genesis struct {
	Info               *genesis.ReqGenesis
	orderOrganizations []*genesisconfig.Organization
	peerOrganizations  []*genesisconfig.Organization
	allOrganizations   []*genesisconfig.Organization
}

func (g *Genesis) set() (err error) {
	g.orderOrganizations, g.peerOrganizations, g.allOrganizations, err = g.organizations(g.Info.Orgs)
	return
}

func (g *Genesis) obtainGenesisBlockData(consortium string) ([]byte, error) {
	data, err := resource.CreateGenesisBlock(g.genesisBlockConfigProfile(consortium), consortium)
	if nil != err {
		return nil, err
	}
	return data, err
}

func (g *Genesis) createGenesisBlock(consortium string) ([]byte, error) {
	data, err := resource.CreateGenesisBlock(g.genesisBlockConfigProfile(consortium), consortium)
	if nil != err {
		return nil, err
	}
	if _, err = gnomon.File().Append(utils.GenesisBlockFilePath(g.Info.League.Domain), data, true); nil != err {
		return nil, err
	}
	return data, err
}

func (g *Genesis) createChannelCreateTx(consortium, channelID string) ([]byte, error) {
	data, err := resource.CreateChannelCreateTx(g.genesisChannelTxConfigProfile(consortium), nil, channelID)
	if nil != err {
		return nil, err
	}
	if _, err = gnomon.File().Append(utils.ChannelTXFilePath(g.Info.League.Domain, channelID), data, true); nil != err {
		return nil, err
	}
	return data, err
}

func (g *Genesis) orgPolicies(mspID string) map[string]*genesisconfig.Policy {
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

func (g *Genesis) organizations(orgs []*genesis.OrgInBlock) (orders, peers, all []*genesisconfig.Organization, err error) {
	for _, org := range orgs {
		var (
			mspDir string
			mspID  = utils.MspID(org.Name)
		)
		organization := &genesisconfig.Organization{
			Name:           org.Name,
			ID:             mspID,
			MSPType:        "bccsp",
			Policies:       g.orgPolicies(mspID),
			AdminPrincipal: "Role.ADMIN",
		}
		switch org.Type {
		default:
			return
		case genesis.OrgType_Peer:
			var anchorPeers []*genesisconfig.AnchorPeer
			for _, peer := range org.AnchorPeers {
				anchorPeers = append(anchorPeers, &genesisconfig.AnchorPeer{Host: peer.Host, Port: int(peer.Port)})
			}
			organization.AnchorPeers = anchorPeers
			if mspDir, err = g.mspExec(org, true); nil != err {
				return
			}
			organization.MSPDir = mspDir
			peers = append(peers, organization)
		case genesis.OrgType_Order:
			if mspDir, err = g.mspExec(org, false); nil != err {
				return
			}
			organization.MSPDir = mspDir
			orders = append(orders, organization)
		}
		all = append(all, organization)
	}
	return
}

func (g *Genesis) mspExec(org *genesis.OrgInBlock, isPeer bool) (mspDir string, err error) {
	mspDir = utils.CryptoGenesisOrgMspPath(g.Info.League.Domain, org.Domain, org.Name, isPeer)
	adminCertFilePath := filepath.Join(mspDir, "admincerts", utils.CertUserCAName(org.Name, org.Domain, "Admin"))
	caCertFilePath := filepath.Join(mspDir, "cacerts", utils.RootOrgCACertFileName(org.Name, org.Domain))
	tlsCaCertFilePath := filepath.Join(mspDir, "tlscacerts", utils.RootOrgTLSCACertFileName(org.Name, org.Domain))
	if _, err = gnomon.File().Append(adminCertFilePath, org.Cert.AdminCert, true); nil != err {
		return
	}
	if _, err = gnomon.File().Append(caCertFilePath, org.Cert.CaCert, true); nil != err {
		return
	}
	if _, err = gnomon.File().Append(tlsCaCertFilePath, org.Cert.TlsCaCert, true); nil != err {
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
func (g *Genesis) applicationCapabilities() map[string]bool {
	return map[string]bool{
		//"V1_1": false, // 启用了新的非向后兼容特性和fabric V1.1的特征
		//"V1_2": false, // 启用了新的非向后兼容特性和fabric V1.2的特征
		//"V1_3": false, // 启用了新的非向后兼容特性和fabric V1.3的特征
		"V1_4_2": true, // 启用了新的非向后兼容特性和fabric V1.4.2的特征
	}
}

func (g *Genesis) applications() *genesisconfig.Application {
	//rule := strings.Join([]string{"OR('", adminOrgMspID, ".admin')"}, "")
	return &genesisconfig.Application{
		Organizations: g.peerOrganizations,
		Capabilities:  g.applicationCapabilities(),
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

func (g *Genesis) ordererCapabilities() map[string]bool {
	return map[string]bool{
		//"V1_1": false, // 支持新的非向后兼容特性和fabric V1.1的特征
		// V1.4.2 for Orderer是一个行为的集合标志，它被确定为在V1.4.2级别上运行的所有Orderer所期望的，但是它与以前版本中的Orderer不兼容。
		// 在启用V1.4.2 orderer功能之前，请确保通道上的所有订货方都处于V1.4.2或更高版本。
		"V1_4_2": true,
	}
}

func (g *Genesis) orderer() *genesisconfig.Orderer {
	var consenters []*etcdraft.Consenter
	for _, consenter := range g.Info.League.EtcdRaft.Consenters {
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
		Addresses:    g.Info.League.Addresses, // []string{"orderer.example.org:7050"}
		BatchTimeout: time.Duration(time.Duration(g.Info.League.BatchTimeout) * time.Second),
		BatchSize: genesisconfig.BatchSize{
			MaxMessageCount:   g.Info.League.BatchSize.MaxMessageCount,   // 500
			AbsoluteMaxBytes:  g.Info.League.BatchSize.AbsoluteMaxBytes,  //10 * 1024 * 1024
			PreferredMaxBytes: g.Info.League.BatchSize.PreferredMaxBytes, //2 * 1024 * 1024
		},
		EtcdRaft: &etcdraft.ConfigMetadata{
			Consenters: consenters,
			Options: &etcdraft.Options{
				TickInterval:         g.Info.League.EtcdRaft.Options.TickInterval,
				ElectionTick:         g.Info.League.EtcdRaft.Options.ElectionTick,
				HeartbeatTick:        g.Info.League.EtcdRaft.Options.HeartbeatTick,
				MaxInflightBlocks:    g.Info.League.EtcdRaft.Options.MaxInflightBlocks,
				SnapshotIntervalSize: g.Info.League.EtcdRaft.Options.SnapshotIntervalSize,
			},
		},
		Organizations: g.orderOrganizations,
		MaxChannels:   g.Info.League.MaxChannels, // 1000
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
		Capabilities: g.ordererCapabilities(),
	}
}

func (g *Genesis) channelDefaults() map[string]*genesisconfig.Policy {
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

func (g *Genesis) genesisBlockConfigProfile(consortium string) *genesisconfig.Profile {
	profile := &genesisconfig.Profile{
		Orderer: g.orderer(),
		Consortiums: map[string]*genesisconfig.Consortium{
			consortium: {Organizations: g.peerOrganizations},
		},
		Policies: g.channelDefaults(),
	}
	return profile
}

func (g *Genesis) genesisChannelTxConfigProfile(consortium string) *genesisconfig.Profile {
	profile := &genesisconfig.Profile{
		Consortium:  consortium,
		Application: g.applications(),
		Policies:    g.channelDefaults(),
	}
	return profile
}
