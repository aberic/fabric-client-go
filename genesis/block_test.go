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
	gen "github.com/aberic/fabric-client-go/grpc/proto/genesis"
	"github.com/aberic/fabric-client-go/utils"
	"github.com/aberic/gnomon"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"io/ioutil"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGenesisBlock(t *testing.T) {
	var leagueDomain = "league.com"
	genesisBlock, _ := testGenesisSet(leagueDomain, "", t)
	resp, err := createGenesisBlock(genesisBlock)
	if nil != err {
		t.Fatal(err)
	}
	blockStr, err := resource.InspectBlock(resp.BlockData)
	if nil != err {
		t.Fatal(err)
	}
	t.Log(blockStr)
	if _, err = gnomon.File().Append(utils.GenesisBlockFilePath(leagueDomain), resp.BlockData, true); nil != err {
		t.Fatal(err)
	}
}

func TestGenesisChannel(t *testing.T) {
	var (
		leagueDomain = "league.com"
		channelID    = "mychannel02"
	)
	_, channelTx := testGenesisSet(leagueDomain, channelID, t)
	resp, err := createChannelTx(channelTx)
	if nil != err {
		t.Fatal(err)
	}
	channelStr, err := resource.InspectChannelCreateTx(resp.ChannelTxData)
	if nil != err {
		t.Fatal(err)
	}
	t.Log(channelStr)
	if _, err = gnomon.File().Append(utils.ChannelTXFilePath(leagueDomain, channelID), resp.ChannelTxData, true); nil != err {
		t.Fatal(err)
	}
}

func testGenesisSet(leagueDomain, channelID string, t *testing.T) (genesisBlock *gen.ReqGenesisBlock, channelTx *gen.ReqChannelTx) {
	var (
		addresses   []string
		consenters  []*gen.Consenter
		ordererOrgs []*gen.OrdererOrg
		peerOrgs    []*gen.PeerOrg
		consortiums []*gen.Consortium
	)
	for i := 1; i < 2; i++ {
		orgName := strings.Join([]string{"orderer", strconv.Itoa(i)}, "")
		orgDomain := strings.Join([]string{"example", strconv.Itoa(i), ".com"}, "")
		orgPath := path.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."))
		offset := 0
		var offsetU32 uint32 = 0
		for j := 0; j < 3; j++ {
			childName := strings.Join([]string{"order", strconv.Itoa(j)}, "")
			host := strings.Join([]string{childName, ".", orgName, ".", orgDomain}, "")
			addresses = append(addresses, strings.Join([]string{host, strconv.Itoa(7050 + offset)}, ":"))
			_, nodePath := utils.CryptoOrgAndNodePath(leagueDomain, orgDomain, orgName, childName, false)
			consenters = append(consenters, &gen.Consenter{
				Host:          host,
				Port:          7050 + offsetU32,
				ClientTlsCert: []byte(filepath.Join(nodePath, "tls", "server.crt")),
				ServerTlsCert: []byte(filepath.Join(nodePath, "tls", "server.crt")),
			})
			offset += 1000
			offsetU32 += 1000
		}
		adminPath := path.Join(orgPath, "Admin")

		adminCertBytes, err := ioutil.ReadFile(filepath.Join(adminPath, "ca.crt"))
		if nil != err {
			t.Fatal(err)
		}
		caCertBytes, err := ioutil.ReadFile(filepath.Join(orgPath, utils.RootOrgCACertFileName(orgName, orgDomain)))
		if nil != err {
			t.Fatal(err)
		}
		tlsCaCertBytes, err := ioutil.ReadFile(filepath.Join(orgPath, utils.RootOrgTLSCACertFileName(orgName, orgDomain)))
		if nil != err {
			t.Fatal(err)
		}

		ordererOrgs = append(ordererOrgs, &gen.OrdererOrg{
			Domain: orgDomain,
			Name:   orgName,
			Cert: &gen.MspCert{
				AdminCert: adminCertBytes,
				CaCert:    caCertBytes,
				TlsCaCert: tlsCaCertBytes,
			},
		})
	}

	for i := 1; i < 4; i++ {
		orgName := strings.Join([]string{"org", strconv.Itoa(i)}, "")
		orgDomain := strings.Join([]string{"example", strconv.Itoa(i), ".com"}, "")

		orgPath := path.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."))
		adminPath := path.Join(orgPath, "Admin")

		adminCertBytes, err := ioutil.ReadFile(filepath.Join(adminPath, "ca.crt"))
		if nil != err {
			t.Fatal(err)
		}
		caCertBytes, err := ioutil.ReadFile(filepath.Join(orgPath, utils.RootOrgCACertFileName(orgName, orgDomain)))
		if nil != err {
			t.Fatal(err)
		}
		tlsCaCertBytes, err := ioutil.ReadFile(filepath.Join(orgPath, utils.RootOrgTLSCACertFileName(orgName, orgDomain)))
		if nil != err {
			t.Fatal(err)
		}

		var anchorPeers []*gen.AnchorPeer
		var port int32 = 8051
		for j := 0; j < 3; j++ {
			childName := strings.Join([]string{"order", strconv.Itoa(j)}, "")
			anchorPeers = append(anchorPeers, &gen.AnchorPeer{
				Host: strings.Join([]string{childName, ".", orgName, ".", orgDomain}, ""),
				Port: port,
			})
			port++
		}

		peerOrgs = append(peerOrgs, &gen.PeerOrg{
			Domain:           orgDomain,
			Name:             orgName,
			OrdererEndpoints: addresses,
			Cert: &gen.MspCert{
				AdminCert: adminCertBytes,
				CaCert:    caCertBytes,
				TlsCaCert: tlsCaCertBytes,
			},
			AnchorPeers: anchorPeers,
		})

	}

	orderer := &gen.Orderer{
		Addresses:    addresses,
		BatchTimeout: 2,
		BatchSize: &gen.BatchSize{
			MaxMessageCount:   1000,
			AbsoluteMaxBytes:  10 * 1024 * 1024,
			PreferredMaxBytes: 2 * 1024 * 1024,
		},
		EtcdRaft: &gen.EtcdRaft{
			Consenters: consenters,
			Options: &gen.Options{
				TickInterval:         "500ms",
				ElectionTick:         10,
				HeartbeatTick:        1,
				MaxInflightBlocks:    5,
				SnapshotIntervalSize: 20,
			},
		},
		MaxChannels: 1000,
	}
	consortiums = append(consortiums, &gen.Consortium{
		Name:     "testone",
		PeerOrgs: peerOrgs,
	})
	consortiums = append(consortiums, &gen.Consortium{
		Name:     "testtwo",
		PeerOrgs: peerOrgs,
	})
	consortiums = append(consortiums, &gen.Consortium{
		Name:     "testthree",
		PeerOrgs: peerOrgs,
	})

	league := &gen.League{Domain: leagueDomain, Version: gen.Version_V1_4_4}
	return &gen.ReqGenesisBlock{
			League:           league,
			Orderer:          orderer,
			DefaultChannelID: "channeldefault",
			OrdererOrgs:      ordererOrgs,
			Consortiums:      consortiums,
		}, &gen.ReqChannelTx{
			League:     league,
			Consortium: "testone",
			ChannelID:  channelID,
			PeerOrgs:   peerOrgs,
		}
}
