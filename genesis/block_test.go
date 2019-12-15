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
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"io/ioutil"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGenesis_Set(t *testing.T) {
	genesis := testGenesisSet(t)
	blockBytes, err := genesis.ObtainGenesisBlockData("test")
	if nil != err {
		t.Fatal(err)
	}
	blockStr, err := resource.InspectBlock(blockBytes)
	if nil != err {
		t.Fatal(err)
	}
	t.Log(blockStr)
}

func testGenesisSet(t *testing.T) *Genesis {
	var (
		leagueDomain = "league.com"
		addresses    []string
		consenters   []*gen.Consenter
		orgs         []*gen.OrgInBlock
	)
	for i := 1; i < 4; i++ {
		orgName := strings.Join([]string{"orderer", strconv.Itoa(i)}, "")
		orgDomain := strings.Join([]string{"example", strconv.Itoa(i), ".com"}, "")
		orgPath := path.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."))
		for j := 0; j < 3; j++ {
			childName := strings.Join([]string{"order", strconv.Itoa(j)}, "")
			host := strings.Join([]string{childName, ".", orgName, ".", orgDomain}, "")
			addresses = append(addresses, strings.Join([]string{host, "7050"}, ":"))
			tlsCertBytes, err := ioutil.ReadFile(filepath.Join(orgPath, childName, "tls.crt"))
			if nil != err {
				t.Fatal(err)
			}
			consenters = append(consenters, &gen.Consenter{
				Host:          host,
				Port:          7050,
				ClientTlsCert: tlsCertBytes,
				ServerTlsCert: tlsCertBytes,
			})
		}
		adminPath := path.Join(orgPath, "user0")

		adminCertBytes, err := ioutil.ReadFile(filepath.Join(adminPath, utils.CertUserCAName(orgName, orgDomain, "user0")))
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

		orgs = append(orgs, &gen.OrgInBlock{
			Domain: orgDomain,
			Name:   orgName,
			Type:   gen.OrgType_Order,
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
		adminPath := path.Join(orgPath, "user0")

		adminCertBytes, err := ioutil.ReadFile(filepath.Join(adminPath, utils.CertUserCAName(orgName, orgDomain, "user0")))
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
		for j := 0; j < 3; j++ {
			childName := strings.Join([]string{"order", strconv.Itoa(j)}, "")
			anchorPeers = append(anchorPeers, &gen.AnchorPeer{
				Host: strings.Join([]string{childName, ".", orgName, ".", orgDomain}, ""),
				Port: 7051,
			})
		}

		orgs = append(orgs, &gen.OrgInBlock{
			Domain:           orgDomain,
			Name:             orgName,
			OrdererEndpoints: addresses,
			Type:             gen.OrgType_Peer,
			Cert: &gen.MspCert{
				AdminCert: adminCertBytes,
				CaCert:    caCertBytes,
				TlsCaCert: tlsCaCertBytes,
			},
			AnchorPeers: anchorPeers,
		})

	}

	genesis := &Genesis{
		Info: &gen.ReqGenesis{
			League: &gen.LeagueInBlock{
				Domain:       leagueDomain,
				Addresses:    addresses,
				BatchTimeout: 2,
				BatchSize: &gen.BatchSize{
					MaxMessageCount:   1000,
					AbsoluteMaxBytes:  10 * 1024 * 1024,
					PreferredMaxBytes: 2 * 1024 * 1024,
				},
				EtcdRaft: &gen.EtcdRaft{
					Consenters: []*gen.Consenter{},
					Options: &gen.Options{
						TickInterval:         "500ms",
						ElectionTick:         10,
						HeartbeatTick:        1,
						MaxInflightBlocks:    5,
						SnapshotIntervalSize: 20,
					},
				},
				MaxChannels: 1000,
			},
			Orgs: orgs,
		},
	}
	if err := genesis.Set(); nil != err {
		t.Fatal(err)
	}

	return genesis
}
