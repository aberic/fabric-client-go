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
	"encoding/json"
	config2 "github.com/aberic/fabric-client-go/config"
	"github.com/aberic/fabric-client-go/grpc/proto/config"
	"github.com/aberic/fabric-client-go/grpc/proto/core"
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

var (
	channelID = "mychannel02"
	orgNum    = "2"
)

func TestChannelCreate(t *testing.T) {
	_ = testPaddingConfig(t)
	channelConfig, err := ioutil.ReadFile(filepath.Join(utils.ObtainDataPath(), "league.com", "channel-artifacts", strings.Join([]string{channelID, "tx"}, ".")))
	if nil != err {
		t.Fatal(err)
	}
	resp, err := ChannelCreate(&core.ReqChannelCreate{
		LeagueDomain:   "league.com",
		OrgDomain:      strings.Join([]string{"example", orgNum, ".com"}, ""),
		ChannelID:      channelID,
		ChannelTxBytes: channelConfig,
	})
	t.Log(resp, err)
}

func TestChannelJoin(t *testing.T) {
	_ = testPaddingConfig(t)
	resp, err := ChannelJoin(&core.ReqChannelJoin{
		LeagueDomain: "league.com",
		OrgDomain:    strings.Join([]string{"example", orgNum, ".com"}, ""),
		PeerName:     "peer0",
		ChannelID:    channelID,
	})
	t.Log(resp, err)
}

func TestChannelList(t *testing.T) {
	_ = testPaddingConfig(t)
	resp, err := ChannelList(&core.ReqChannelList{
		LeagueDomain: "league.com",
		OrgDomain:    strings.Join([]string{"example", orgNum, ".com"}, ""),
		PeerName:     "peer0",
	})
	t.Log(resp, err)
}

func TestChannelConfigBlock(t *testing.T) {
	_ = testPaddingConfig(t)
	if resp, err := ChannelConfigBlock(&core.ReqChannelConfigBlock{
		LeagueDomain: "league.com",
		OrgDomain:    strings.Join([]string{"example", orgNum, ".com"}, ""),
		PeerName:     "peer0",
		ChannelID:    channelID,
	}); nil != err {
		t.Fatal(err)
	} else {
		t.Log(resource.InspectBlock(resp.GenesisBlockBytes))
	}
}

func TestChannelUpdateConfigBlock(t *testing.T) {
	var (
		leagueDomain         = "league.com"
		newGenesisBlockBytes []byte
		err                  error
	)
	if newGenesisBlockBytes, err = ioutil.ReadFile(utils.GenesisBlock4AddFilePath(leagueDomain)); nil != err {
		t.Fatal(err)
	}
	_ = testPaddingConfig(t)
	resp, err := ChannelUpdateConfigBlock(&core.ReqChannelUpdateBlock{
		LeagueDomain:      leagueDomain,
		OrgDomain:         strings.Join([]string{"example", orgNum, ".com"}, ""),
		PeerName:          "peer0",
		Consortium:        "testone",
		NewOrgName:        "org3",
		ChannelID:         channelID,
		GenesisBlockBytes: newGenesisBlockBytes,
	})
	if nil != err {
		t.Fatal(err)
	}
	t.Log(resource.InspectBlock(resp.EnvelopeBytes))
	channelUpdateFilePath := utils.ChannelUpdateTXFilePath(leagueDomain, channelID)
	if _, err = gnomon.File().Append(channelUpdateFilePath, resp.EnvelopeBytes, true); nil != err {
		t.Fatal(err)
	}
}

//func TestSignChannelTx(t *testing.T) {
//	newChannelTxBytes, err := signChannelTx(strings.Join([]string{"org", orgNum}, ""), "Admin", channelID, configBytes, envelopeBytes []byte)
//}

func testPaddingConfig(t *testing.T) *config2.Config {
	var (
		conf         *config2.Config
		leagueDomain = "league.com"
		orderDomain  = "example1.com"
		orderName    = "orderer1"
		orgDomain    = strings.Join([]string{"example", orgNum, ".com"}, "")
		orgName      = strings.Join([]string{"org", orgNum}, "")
		peerNames    = []string{"peer0", "peer1", "peer2"}
		err          error
	)
	if conf, err = config2.Mock(&config.ReqConfigSet{
		Version:      "1.0.0",
		LeagueDomain: leagueDomain,
		Orderer:      testOrder(leagueDomain, orderName, orderDomain, "Admin", t),
		Org:          testOrg(leagueDomain, orgName, orgDomain, "Admin", t),
		Client: &config.Client{
			Tls: true,
		},
		Channels: map[string]*config.Channel{
			"mychannel01": {PeerNames: peerNames},
			"mychannel02": {PeerNames: peerNames},
			"mychannel03": {PeerNames: peerNames},
		},
	}); nil != err {
		t.Fatal(err)
	}
	if data, err := json.Marshal(conf); nil == err {
		t.Log(string(data))
	}
	config2.Set(leagueDomain, orgDomain, conf)
	return conf
}

func testOrder(leagueDomain, ordererName, ordererDomain, userName string, t *testing.T) *config.Orderer {
	ordererPath := path.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{ordererName, ordererDomain}, "."))
	certBytes, err := ioutil.ReadFile(filepath.Join(ordererPath, "ca.crt"))
	if nil != err {
		t.Fatal(err)
	}
	tlsCertBytes, err := ioutil.ReadFile(filepath.Join(ordererPath, "tls.crt"))
	if nil != err {
		t.Fatal(err)
	}
	orderer := &config.Orderer{
		Domain:       ordererDomain,
		Name:         ordererName,
		MspID:        utils.MspID(ordererName),
		Username:     userName,
		User:         testOrderUser(userName, ordererPath, true, t),
		Nodes:        testOrderNodes(ordererName, ordererDomain, ordererPath, t),
		CertBytes:    certBytes,
		TlsCertBytes: tlsCertBytes,
	}
	return orderer
}

func testOrderUser(username, ordererPath string, isAdmin bool, t *testing.T) *config.User {
	userPath := path.Join(ordererPath, username)
	keyBytes, err := ioutil.ReadFile(filepath.Join(userPath, "ca.key"))
	if nil != err {
		t.Fatal(err)
	}
	certBytes, err := ioutil.ReadFile(filepath.Join(userPath, "ca.crt"))
	if nil != err {
		t.Fatal(err)
	}
	tlsKeyBytes, err := ioutil.ReadFile(filepath.Join(userPath, "tls.key"))
	if nil != err {
		t.Fatal(err)
	}
	tlsCertBytes, err := ioutil.ReadFile(filepath.Join(userPath, "tls.crt"))
	if nil != err {
		t.Fatal(err)
	}
	var user = &config.User{}
	user.Name = username
	user.IsAdmin = isAdmin
	user.Crypto = &config.Crypto{
		Key:     keyBytes,
		Cert:    certBytes,
		TlsKey:  tlsKeyBytes,
		TlsCert: tlsCertBytes,
	}
	return user
}

func testOrderNodes(ordererName, ordererDomain, ordererPath string, t *testing.T) []*config.Node {
	var nodes []*config.Node
	offset := 0
	for i := 0; i < 3; i++ {
		childName := strings.Join([]string{"order", strconv.Itoa(i)}, "")
		childPath := path.Join(ordererPath, childName)
		keyBytes, err := ioutil.ReadFile(filepath.Join(childPath, "ca.key"))
		if nil != err {
			t.Fatal(err)
		}
		certBytes, err := ioutil.ReadFile(filepath.Join(childPath, "ca.crt"))
		if nil != err {
			t.Fatal(err)
		}
		tlsKeyBytes, err := ioutil.ReadFile(filepath.Join(childPath, "tls.key"))
		if nil != err {
			t.Fatal(err)
		}
		tlsCertBytes, err := ioutil.ReadFile(filepath.Join(childPath, "tls.crt"))
		if nil != err {
			t.Fatal(err)
		}
		nodes = append(nodes, &config.Node{
			Name: childName,
			Url:  strings.Join([]string{"grpcs://127.0.0.1", strconv.Itoa(7050 + offset)}, ":"),
			GrpcOptions: &config.GRPCOptions{
				SslTargetNameOverride: strings.Join([]string{childName, ordererName, ordererDomain}, "."),
				KeepAliveTime:         "0s",
				KeepAliveTimeout:      "20s",
				KeepAlivePermit:       false,
				FailFast:              false,
				AllowInsecure:         false,
			},
			Crypto: &config.Crypto{
				Key:     keyBytes,
				Cert:    certBytes,
				TlsKey:  tlsKeyBytes,
				TlsCert: tlsCertBytes,
			},
		})
		offset += 1000
	}
	return nodes
}

func testOrg(leagueDomain, orgName, orgDomain, username string, t *testing.T) *config.Org {
	orgPath := path.Join(utils.ObtainDataPath(), leagueDomain, strings.Join([]string{orgName, orgDomain}, "."))
	certBytes, err := ioutil.ReadFile(filepath.Join(orgPath, "ca.crt"))
	if nil != err {
		t.Fatal(err)
	}
	tlsCertBytes, err := ioutil.ReadFile(filepath.Join(orgPath, "tls.crt"))
	if nil != err {
		t.Fatal(err)
	}
	org := &config.Org{
		Domain:       orgDomain,
		Name:         orgName,
		MspID:        utils.MspID(orgName),
		Username:     username,
		Users:        testOrgUsers(username, orgPath, t),
		Peers:        testOrgPeers(orgNum, orgName, orgDomain, orgPath, t),
		CertBytes:    certBytes,
		TlsCertBytes: tlsCertBytes,
	}
	return org
}

func testOrgUsers(username, orgPath string, t *testing.T) []*config.User {
	var users []*config.User
	for i := 0; i < 3; i++ {
		var userName string
		if i == 0 {
			userName = "Admin"
		} else {
			userName = strings.Join([]string{"User", strconv.Itoa(i)}, "")
		}
		userPath := path.Join(orgPath, userName)
		keyBytes, err := ioutil.ReadFile(filepath.Join(userPath, "ca.key"))
		if nil != err {
			t.Fatal(err)
		}
		certBytes, err := ioutil.ReadFile(filepath.Join(userPath, "ca.crt"))
		if nil != err {
			t.Fatal(err)
		}
		tlsKeyBytes, err := ioutil.ReadFile(filepath.Join(userPath, "tls.key"))
		if nil != err {
			t.Fatal(err)
		}
		tlsCertBytes, err := ioutil.ReadFile(filepath.Join(userPath, "tls.crt"))
		if nil != err {
			t.Fatal(err)
		}
		users = append(users, &config.User{
			Name:    userName,
			IsAdmin: username == userName,
			Crypto: &config.Crypto{
				Key:     keyBytes,
				Cert:    certBytes,
				TlsKey:  tlsKeyBytes,
				TlsCert: tlsCertBytes,
			},
		})
	}
	return users
}

func testOrgPeers(orgNum, orgName, orgDomain, orgPath string, t *testing.T) []*config.Peer {
	var (
		peers                 []*config.Peer
		urlPort, eventUrlPort int
	)
	switch orgNum {
	default:
		urlPort = 7051
		eventUrlPort = 7053
	case "2":
		urlPort = 8051
		eventUrlPort = 8053
	case "3":
		urlPort = 9051
		eventUrlPort = 9053
	}
	for i := 0; i < 3; i++ {
		urlPort += i
		eventUrlPort += i
		peerName := strings.Join([]string{"peer", strconv.Itoa(i)}, "")
		peerPath := path.Join(orgPath, peerName)
		keyBytes, err := ioutil.ReadFile(filepath.Join(peerPath, "ca.key"))
		if nil != err {
			t.Fatal(err)
		}
		certBytes, err := ioutil.ReadFile(filepath.Join(peerPath, "ca.crt"))
		if nil != err {
			t.Fatal(err)
		}
		tlsKeyBytes, err := ioutil.ReadFile(filepath.Join(peerPath, "tls.key"))
		if nil != err {
			t.Fatal(err)
		}
		tlsCertBytes, err := ioutil.ReadFile(filepath.Join(peerPath, "tls.crt"))
		if nil != err {
			t.Fatal(err)
		}
		peers = append(peers, &config.Peer{
			Name:     peerName,
			Url:      strings.Join([]string{"grpcs://127.0.0.1", strconv.Itoa(urlPort)}, ":"),
			EventUrl: strings.Join([]string{"grpcs://127.0.0.1", strconv.Itoa(eventUrlPort)}, ":"),
			GrpcOptions: &config.GRPCOptions{
				SslTargetNameOverride: strings.Join([]string{peerName, orgName, orgDomain}, "."),
				KeepAliveTime:         "0s",
				KeepAliveTimeout:      "20s",
				KeepAlivePermit:       false,
				FailFast:              false,
				AllowInsecure:         false,
			},
			Crypto: &config.Crypto{
				Key:     keyBytes,
				Cert:    certBytes,
				TlsKey:  tlsKeyBytes,
				TlsCert: tlsCertBytes,
			},
			EventSource:    true,
			ChaincodeQuery: true,
			LedgerQuery:    true,
			EndorsingPeer:  true,
		})
		urlPort += 1000
		eventUrlPort += 1000
	}
	return peers
}
