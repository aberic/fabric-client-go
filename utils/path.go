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

package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// MspID 组织MspID
func MspID(orgName string) string {
	return strings.Join([]string{orgName, "MSP"}, "")
}

// RootTLSCACertFileName 指定联盟主域名的根TLS证书文件名称
func RootTLSCACertFileName(leagueDomain string) string {
	return strings.Join([]string{"tlsca.", leagueDomain, "-cert.pem"}, "")
}

// RootOrgCACertFileName 指定联盟主域名的根证书文件名称
func RootOrgCACertFileName(orgName, orgDomain string) string {
	return strings.Join([]string{"ca.", orgName, ".", orgDomain, "-cert.pem"}, "")
}

// RootOrgTLSCACertFileName 指定联盟主域名的根TLS证书文件名称
func RootOrgTLSCACertFileName(orgName, orgDomain string) string {
	return strings.Join([]string{"tlsca.", orgName, ".", orgDomain, "-cert.pem"}, "")
}

// CryptoOrgPath 组织机构及其节点根目录
func CryptoOrgPath(leagueDomain, orgDomain, orgName string, isPeer bool) string {
	var orgsName, orgPathName string
	if isPeer {
		orgsName = "peerOrganizations/"
	} else {
		orgsName = "ordererOrganizations/"
	}
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	return filepath.Join(dataPath, leagueDomain, "crypto-config", orgPathName)
}

// CryptoOrgAndNodePath 组织机构及其节点根目录
func CryptoOrgAndNodePath(leagueDomain, orgDomain, orgName, nodeName string, isPeer bool) (orgPath, nodePath string) {
	var orgsName, orgPathName, nodesName, nodePathName string
	if isPeer {
		orgsName = "peerOrganizations/"
		nodesName = "peers"
	} else {
		orgsName = "ordererOrganizations/"
		nodesName = "orderers"
	}
	nodePathName = strings.Join([]string{nodeName, orgName, orgDomain}, ".")
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	orgPath = filepath.Join(dataPath, leagueDomain, "crypto-config", orgPathName)
	nodePath = filepath.Join(orgPath, nodesName, nodePathName)
	return
}

// CryptoOrgAndUserPath 组织机构及其用户根目录
func CryptoOrgAndUserPath(leagueDomain, orgDomain, orgName, username string, isPeer bool) (orgPath, userPath string) {
	var orgsName, orgPathName, nodesName, nodePathName string
	if isPeer {
		orgsName = "peerOrganizations/"
	} else {
		orgsName = "ordererOrganizations/"
	}
	nodePathName = strings.Join([]string{username, "@", orgName, ".", orgDomain}, "")
	nodesName = "users"
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	orgPath = filepath.Join(dataPath, leagueDomain, "crypto-config", orgPathName)
	userPath = filepath.Join(orgPath, nodesName, nodePathName)
	return
}

// CertNodeCAName 组织下节点证书名称
func CertNodeCAName(orgName, orgDomain, nodeName string) string {
	return strings.Join([]string{nodeName, ".", orgName, ".", orgDomain, "-cert.pem"}, "")
}

// CertNodeCANameWithOutCert 组织下节点证书名称
func CertNodeCANameWithOutCert(orgName, orgDomain, nodeName string) string {
	return strings.Join([]string{nodeName, orgName, orgDomain}, ".")
}

// CertUserCAName 组织下用户证书名称
func CertUserCAName(orgName, orgDomain, userName string) string {
	return strings.Join([]string{userName, "@", orgName, ".", orgDomain, "-cert.pem"}, "")
}

// CertUserCANameWithOutCert 组织下用户证书名称
func CertUserCANameWithOutCert(orgName, orgDomain, userName string) string {
	return strings.Join([]string{userName, "@", orgName, ".", orgDomain}, "")
}

// CertOrgCaNameWithOutCert 组织下节点证书名称
func CertOrgCaNameWithOutCert(orgName, orgDomain string) string {
	return strings.Join([]string{"ca", orgName, orgDomain}, ".")
}

// CertOrgTlsCaNameWithOutCert 组织下节点证书名称
func CertOrgTlsCaNameWithOutCert(orgName, orgDomain string) string {
	return strings.Join([]string{"tlsca", orgName, orgDomain}, ".")
}

// CryptoConfigPath crypto-config目录
func CryptoConfigPath(leagueName string) string {
	return filepath.Join(dataPath, leagueName, "crypto-config")
}

// ChannelArtifactsPath channel-artifacts目录
func ChannelArtifactsPath(leagueName string) string {
	return filepath.Join(dataPath, leagueName, "channel-artifacts")
}

// GenesisBlockFilePath orderer.genesis.block路径
func GenesisBlockFilePath(leagueName string) string {
	return filepath.Join(dataPath, leagueName, "channel-artifacts/orderer.genesis.block")
}

// ChannelTXFilePath 通道tx文件路径
func ChannelTXFilePath(leagueName, channelName string) string {
	return strings.Join([]string{ChannelArtifactsPath(leagueName), "/", channelName, ".tx"}, "")
}

// CryptoGenesisOrgMspPath CryptoGenesisOrgMspPath
func CryptoGenesisOrgMspPath(leagueDomain, orgDomain, orgName string, isPeer bool) (mspPath string) {
	var orgsName, orgPathName string
	if isPeer {
		orgsName = "peerOrganizations/"
	} else {
		orgsName = "ordererOrganizations/"
	}
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	return filepath.Join(os.TempDir(), "genesis", leagueDomain, "crypto-config", orgPathName, "msp")
}
