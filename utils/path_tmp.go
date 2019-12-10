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
	"path/filepath"
	"strings"
)

// MspID 组织MspID
func MspID(orgName string) string {
	return strings.Join([]string{orgName, "MSP"}, "")
}

// CertificateAuthorityFilePath CertificateAuthorityFilePath
func CertificateAuthorityFilePath(leagueDomain, caName string) string {
	return filepath.Join(dataPath, leagueDomain, "ca", caName, "cert.pem")
}

// CertificateAuthorityClientKeyFilePath CertificateAuthorityClientKeyFilePath
func CertificateAuthorityClientKeyFilePath(leagueDomain, caName string) string {
	return filepath.Join(dataPath, leagueDomain, "ca", caName, "client.key")
}

// CertificateAuthorityClientCertFilePath CertificateAuthorityClientCertFilePath
func CertificateAuthorityClientCertFilePath(leagueDomain, caName string) string {
	return filepath.Join(dataPath, leagueDomain, "ca", caName, "client.crt")
}

// CryptoOrgMspPath CryptoOrgMspPath
func CryptoOrgMspPath(leagueDomain, orgDomain, orgName string, isPeer bool) (mspPath string) {
	var orgsName, orgPathName string
	if isPeer {
		orgsName = "peerOrganizations/"
	} else {
		orgsName = "ordererOrganizations/"
	}
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	return filepath.Join(dataPath, leagueDomain, "crypto-config", orgPathName, "msp")
}

// ChainCodePath code目录
func ChainCodePath(leagueName, chainCodeName, version string) (source, path, zipPath string) {
	source = filepath.Join(dataPath, leagueName, "code/go")
	path = filepath.Join(chainCodeName, version, chainCodeName)
	zipPath = strings.Join([]string{source, "/src/", path, ".zip"}, "")
	return
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

// ChannelUpdateTXFilePath 通道tx文件路径
func ChannelUpdateTXFilePath(leagueName, channelName string) string {
	return strings.Join([]string{ChannelArtifactsPath(leagueName), "/", channelName, "_update.pb"}, "")
}
