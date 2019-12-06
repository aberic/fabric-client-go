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

// CryptoRootCAPath 指定联盟主域名的根证书文件目录
func CryptoRootCAPath(leagueDomain string) string {
	return filepath.Join(dataPath, leagueDomain, "crypto-config", "root", "ca")
}

// CryptoRootCATmpPath 指定联盟主域名的根证书文件临时目录
func CryptoRootCATmpPath(leagueDomain string) string {
	return filepath.Join(dataTmpPath, leagueDomain, "crypto-config", "root", "ca")
}

// CryptoRootTLSCAPath 指定联盟主域名的根TLS证书文件目录
func CryptoRootTLSCAPath(leagueDomain string) string {
	return filepath.Join(dataPath, leagueDomain, "crypto-config", "root", "tlsca")
}

// CryptoRootTLSCATmpPath 指定联盟主域名的根TLS证书文件临时目录
func CryptoRootTLSCATmpPath(leagueDomain string) string {
	return filepath.Join(dataTmpPath, leagueDomain, "crypto-config", "root", "tlsca")
}

// RootCACertFileName 指定联盟主域名的根证书文件名称
func RootCACertFileName(leagueDomain string) string {
	return strings.Join([]string{"ca.", leagueDomain, "-cert.pem"}, "")
}

// RootTLSCACertFileName 指定联盟主域名的根TLS证书文件名称
func RootTLSCACertFileName(leagueDomain string) string {
	return strings.Join([]string{"tlsca.", leagueDomain, "-cert.pem"}, "")
}

// CsrTmpPath CA请求证书文件临时目录
func CsrTmpPath(leagueDomain, orgName, orgDomain string) string {
	return filepath.Join(dataTmpPath, leagueDomain, "csr", strings.Join([]string{orgName, orgDomain}, "."))
}

// CsrFileTmpPath CA请求证书文件临时路径
func CsrFileTmpPath(leagueDomain, orgName, orgDomain, commonName string) string {
	fileName := strings.Join([]string{commonName, "csr"}, ".")
	return filepath.Join(dataTmpPath, leagueDomain, "csr", strings.Join([]string{orgName, orgDomain}, "."), fileName)
}

// CryptoOrgAndNodePath 组织机构及其节点根目录
func CryptoOrgAndNodePath(leagueDomain, orgDomain, orgName, nodeName string, isPeer bool) (orgPath, nodePath string) {
	var orgsName, orgPathName, nodesName, nodePathName string
	if isPeer {
		orgsName = "peerOrganizations/"
		nodesName = "peers"
		nodePathName = strings.Join([]string{nodeName, orgName, orgDomain}, ".")
	} else {
		orgsName = "ordererOrganizations/"
		nodesName = "orderers"
		nodePathName = strings.Join([]string{nodeName, orgName, orgDomain}, ".")
	}
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	orgPath = filepath.Join(dataPath, leagueDomain, "crypto-config", orgPathName)
	nodePath = filepath.Join(orgPath, nodesName, nodePathName)
	return
}

// CryptoOrgAndNodeTmpPath 组织机构及其节点临时根目录
func CryptoOrgAndNodeTmpPath(leagueDomain, orgDomain, orgName, nodeName string, isPeer bool) (orgPath, nodePath string) {
	var orgsName, orgPathName, nodesName, nodePathName string
	if isPeer {
		orgsName = "peerOrganizations/"
		nodesName = "peers"
		nodePathName = strings.Join([]string{nodeName, orgName, orgDomain}, ".")
	} else {
		orgsName = "ordererOrganizations/"
		nodesName = "orderers"
		nodePathName = strings.Join([]string{nodeName, orgName, orgDomain}, ".")
	}
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	orgPath = filepath.Join(dataTmpPath, leagueDomain, "crypto-config", orgPathName)
	nodePath = filepath.Join(orgPath, nodesName, nodePathName)
	return
}

// CryptoOrgAndUserPath 组织机构及其用户根目录
func CryptoOrgAndUserPath(leagueDomain, orgDomain, orgName, nodeName string, isPeer bool) (orgPath, nodePath string) {
	var orgsName, orgPathName, nodesName, nodePathName string
	if isPeer {
		orgsName = "peerOrganizations/"
		nodesName = "users"
		nodePathName = strings.Join([]string{nodeName, "@", orgName, ".", orgDomain}, "")
	} else {
		orgsName = "ordererOrganizations/"
		nodesName = "users"
		nodePathName = strings.Join([]string{nodeName, "@", orgName, ".", orgDomain}, "")
	}
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	orgPath = filepath.Join(dataPath, leagueDomain, "crypto-config", orgPathName)
	nodePath = filepath.Join(orgPath, nodesName, nodePathName)
	return
}

// CryptoOrgAndUserTmpPath 组织机构及其用户临时根目录
func CryptoOrgAndUserTmpPath(leagueDomain, orgDomain, orgName, nodeName string, isPeer bool) (orgPath, nodePath string) {
	var orgsName, orgPathName, nodesName, nodePathName string
	if isPeer {
		orgsName = "peerOrganizations/"
		nodesName = "users"
		nodePathName = strings.Join([]string{nodeName, "@", orgName, ".", orgDomain}, "")
	} else {
		orgsName = "ordererOrganizations/"
		nodesName = "users"
		nodePathName = strings.Join([]string{nodeName, "@", orgName, ".", orgDomain}, "")
	}
	orgPathName = strings.Join([]string{orgsName, orgName, ".", orgDomain}, "")
	orgPath = filepath.Join(dataTmpPath, leagueDomain, "crypto-config", orgPathName)
	nodePath = filepath.Join(orgPath, nodesName, nodePathName)
	return
}

// CertNodeCAName 组织下节点证书名称
func CertNodeCAName(orgName, orgDomain, nodeName string) string {
	return strings.Join([]string{nodeName, ".", orgName, ".", orgDomain, "-cert.pem"}, "")
}

// CertUserCAName 组织下用户证书名称
func CertUserCAName(orgName, orgDomain, userName string) string {
	return strings.Join([]string{userName, "@", orgName, ".", orgDomain, "-cert.pem"}, "")
}
