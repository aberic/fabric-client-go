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

// ChainCodePath code目录
func ChainCodePath(leagueName, chainCodeName, version string) (source, path, zipPath string) {
	source = filepath.Join(dataPath, leagueName, "code/go")
	path = filepath.Join(chainCodeName, version, chainCodeName)
	zipPath = strings.Join([]string{source, "/src/", path, ".zip"}, "")
	return
}
