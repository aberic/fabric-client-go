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

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

var (
	priParentBytes = `-----BEGIN PRIVATE KEY-----
MHcCAQEEIIhrOabzAfOlN0/i0sXGKJguCZ826fsLelzW2p2rjCLzoAoGCCqGSM49
AwEHoUQDQgAE87Z73DwJaF/ma9JDJ1vOAfEET28ugvPbWGmVl3X7O5TGyfLmCdqc
KsZsFqVS4myUmbg2dndSqaaEGz0ZyMunRg==
-----END PRIVATE KEY-----`
	rootCertBytes = `-----BEGIN CERTIFICATE-----
MIIB9TCCAZygAwIBAgIIAO3TOff5WAcwCgYIKoZIzj0EAwIwWDELMAkGA1UEBhMC
Q04xEDAOBgNVBAgTB0JlaWppbmcxEDAOBgNVBAcTB0JlaWppbmcxDzANBgNVBAoT
BmxlYWd1ZTEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMTkxMjA5MDA1MTExWhcN
MzMwODE3MDA1MTExWjBYMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHQmVpamluZzEQ
MA4GA1UEBxMHQmVpamluZzEPMA0GA1UEChMGbGVhZ3VlMRQwEgYDVQQDEwtleGFt
cGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPO2e9w8CWhf5mvSQydb
zgHxBE9vLoLz21hplZd1+zuUxsny5gnanCrGbBalUuJslJm4NnZ3UqmmhBs9GcjL
p0ajUDBOMA4GA1UdDwEB/wQEAwIBFjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAMBgNVHQ4EBQQDAQIDMAoGCCqGSM49BAMC
A0cAMEQCIEYlkqe+JjAEptJrHODZuFH86qIrGtPB9otoi28DMzyjAiBWH98H3raa
LCPUn2kHCW5fX0lFsSJ+w/xYuZCPJLkYiA==
-----END CERTIFICATE-----`
	pubBytes = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHgioiBii+X6dgYRwdXbEbbNgbZog
1vXemDItzT+Jnd83Lt+NCHcdQxt0v7m9ky6gKQSx2Uu9zz+tfBE5vPfc7Q==
-----END PUBLIC KEY-----`
)

func TestGenerateCryptoRootCrt(t *testing.T) {
	var (
		cc              = &CertConfig{}
		caRootCertBytes []byte
		err             error
	)
	if caRootCertBytes, err = cc.generateCryptoRootCrt([]byte(priParentBytes), pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256, "/tmp/caRootCertBytes/cert.crt"); nil != err {
		t.Error(err)
	}
	t.Log(string(caRootCertBytes))

	// TestGenerateCryptoRootCrtByteFail
	if caRootCertBytes, err = cc.generateCryptoRootCrt([]byte{}, pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256, "/tmp/caRootCertBytes/cert.crt"); nil != err {
		t.Log(err)
	}

	// TestGenerateCryptoRootCrtFileFail
	if caRootCertBytes, err = cc.generateCryptoRootCrt([]byte(priParentBytes), pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256, "/fabric"); nil != err {
		t.Log(err)
	}
}

func TestGenerateCsr(t *testing.T) {
	var (
		cc       = &CertConfig{}
		csrBytes []byte
		err      error
	)
	if csrBytes, err = cc.generateCsr([]byte(priParentBytes), pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256); nil != err {
		t.Error(err)
	}
	t.Log(string(csrBytes))

	// TestGenerateCsrCNFail
	if csrBytes, err = cc.generateCsr([]byte(priParentBytes), pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "",
	}, x509.ECDSAWithSHA256); nil != err {
		t.Log(err)
	}

	// TestGenerateCsrBytesFail
	if csrBytes, err = cc.generateCsr([]byte{}, pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256); nil != err {
		t.Log(err)
	}
}

func TestGenerateCryptoChildCrt(t *testing.T) {
	var (
		cc        = &CertConfig{}
		certBytes []byte
		err       error
	)
	if certBytes, err = cc.generateCryptoChildCrt([]byte(rootCertBytes), []byte(priParentBytes), []byte(pubBytes), pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256); nil != err {
		t.Error(err)
	}
	t.Log(string(certBytes))

	// TestGenerateCryptoChildCrtByteFail1
	if certBytes, err = cc.generateCryptoChildCrt([]byte{}, []byte(priParentBytes), []byte(pubBytes), pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256); nil != err {
		t.Log(err)
	}

	// TestGenerateCryptoChildCrtByteFail2
	if certBytes, err = cc.generateCryptoChildCrt([]byte(rootCertBytes), []byte{}, []byte(pubBytes), pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256); nil != err {
		t.Log(err)
	}

	// TestGenerateCryptoChildCrtByteFail3
	if certBytes, err = cc.generateCryptoChildCrt([]byte(rootCertBytes), []byte(priParentBytes), []byte{}, pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256); nil != err {
		t.Log(err)
	}

	// TestGenerateCryptoChildCrtFileFail
	if certBytes, err = cc.generateCryptoChildCrt([]byte(rootCertBytes), []byte(priParentBytes), []byte(pubBytes), pkix.Name{
		Country:      []string{"CN"},
		Organization: []string{"league"},
		Locality:     []string{"Beijing"},
		Province:     []string{"Beijing"},
		CommonName:   "example.com",
	}, x509.ECDSAWithSHA256); nil != err {
		t.Error(err)
	}
}
