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

var priParentBytes = `-----BEGIN PRIVATE KEY-----
MHcCAQEEIIaHoNd1A8KWQeVNzSBRvzT0JKf6uGwWdLCT/mRocVqSoAoGCCqGSM49
AwEHoUQDQgAEatf+/Vs1yCIMqAnf4gLlaM+22bhdlxcySk99EBKZZOuCud16/ndo
7ZEe9u8N//9l0On2YH3oRSafKFmrUg1koQ==
-----END PRIVATE KEY-----`

var rootCertBytes = `-----BEGIN CERTIFICATE-----
MIIB9TCCAZygAwIBAgIISgXS2eOjdQwwCgYIKoZIzj0EAwIwWDELMAkGA1UEBhMC
Q04xEDAOBgNVBAgTB0JlaWppbmcxEDAOBgNVBAcTB0JlaWppbmcxDzANBgNVBAoT
BmxlYWd1ZTEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMTkxMjA2MDY1OTExWhcN
MzMwODE0MDY1OTExWjBYMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHQmVpamluZzEQ
MA4GA1UEBxMHQmVpamluZzEPMA0GA1UEChMGbGVhZ3VlMRQwEgYDVQQDEwtleGFt
cGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGrX/v1bNcgiDKgJ3+IC
5WjPttm4XZcXMkpPfRASmWTrgrndev53aO2RHvbvDf//ZdDp9mB96EUmnyhZq1IN
ZKGjUDBOMA4GA1UdDwEB/wQEAwIBFjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAMBgNVHQ4EBQQDAQIDMAoGCCqGSM49BAMC
A0cAMEQCIBlyCH3Rj+u+mUO9t6ei5FjtPjYSvfhOgvHTQSh9rKZ4AiAEhHLe+t++
PLb8f6i0eB8R152bDEaEpAgw8kDbc3yIJA==
-----END CERTIFICATE-----`

var pubBytes = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHgioiBii+X6dgYRwdXbEbbNgbZog
1vXemDItzT+Jnd83Lt+NCHcdQxt0v7m9ky6gKQSx2Uu9zz+tfBE5vPfc7Q==
-----END PUBLIC KEY-----`

var csrBytes = `-----BEGIN CERTIFICATE REQUEST-----
MIIBPDCB4wIBADBYMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHQmVpamluZzEQMA4G
A1UEBxMHQmVpamluZzEPMA0GA1UEChMGbGVhZ3VlMRQwEgYDVQQDEwtleGFtcGxl
LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGrX/v1bNcgiDKgJ3+IC5WjP
ttm4XZcXMkpPfRASmWTrgrndev53aO2RHvbvDf//ZdDp9mB96EUmnyhZq1INZKGg
KTAnBgkqhkiG9w0BCQ4xGjAYMBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAoGCCqG
SM49BAMCA0gAMEUCICSKUWUDvqo+rOncH9Q/krz/1Syc97UGbiCQ9PdXlDtcAiEA
qydz8zubbSc2WM2SmFDLKnaScMSNVw8jsR3Sc066kno=
-----END CERTIFICATE REQUEST-----`

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
