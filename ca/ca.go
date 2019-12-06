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
	"github.com/aberic/fabric-client-go/grpc/proto/ca"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	mspctx "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"path/filepath"
	"time"
)

// generateCrypto 生成密钥对
func generateCrypto(config *ca.ReqKeyConfig) (*ca.RespKeyConfig, error) {
	kc := &keyConfig{}
	cryptoType, cryptoAlgorithm := generateCryptoParams(config)
	priFileBytes, pubFileBytes, err := kc.generateCrypto(cryptoType, cryptoAlgorithm)
	if nil != err {
		return &ca.RespKeyConfig{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &ca.RespKeyConfig{Code: ca.Code_Success, PriKeyBytes: priFileBytes, PubKeyBytes: pubFileBytes}, nil
}

// generateLeagueCrt 生成联盟根证书
func generateLeagueCrt(league *ca.ReqCreateLeague) (*ca.RespCreateLeague, error) {
	var (
		cc                                  = &CertConfig{}
		caRootCertBytes, tlsCaRootCertBytes []byte
		err                                 error
	)
	caPath, certName, tlsCaPath, tlsCertName := cc.getRootCA(league.Csr.CommonName)
	certFilePathFilePath := filepath.Join(caPath, certName)
	tlsCertFilePathFilePath := filepath.Join(tlsCaPath, tlsCertName)
	if caRootCertBytes, err = cc.generateCryptoRootCrt(league.PriKeyBytes, getSubject(league.Csr), getSignAlgorithm(league.SignAlgorithm), certFilePathFilePath); nil != err {
		return &ca.RespCreateLeague{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	if tlsCaRootCertBytes, err = cc.generateCryptoRootCrt(league.PriTlsKeyBytes, getSubject(league.Csr), getSignAlgorithm(league.SignAlgorithm), tlsCertFilePathFilePath); nil != err {
		return &ca.RespCreateLeague{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &ca.RespCreateLeague{Code: ca.Code_Success, CaCertBytes: caRootCertBytes, TlsCaCertBytes: tlsCaRootCertBytes}, nil
}

// generateOrgChildCsr 生成CA请求证书文件
func generateOrgChildCsr(csr *ca.ReqCreateCsr) (*ca.RespCreateCsr, error) {
	var (
		cc       = &CertConfig{}
		csrBytes []byte
		err      error
	)
	if csrBytes, err = cc.generateCsr(csr.PriKeyBytes, getSubject(csr.Name), getSignAlgorithm(csr.SignAlgorithm)); err != nil {
		return &ca.RespCreateCsr{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &ca.RespCreateCsr{Code: ca.Code_Success, CsrBytes: csrBytes}, nil
}

// generateOrgChildCrt 生成组织下子节点/用户证书
func generateOrgChildCrt(child *ca.ReqCreateOrgChild) (*ca.RespCreateOrgChild, error) {
	var (
		cc            = &CertConfig{}
		cert, tlsCert []byte
		err           error
	)
	// tls ca cert
	if tlsCert, err = cc.generateCryptoChildCrt(child.OrgChild.RootTlsCaCertBytes, child.OrgChild.PriTlsParentBytes,
		child.OrgChild.PubTlsBytes, getSubject(child.OrgChild.EnrollInfo.EnrollRequest.Name),
		getSignAlgorithm(child.OrgChild.SignAlgorithm)); nil != err {
		return &ca.RespCreateOrgChild{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	// ca cert
	if cert, err = cc.enroll(getGcr(child.OrgChild), child.OrgChild.EnrollInfo.FabricCaServerURL,
		child.OrgChild.EnrollInfo.EnrollRequest.EnrollID, child.OrgChild.EnrollInfo.EnrollRequest.Secret); nil != err {
		return &ca.RespCreateOrgChild{Code: ca.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &ca.RespCreateOrgChild{Code: ca.Code_Success, Cert: cert, TlsCert: tlsCert}, nil
}

// GetCAInfo returns generic CA information
func caInfo(orgName string, sdk *fabsdk.FabricSDK) (*msp.GetCAInfoResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetCAInfo()
}

// Enroll enrolls a registered user in order to receive a signed X509 certificate.
// A new key pair is generated for the user. The private key and the
// enrollment certificate issued by the CA are stored in SDK stores.
// They can be retrieved by calling IdentityManager.GetSigningIdentity().
//  Parameters:
//  enrollmentID enrollment ID of a registered user
//  opts are optional enrollment options
//
//  Returns:
//  an error if enrollment fails
func enroll(orgName, enrollmentID string, sdk *fabsdk.FabricSDK, opts ...msp.EnrollmentOption) error {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return err
	}
	return mspClient.Enroll(enrollmentID, opts...)
}

// Reenroll reenrolls an enrolled user in order to obtain a new signed X509 certificate
//  Parameters:
//  enrollmentID enrollment ID of a registered user
//
//  Returns:
//  an error if re-enrollment fails
func reenroll(orgName, enrollmentID string, sdk *fabsdk.FabricSDK, opts ...msp.EnrollmentOption) error {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return err
	}
	return mspClient.Reenroll(enrollmentID, opts...)
}

// Register registers a User with the Fabric CA
//  Parameters:
//  request is registration request
//
//  Returns:
//  enrolment secret
func register(orgName string, registerReq *msp.RegistrationRequest, sdk *fabsdk.FabricSDK) (string, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return "", err
	}
	return mspClient.Register(registerReq)
}

// AffiliationRequest represents the request to add/remove affiliation to the fabric-ca-server
func addAffiliation(orgName string, affReq *msp.AffiliationRequest, sdk *fabsdk.FabricSDK) (*msp.AffiliationResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.AddAffiliation(affReq)
}

// RemoveAffiliation removes an existing affiliation from the server
func removeAffiliation(orgName string, affReq *msp.AffiliationRequest, sdk *fabsdk.FabricSDK) (*msp.AffiliationResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.RemoveAffiliation(affReq)
}

// ModifyAffiliation renames an existing affiliation on the server
func modifyAffiliation(orgName string, affReq *msp.ModifyAffiliationRequest, sdk *fabsdk.FabricSDK) (*msp.AffiliationResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.ModifyAffiliation(affReq)
}

// GetAffiliation returns information about the requested affiliation
func getAffiliation(affiliation, orgName string, sdk *fabsdk.FabricSDK) (*msp.AffiliationResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetAffiliation(affiliation)
}

// GetAffiliationByCaName returns information about the requested affiliation
func getAffiliationByCaName(affiliation, orgName, caName string, sdk *fabsdk.FabricSDK) (*msp.AffiliationResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetAffiliation(affiliation, msp.WithCA(caName))
}

// GetAllAffiliations returns all affiliations that the caller is authorized to see
func getAllAffiliations(orgName string, sdk *fabsdk.FabricSDK) (*msp.AffiliationResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetAllAffiliations()
}

// GetAllAffiliationsByCaName returns all affiliations that the caller is authorized to see
func getAllAffiliationsByCaName(orgName, caName string, sdk *fabsdk.FabricSDK) (*msp.AffiliationResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetAllAffiliations(msp.WithCA(caName))
}

// GetAllIdentities returns all identities that the caller is authorized to see
//  Parameters:
//  options holds optional request options
//  Returns:
//  Response containing identities
func getAllIdentities(orgName string, sdk *fabsdk.FabricSDK) ([]*msp.IdentityResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetAllIdentities()
}

// GetAllIdentitiesByCaName returns all identities that the caller is authorized to see
//  Parameters:
//  options holds optional request options
//  Returns:
//  Response containing identities
func getAllIdentitiesByCaName(orgName, caName string, sdk *fabsdk.FabricSDK) ([]*msp.IdentityResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetAllIdentities(msp.WithCA(caName))
}

// CreateIdentity creates a new identity with the Fabric CA server. An enrollment secret is returned which can then be used,
// along with the enrollment ID, to enroll a new identity.
//  Parameters:
//  request holds info about identity
//
//  Returns:
//  Return identity info including the secret
func createIdentity(orgName string, req *msp.IdentityRequest, sdk *fabsdk.FabricSDK) (*msp.IdentityResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.CreateIdentity(req)
}

// ModifyIdentity modifies identity with the Fabric CA server.
//  Parameters:
//  request holds info about identity
//
//  Returns:
//  Return updated identity info
func modifyIdentity(orgName string, req *msp.IdentityRequest, sdk *fabsdk.FabricSDK) (*msp.IdentityResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.ModifyIdentity(req)
}

// GetIdentity retrieves identity information.
//  Parameters:
//  ID is required identity ID
//  options holds optional request options
//
//  Returns:
//  Response containing identity information
func getIdentity(id, orgName string, sdk *fabsdk.FabricSDK) (*msp.IdentityResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetIdentity(id)
}

// GetIdentityByCaName retrieves identity information.
//  Parameters:
//  ID is required identity ID
//  options holds optional request options
//
//  Returns:
//  Response containing identity information
func getIdentityByCaName(id, caName, orgName string, sdk *fabsdk.FabricSDK) (*msp.IdentityResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetIdentity(id, msp.WithCA(caName))
}

// RemoveIdentity removes identity with the Fabric CA server.
//  Parameters:
//  request holds info about identity to be removed
//
//  Returns:
//  Return removed identity info
func removeIdentity(orgName string, req *msp.RemoveIdentityRequest, sdk *fabsdk.FabricSDK) (*msp.IdentityResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.RemoveIdentity(req)
}

// CreateSigningIdentity creates a signing identity with the given options
func createSigningIdentity(orgName string, sdk *fabsdk.FabricSDK, opts ...mspctx.SigningIdentityOption) (mspctx.SigningIdentity, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.CreateSigningIdentity(opts...)
}

// GetSigningIdentity returns signing identity for id
//  Parameters:
//  id is user id
//
//  Returns:
//  signing identity
func getSigningIdentity(id, orgName string, sdk *fabsdk.FabricSDK) (mspctx.SigningIdentity, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.GetSigningIdentity(id)
}

// Revoke revokes a User with the Fabric CA
//  Parameters:
//  request is revocation request
//
//  Returns:
//  revocation response
func revoke(orgName string, req *msp.RevocationRequest, sdk *fabsdk.FabricSDK) (*msp.RevocationResponse, error) {
	mspClient, err := msp.New(sdk.Context(), msp.WithOrg(orgName))
	if err != nil {
		return nil, err
	}
	return mspClient.Revoke(req)
}

func generateCryptoParams(config *ca.ReqKeyConfig) (ct cryptoType, cal cryptoAlgorithm) {
	switch config.CryptoType {
	default:
		ct = 0
	case ca.CryptoType_ECDSA:
		ct = cryptoECC
		switch config.GetEccAlgorithm() {
		default:
			cal = 0
		case ca.EccAlgorithm_p256:
			cal = p256
		case ca.EccAlgorithm_p384:
			cal = p384
		case ca.EccAlgorithm_p521:
			cal = p521
		}
	case ca.CryptoType_RSA:
		ct = cryptoRSA
		switch config.GetRsaAlgorithm() {
		default:
			cal = 0
		case ca.RsaAlgorithm_r2048:
			cal = r2048
		case ca.RsaAlgorithm_r4096:
			cal = r4096
		}
	}
	return
}

func getGcr(child *ca.OrgChild) generateCertificateRequest {
	gcr := generateCertificateRequest{CR: string(child.EnrollInfo.CsrPemBytes), EnrollRequest: *child.EnrollInfo.EnrollRequest}
	gcr.NotAfter = time.Now().Add(time.Duration(child.EnrollInfo.NotAfter) * 24 * time.Hour)
	gcr.NotBefore = time.Now().Add(time.Duration(child.EnrollInfo.NotBefore) * 24 * time.Hour)
	return gcr
}

// getSignAlgorithm 获取x509签名算法
func getSignAlgorithm(signAlgorithm ca.SignAlgorithm) x509.SignatureAlgorithm {
	switch signAlgorithm {
	default:
		return x509.ECDSAWithSHA256
	case ca.SignAlgorithm_ECDSAWithSHA256:
		return x509.ECDSAWithSHA256
	case ca.SignAlgorithm_ECDSAWithSHA384:
		return x509.ECDSAWithSHA384
	case ca.SignAlgorithm_ECDSAWithSHA512:
		return x509.ECDSAWithSHA512
	case ca.SignAlgorithm_SHA256WithRSA:
		return x509.SHA256WithRSA
	case ca.SignAlgorithm_SHA512WithRSA:
		return x509.SHA512WithRSA
	}
}

func getSubject(csr *ca.CSR) pkix.Name {
	return pkix.Name{
		Country:            csr.Country,
		Organization:       csr.Organization,
		OrganizationalUnit: csr.OrganizationalUnit,
		Locality:           csr.Locality,
		Province:           csr.Province,
		StreetAddress:      csr.StreetAddress,
		PostalCode:         csr.PostalCode,
		SerialNumber:       csr.SerialNumber,
		CommonName:         csr.CommonName,
	}
}
