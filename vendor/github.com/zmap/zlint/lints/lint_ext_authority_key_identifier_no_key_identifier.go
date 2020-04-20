package lints

/*
 * ZLint Copyright 2018 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/***********************************************************************
RFC 5280: 4.2.1.1
The keyIdentifier field of the authorityKeyIdentifier extension MUST
   be included in all certificates generated by conforming CAs to
   facilitate certification path construction.  There is one exception;
   where a CA distributes its public key in the form of a "self-signed"
   certificate, the authority key identifier MAY be omitted.  The
   signature on a self-signed certificate is generated with the private
   key associated with the certificate's subject public key.  (This
   proves that the issuer possesses both the public and private keys.)
   In this case, the subject and authority key identifiers would be
   identical, but only the subject key identifier is needed for
   certification path building.
***********************************************************************/

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type authorityKeyIdNoKeyIdField struct{}

func (l *authorityKeyIdNoKeyIdField) Initialize() error {
	return nil
}

func (l *authorityKeyIdNoKeyIdField) CheckApplies(c *x509.Certificate) bool {
	return true
}

func (l *authorityKeyIdNoKeyIdField) Execute(c *x509.Certificate) *LintResult {
	if c.AuthorityKeyId == nil && !util.IsSelfSigned(c) { //will be nil by default if not found in x509.parseCert
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_authority_key_identifier_no_key_identifier",
		Description:   "CAs must include keyIdentifer field of AKI in all non-self-issued certificates",
		Citation:      "RFC 5280: 4.2.1.1",
		Source:        RFC5280,
		EffectiveDate: util.RFC2459Date,
		Lint:          &authorityKeyIdNoKeyIdField{},
	})
}
