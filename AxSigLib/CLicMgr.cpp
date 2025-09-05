/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2004-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:support@axantum.com and http://www.axantum.com
----
	CLicMgr.cpp                     Handle and validate licenses
*/
#include "stdafx.h"
#include "CLicMgr.h"
#include "hex.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CLicMgr.cpp"

/// \brief Set the public key to use
void
CLicMgr::SetVerifier(const axpl::ttstring& sVerifierHex) {
	try {
		// Prime the StringSource with the Hex string, decode it and decode the result for the
		// public key.
		m_Verifier.AccessKey().BERDecode(StringSource(axpl::t2s(sVerifierHex), true, new HexDecoder));
	}
	catch (CryptoPP::Exception Err) {
		ASSCHK(false, s2t(Err.GetWhat()).c_str());
	}
	return;
}

/// \brief Add a specified license type after checking the sig for the licensee
bool
CLicMgr::AddChkType(const axpl::ttstring& sType, const axpl::ttstring& sLicensee, const axpl::ttstring& sSig) {
	// First check if any is empty - this is not valid.
	if (sLicensee.empty() || sSig.empty()) {
		return false;
	}
	m_sLastErrorMsg = _T("");
	try {
		// Decode the signature from the string base 34 representation
		StringSource signatureSource(t2s(sSig), true, new Base34Decoder(ShortRbits + SBits));
		// Check that we can get just the right amount of bits from it
		if (signatureSource.MaxRetrievable() != m_Verifier.SignatureLength()) {
			m_sLastErrorMsg = _T("Internal error. Signature wrong length.");
		}
		else {
			// Allocate a block and put the signature there
			SecByteBlock signature(m_Verifier.SignatureLength());
			signatureSource.Get(signature, signature.size());

			// Make us a filter, taking both a signature and a message as input
			SignatureVerificationFilter* verifierFilter = new SignatureVerificationFilter(m_Verifier);
			// First we put the signature to the filter
			verifierFilter->Put(signature, m_Verifier.SignatureLength());
			// Then we send the message to it
			StringSource messageSource(m_Verifier.CanonicalizeMessage(t2s(sType + sLicensee)), true, verifierFilter);

			// And now we check the result.
			if (verifierFilter->GetLastResult()) {
				// It was ok - add this to the map of valid licenses
				m_smspValidLic[sType] = axpl::ttstringpair(sLicensee, sSig);
				return true;
			}
		}
	}
	catch (CryptoPP::Exception Err) {
		m_sLastErrorMsg = s2t(Err.GetWhat());
	}
	return false;
}

/// \brief Check if we have a valid license for a given type
bool
CLicMgr::ChkType(const axpl::ttstring& sType) {
	// Just iterate through the list of currently valid licenses and return true
	// if we find an exact match.
	return m_smspValidLic.find(sType) != m_smspValidLic.end();
}

/// \brief Get a valid license, if any, for a given type
axpl::ttstringpair
CLicMgr::GetType(const axpl::ttstring& sType) {
	map<axpl::ttstring, axpl::ttstringpair>::const_iterator it = m_smspValidLic.find(sType);
	if (it != m_smspValidLic.end()) {
		return it->second;
	}
	return axpl::ttstringpair(_T(""), _T(""));
}