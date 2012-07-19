/*
    @(#) $Id$

    Ax Crypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
    Server or Web Storage of Document Files.

    Copyright (C) 2004 Svante Seleborg/Axantum Software AB, All rights reserved.

    This program is free software; you can redistribute it and/or modify it under the terms
    of the GNU General Public License as published by the Free Software Foundation;
    either version 2 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program;
    if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
    Boston, MA 02111-1307 USA

    The author may be reached at mailto:software@axantum.com and http://www.axantum.com
----
    CVerifyFileSigs.cpp - Verify file signatures

    E-mail                          YYYY-MM-DD              Reason
    software@axantum.com             2004-09-13              Initial

*/
#include "stdafx.h"
#include "CConfigVerify.h"
#include "hex.h"
#include "files.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CConfigVerify.cpp"

#pragma warning(disable : 4267 4661)

/// \brief Point to the signature XML to use
/// If unsuccessful, get the error with GetLastError() and is also indicated
/// GetSigsXML returning NULL. If a path is given, it is prepended along with
/// a slash to the path to the sigs file.
/// \param sSigs a file system path to the signature XML
/// \param sPath a file system path to the folder of the signature XML
CConfigVerify::CConfigVerify(const axpl::ttstring &sSigs, const axpl::ttstring &sPath) : CConfig(sSigs, sPath) {
}

/// \brief Load the BERencoded binary public key used for file signature validation
void
CConfigVerify::SetBEREncodedFilePublicKey(const unsigned char *bPublicKey, const size_t cbPublicKey) {
    try {
        // Load the key into the verifier object
        m_PublicKey.AccessKey().BERDecode(StringStore(bPublicKey, cbPublicKey));
    } catch (CryptoPP::Exception Err) {
        ASSCHK(false, axpl::s2t(Err.GetWhat()).c_str());
    }
}

/// \brief Recursively descend the XML tree and find all signatures we can find.
/// It looks for elements named 'Signature' - regardless of depth, and with
/// attribute 'File'. When it finds such, it locates the file and signature
/// wich it adds to the provided ttstringpairvector.
/// \param pXNode A XML tree to descend
/// \param spvFileSigs A vector of string pairs where we return the File/Sig-pairs.
void
CConfigVerify::GetFilesSigsFromXML(const XNode *pXNode, axpl::ttstringpairvector &spvFileSigs) {
    if (pXNode) {
        if (TTStringCompareIgnoreCase(pXNode->name, _TT("signature"))) {
            for (XAttrs::const_iterator it = pXNode->attrs.begin(); it != pXNode->attrs.end(); it++) {
                if (TTStringCompareIgnoreCase((*it)->name, _TT("file"))) {
                    spvFileSigs.push_back(ttstringpair((*it)->value, pXNode->value));
                }
            }
        }

        for (XNodes::const_iterator it = pXNode->childs.begin(); it != pXNode->childs.end(); it++) {
            GetFilesSigsFromXML(*it, spvFileSigs);
        }
    }
}

/// \brief Verify that a file signature is correct
/// \param sFile The name of a file to check
/// \param sSig The purported signature
/// \return true if ok, false otherwise. See GetLastErrorMsg() for details.
bool
CConfigVerify::VerifyFile(const axpl::ttstring &sFile, const axpl::ttstring &sSig, const axpl::ttstring &sPath) {
    try {
        // Get BufferedTransformation which also decodes the hex-representation
        StringSource publicKey(axpl::t2s(sSig), true, new HexDecoder());

        // Verify that the length is the same as the expected signature length.
        if (publicKey.MaxRetrievable() != m_PublicKey.SignatureLength()) {
            m_sLastError = _TT("Invalid public verification key length");
            return false;
        }

	    // Allocate a memory block for the signature, and then get it
        SecByteBlock signature(m_PublicKey.SignatureLength());
        publicKey.Get(signature, m_PublicKey.SignatureLength());

        VerifierFilter *pVerifierFilter(new VerifierFilter(m_PublicKey));
	    pVerifierFilter->Put(signature, m_PublicKey.SignatureLength());
        FileSource f(axpl::t2s((sPath.empty() ? sFile : sPath + _TT("/") + sFile)).c_str(), true, pVerifierFilter);

        if (!pVerifierFilter->GetLastResult()) {
            m_sLastError = _TT("Invalid signature for: ") + sFile;
            return false;
        }
    } catch (CryptoPP::Exception Err) {
        m_sLastError = axpl::s2t(Err.GetWhat());
        return false;
    }

    // Yes! All was well, the file was untampered with.
    return true;
}

/// \brief Verify the file signatures in the provided array of string pairs.
/// \param spvFileSigs Pairs of file names and signatures to be verified
/// \return true if all are verified and no other errors occurr. See GetLastErrorMsg() othewise.
bool
CConfigVerify::VerifyFiles(const axpl::ttstringpairvector &spvFileSigs, const axpl::ttstring &sPath) {
    for (axpl::ttstringpairvector::const_iterator it = spvFileSigs.begin(); it != spvFileSigs.end(); it++) {
        if (!VerifyFile(it->first, it->second, sPath)) {
            return false;
        }
    }
    return true;
}