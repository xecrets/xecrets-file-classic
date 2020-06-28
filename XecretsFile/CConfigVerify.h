#ifndef CCONFIGVERIFY_H
#define CCONFIGVERIFY_H
/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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
	CVerifyFileSigs.h                       Verifying handler of config files
*/
#include "../XecretsFileCommon/CConfig.h"

#pragma warning(disable : 4267 4661)
#define CRYPTOPP_DEFAULT_NO_DLL
#include "config.h"
#include "eccrypto.h"

using namespace CryptoPP;

/// \brief Interface to XML-based, signed configuration files.
/// A main, unsigned XML file typically named Sigs.XML contains information
/// pointing to a real configuration file, which is signed. The signature
/// is stored in Sigs.XML along with the reference to the file. The Sigs.XML
/// file may also contain signed licenses etc.
/// The configuration XML, typically named Config.XML, is signed and can
/// therefore be trusted. It contains signatures of various files and other
/// information about the application that is static after release (since it
/// is signed).
class CConfigVerify : public CConfig {
	ECDSA<ECP, SHA1>::Verifier m_PublicKey;  ///< The actual public key, loaded from an encoded format.

public:
	// Point to the signature XML to use
	CConfigVerify(const axpl::ttstring& sSigs, const axpl::ttstring& sPath = _TT(""));
	// Give us the public key to verify with
	void SetBEREncodedFilePublicKey(const unsigned char* bPublicKey, const size_t cbPublicKey);
	/// \brief Recursively descend the XML tree and find all signatures we can find.
	void GetFilesSigsFromXML(const XNode* pXNode, axpl::ttstringpairvector& spvFileSigs);
	/// \brief Verify that a file signature is correct
	bool VerifyFile(const axpl::ttstring& sFile, const axpl::ttstring& sSig, const axpl::ttstring& sPath = _TT(""));
	/// \brief Verify the file signatures in the provided array of string pairs.
	bool VerifyFiles(const axpl::ttstringpairvector& spvFileSigs, const axpl::ttstring& sPath = _TT(""));
};
#endif