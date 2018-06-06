#ifndef CLICMGR_H
#define CLICMGR_H
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
    CLicMgr.h                    Manage licenses
*/
#include "SVerify.h"
#include "Base34Dec.h"
#include <string>

using namespace std;

class CLicMgr {
    // Total of 183 bits gives us 36 characters in Base 34 for signatures.
    // These are hard-coded parameters and must match what is in AxKeyGen. They should probably
    // live in a common header file, but...
    static const unsigned int ShortRbits = 55;// The shortened hash
    static const int SBits = 128;           // The size of the s parameter from the elliptic curve used
    SHORTVERIFY<SECDSA<ECP, SHA1, ShortRbits> > m_Verifier;

    map<axpl::ttstring, axpl::ttstringpair> m_smspValidLic; // A map of validated license types along with the info
    axpl::ttstring m_sLastErrorMsg;                 // The last error message...
public:
    CLicMgr() {}
    CLicMgr(const axpl::ttstring &sVerifierHex) {
        SetVerifier(sVerifierHex);
    }
    axpl::ttstring GetLastErrorMsg() {
        return m_sLastErrorMsg;
    }
    /// \brief Set the public key to use
    void SetVerifier(const axpl::ttstring &sVerifierHex);
    /// \brief Add a specified license type after checking the sig for the licensee
    bool AddChkType(const axpl::ttstring &sType, const axpl::ttstring &sLicensee, const axpl::ttstring &sSig);
    /// \brief Check if we have a valid license for a given type
    bool ChkType(const axpl::ttstring &sType);
    /// \brief Get a valid license, if any, for a given type
    ttstringpair GetType(const axpl::ttstring &sType);
};
#endif