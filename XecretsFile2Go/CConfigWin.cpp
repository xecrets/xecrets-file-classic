/*! \file
    \brief CConfigWin.cpp - The Windows implementation of configuration-specific parameters

    @(#) $Id$

    AxCrypt2Go - Stand-Alone Install-free Ax Crypt for the road.

    This module initializes all the static members of the CConfig class. It relies heavily on the fact
    that static initializers in a module are executed in the order they appear in the file...

    Copyright (C) 2006 Svante Seleborg/Axantum Software AB, All rights reserved.

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

    Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
    YYYY-MM-DD              Reason
    2006-01-15              Initial
\endverbatim
*/

#include "stdafx.h"

#include "CConfigWin.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CConfigWin.cpp"

/// \brief This may be used in more than one place, so start by setting this up.
static HMODULE hModule = ::GetModuleHandle(NULL);

/// \brief The current way of specifying the extension - should be moved from here in the future likely
const axcl::tstring CConfigWin::m_sEncryptedFileExtension = AXENCRYPTEDFILEEXT;

/// \brief Derive a short product name from the name of the executable
static axcl::tstring GetShortProductName() {
    DWORD dwMaxLen = 0, dwLen;
    std::auto_ptr<_TCHAR> szModuleFileName;
    do {
        szModuleFileName.reset(new _TCHAR[dwMaxLen += MAX_PATH]);
        dwLen = ::GetModuleFileName(hModule, szModuleFileName.get(), dwMaxLen);
    } while (dwLen == dwMaxLen);
    ASSAPI(dwLen != 0);
    PathRemoveExtension(szModuleFileName.get());
    return PathFindFileName(szModuleFileName.get());
}

axcl::tstring CConfig::m_sShortProductName = GetShortProductName();
axcl::tstring CConfig::m_sInternalName = MakeInternalName(m_sShortProductName);

/// \brief Transform a file-name into a file name representing an encrypted file
/// This converts a string, assumed to be a file name, into the form used for encrypted files.
/// Example: append .xxx to the name.
axcl::tstring CConfig::MakeEncryptedFileName(const axcl::tstring& sPlainName) {
    return axcl::tstring(sPlainName).append(CConfigWin::GetEncryptedFileExtension());
}

/// \brief Transform a file-name into a file name representing a decrypted file
/// This converts a string, assumed to be a file name, into the form used for decrypted files.
/// Example: remove .xxx from the name.
axcl::tstring CConfig::MakeDecryptedFileName(const axcl::tstring& sCipherName) {
    if (IsEncryptedFileName(sCipherName)) {
        return axcl::tstring(sCipherName).erase(sCipherName.length() - CConfigWin::GetEncryptedFileExtension().length());
    }
    return sCipherName;
}

/// \brief Check if a file-name represents an encrypted file.
/// Tests to see if the file-name pattern appears to represent an encrypted file. This is only
/// an educated guess, so to be certain the file must be inspected.
/// Example: check if the name ends with .xxx
bool CConfig::IsEncryptedFileName(const axcl::tstring& sCipherName) {
    if (sCipherName.length() > CConfigWin::GetEncryptedFileExtension().length()) {
        axcl::tstring sCipherExtension(sCipherName.substr(sCipherName.length() - CConfigWin::GetEncryptedFileExtension().length()));
        for (axcl::tstring::iterator it = sCipherExtension.begin(); it != sCipherExtension.end(); it++) {
            *it = std::tolower(*it, std::locale::classic());
        }
        return sCipherExtension == CConfigWin::GetEncryptedFileExtension();
    }
    return false;
}