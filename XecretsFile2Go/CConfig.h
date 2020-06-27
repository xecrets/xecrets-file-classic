#ifndef CCONFIG_H
#define CCONFIG_H
/*! \file
	\brief CConfig.h - Configuration information for XecretsFile2Go

	@(#) $Id$

	XecretsFile2Go - Stand-Alone Install-free Ax Crypt for the road.

	This file defines configuration data that might differ for different builds, and provides an
	interface for the rest of the code to fetch strings and other values that might differ between
	configurations. One specific use is to differentiate OEM versions, the GPL version (user built) and the
	official free version.

	The requirement is to have as little as possible, preferrably nothing, to be compile-time dependent. The
	only things that should be compile time dependent are those that by definition has to do with compilation,
	specifically various debug versions.

	The goal is to have one compile for all versions, and version specific strings and information to be
	either patched after the build into the executable, or have them contained in an external configuration
	file, typically a signed XML-file. The actual strategy may vary depending on the target platform.

	Copyright (C) 2005 Svante Seleborg/Axantum Software AB, All rights reserved.

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
	2005-08-06              Initial
\endverbatim
*/
#include <algorithm>
#include <locale>
#include <cctype>

#include "../XecretsFileLib/XecretsFileLibPP.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CConfig.h"

/// \brief Configuration info. This class only has static members, do not try to instantiate.
/// Since this is a static-only class, the implementation may be fully or partially os-dependent
/// with static contexts defined in the implementation file.
class CConfig {
private:
	/// \brief The short product-name, used for insertion into messages whenever the program is referenced
	static axcl::tstring m_sShortProductName;
	/// \brief A Short, single-word, presumably pretty unique name to identify things internally
	static axcl::tstring m_sInternalName;

protected:
	/// \brief A private dummy constructor to ensure that no instance is created of this class
	CConfig() {
	}

private:
	/// \brief Convert a string to a suitable form to use as an internal name - this is not to be visible, ever.
	static const axcl::tstring MakeInternalName(const axcl::tstring& s) {
		axcl::tstring d;
		for (axcl::tstring::const_iterator it = s.begin(); it != s.end() && d.length() < 10; it++) {
			if (std::isalnum(*it, std::locale::classic())) {
				d.push_back(std::toupper(*it, std::locale::classic()));
			}
		}
		return d;
	}

public:
	/// \brief The short product-name, used for insertion into messages whenever the program is referenced
	/// This short name will typically be identical to the base-name of the executable file, and will
	/// typically (but not necessarily) be a single word. It will be used to refer to the program itself
	/// in messages to the user. It should not be used for internal identification purposes.
	/// Example: XecretsFile2Go
	static const axcl::tstring& ShortProductName() {
		return m_sShortProductName;
	}

public:
	/// \brief A Short, single-word, presumably pretty unique name to identify things internally
	/// This name should never be visible to the user, so it should not be used as a tag in configuration
	/// files etc. It's strictly for internal use, such as naming OS objects etc. It should be strictly
	/// alphanumeric, all uppercase or lowercase as convention dictates and be short.
	/// Example: XecretsFile2Go
	static const axcl::tstring& InternalName() {
		return m_sInternalName;
	}

	/// \brief Transform a file-name into a file name representing an encrypted file
	/// This converts a string, assumed to be a file name, into the form used for encrypted files.
	/// Example: append .xxx to the name.
	static axcl::tstring MakeEncryptedFileName(const axcl::tstring& sPlainName);

	/// \brief Transform a file-name into a file name representing a decrypted file
	/// This converts a string, assumed to be a file name, into the form used for decrypted files.
	/// Example: remove .xxx from the name.
	static axcl::tstring MakeDecryptedFileName(const axcl::tstring& sCipherName);

	/// \brief Check if a file-name represents an encrypted file.
	/// Tests to see if the file-name pattern appears to represent an encrypted file. This is only
	/// an educated guess, so to be certain the file must be inspected.
	/// Example: check if the name ends with .xxx
	static bool IsEncryptedFileName(const axcl::tstring& sCipherName);
};

#endif // CCONFIG_H