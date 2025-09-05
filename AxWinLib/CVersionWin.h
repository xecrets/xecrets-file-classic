/*! \file
	\brief Get various version info from version resources of an exectuable

	@(#) $Id$

	AxLib - Collection of useful code. All code here is generally intended to be simply included in
	the projects, the intention is not to províde a stand-alone linkable library, since so many
	variants are possible (single/multithread release/debug etc) and also because it is frequently
	used in open source programs, and then the distributed source must be complete and there is no
	real reason to make the distributions so large etc.

	It's of course also possible to build a partial or full library in the respective solution.

	Copyright (C) 2006-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:svante@axantum.com and http://wwww.axantum.com
----
	CVersionWin.h
*/

namespace AxLib {
	/// \brief Get version from version resources
	///
	/// Get various version info from version resources of an
	/// executable, perhaps ourselves.
	class CVersion {
		VS_FIXEDFILEINFO* m_pFixedFileInfo;     ///< Fixed info, references m_pFileVersionInfo
		void* m_pFileVersionInfo;               ///< The version resources from the executable

	private:
		_TCHAR* newLoadString(UINT uId, HMODULE hModule = NULL); ///< Load a string resource into an new'd string buffer

	public:
		CVersion(HINSTANCE hInstance = NULL);   ///< Load the resources
		~CVersion();                            ///< Free allocated memory
		WORD Major();                           ///< Get the Major version word
		WORD Minor();                           ///< Get the Minor version word
		WORD Minuscle();                        ///< Get the Minuscle version word
		WORD Patch();                           ///< Get the Patch level version word
		_TCHAR* newProductName();               ///< Product name, from resource. Allocated.
		_TCHAR* newCompanyName();               ///< Company name, from resource. Allocated.
		_TCHAR* newLegalCopyright();            ///< Copyright string, from resource. Allocated.
		_TCHAR* newNameVersionString(UINT uProductName = 0);         ///< Formatted version string. Allocated.
	};
} // namespace AxLib
