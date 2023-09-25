/*! \file
	\brief Axgettext - Interface to GNU gettext routines

	@(#) $Id$

*/
/*! \page License Axgettext - Interface to GNU gettext routines

	Copyright (C) 2005-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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
*/
//    version
//    htmlinclude Version.txt
/*! \mainpage Axgettext - Interface to GNU gettext routines

	\author
	Svante Seleborg/Axantum Software AB

	\par License:
	\ref License "GNU General Public License"

	This is an interface to the GNU gettext library, with the following designgoals

	- Dynamic loading of dll if present, use statically linked version otherwise. This should satisfy the terms
	  of the LGPL under which gettext is licensed, allowing the main program to use a statically linked version
	  whilst offering the user the option to substitute for their own at their leisure - regardless of whether this
	  code in turn is licensed under GPL or as a commerical application.

	- Conformance to the TCHAR paradigm in Windows. All text in the dictionary is assumed by this code to be stored
	  as UTF-8 encoded Unicode. When run as a wide char (Unicode) program, this is translated via MultiByteToWideChar into
	  UTF-16 used by Windows. When run as a narrow char (Ansi) program, the UTF-8 representation is translated into
	  Ansi by roundtripping from MultiByteToWideChar to WideCharToMultiByte into Ansi.

	- Translated strings are inserted a tree that is kept for the entire program execution, so that pointers are universally
	  useful and identical once referenced.

	- The ability to exlude all real use of gettext by defining the preprocessor variable
	  NOGETTEXT. The primary purpose of this is for testing purposes since it currently is
	  not possible to ask the gettext library to release all allocated memory, and this lack
	  makes memory leak detection well neigh impossible. This is a rather surprising lack of
	  fundamental good programming practice for such an established package.
*/
#include "stdafx.h"

#include <windows.h>
#include <tchar.h>
#include <stdarg.h>

#include <set>
#include <string>

#ifndef NOGETTEXT
// The libgnuintl.h is the one to use from this side of the build. libintl.h is used to build the
// actual library, and also defines the dll-import stuff for vc, which is not a good idea here.
// The only difference between libintl.h and libgnuintl.h at the time of this writing (2005-11-14)
// was the use of LIBINTL_DLL_EXPORTED in the function definitions. A simple conditional to allow
// to set that to nothing would have sufficed instead as far as I can determine.
#include "../intl/libgnuintl.h"
#endif NOGETTEXT

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "Axgettext.cpp"

extern "C" int libintl_vswprintf(wchar_t* resultbuf, size_t length, const wchar_t* format, va_list args);
extern "C" int libintl_vsnprintf(char* resultbuf, size_t length, const char* format, va_list args);

namespace AxLib {
	CGettext::stringset CGettext::m_setTranslations;
	CGettext::uintstringmap CGettext::m_mapStringResources;

	static HMODULE mhIntlDll = LoadLibrary(_T("./intl.dll"));

	// The following set of "null"-implementations are used to mimic the basic semantic functionality
	// of the corresponding gettext-functions, but are used when we effectively want to ignore and not
	// use gettext, primarily for debugging - at least until such a time when gettext supports proper
	// release of memory resources so as to allow memory leak detection.
	extern "C" {
		static char* ax_gettext(const char* __msgid) {
			return const_cast<char*>(__msgid);
		}

		static char* ax_dgettext(const char* /*__domainname*/, const char* __msgid) {
			return const_cast<char*>(__msgid);
		}

		static char* ax_textdomain(const char* __domainname) {
			return const_cast<char*>(__domainname);
		}

		static char* ax_bindtextdomain(const char* __domainname, const char* /*__dirname*/) {
			return const_cast<char*>(__domainname);
		}

		static char* ax_bind_textdomain_codeset(const char* /*__domainname*/, const char* __codeset) {
			return const_cast<char*>(__codeset);
		}
	}

	// Define NOGETTEXT to effectively short-circuit all use of gettext, but still retain the AxLib::tgettext semantics, i.e.
	// handling of Unicode/Non-Unicode scenarios with one source.
	extern "C" {
#ifdef NOGETTEXT
		static char* (*pfgettext) (const char* __msgid) = ax_gettext;
		static char* (*pfdgettext) (const char* __domainname, const char* __msgid) = ax_dgettext;
		static char* (*pftextdomain) (const char* __domainname) = ax_textdomain;
		static char* (*pfbindtextdomain) (const char* __domainname, const char* __dirname) = ax_bindtextdomain;
		static char* (*pfbind_textdomain_codeset) (const char* __domainname, const char* __codeset) = ax_bind_textdomain_codeset;
#ifdef _UNICODE
		static int (*pfvsntprintf)(wchar_t* resultbuf, size_t length, const wchar_t* format, va_list args) = vswprintf;
#else
		static int (*pfvsntprintf)(char* resultbuf, size_t length, const char* format, va_list args) = vsprintf;
#endif
#else
		static char* (*pfgettext) (const char* __msgid) = mhIntlDll == NULL ? gettext : (char* (*) (const char*))GetProcAddress(mhIntlDll, "libintl_gettext");
		static char* (*pfdgettext) (const char* __domainname, const char* __msgid) = mhIntlDll == NULL ? dgettext : (char* (*) (const char*, const char*))GetProcAddress(mhIntlDll, "libintl_dgettext");
		static char* (*pftextdomain) (const char* __domainname) = mhIntlDll == NULL ? textdomain : (char* (*) (const char*))GetProcAddress(mhIntlDll, "libintl_textdomain");
		static char* (*pfbindtextdomain) (const char* __domainname, const char* __dirname) = mhIntlDll == NULL ? bindtextdomain : (char* (*) (const char*, const char*))GetProcAddress(mhIntlDll, "libintl_bindtextdomain");
		static char* (*pfbind_textdomain_codeset) (const char* __domainname, const char* __codeset) = mhIntlDll == NULL ? bind_textdomain_codeset : (char* (*) (const char*, const char*))GetProcAddress(mhIntlDll, "libintl_bind_textdomain_codeset");
#ifdef _UNICODE
		// Need to #define HAVE_FWPRINTF 1 in config.h - it's #undef'd for unknown reasons
		static int (*pfvsntprintf)(wchar_t* resultbuf, size_t length, const wchar_t* format, va_list args) = mhIntlDll == NULL ? libintl_vswprintf : (int (*)(wchar_t*, size_t, const wchar_t*, va_list))GetProcAddress(mhIntlDll, "libintl_vswprintf");
#else
		static int (*pfvsntprintf)(char* resultbuf, size_t length, const char* format, va_list args) = mhIntlDll == NULL ? libintl_vsnprintf : (int (*)(char*, size_t, const char*, va_list))GetProcAddress(mhIntlDll, "libintl_vsnprintf");
#endif
#endif
	}

	/// \brief Lookup a ASCII string with GNU gettext, and convert the translated UTF-8 to UTF-16
	/// \return The converted string, or NULL on error
	wchar_t* CGettext::Utf16Gettext(const char* s) {
		char* utf8 = pfgettext(s);
		int cc = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
		if (cc <= 0) {
			return NULL;
		}
		wchar_t* utf16 = new wchar_t[cc];

		cc = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, utf16, cc);
		if (cc <= 0) {
			return NULL;
		}
		return utf16;
	}

	/// \brief Store a string, and return a pointer to the stored string
	template<class T> static T* CGettext::SaveReturn(T* s) {
		// Implement the handling of vertical-bar classification of translated texts. A translated (normally a non-translated...)
		// string may contain the veritical-bar (|) to ensure context-sensitive translation of short items. For example,
		// MainMenu|File|Exit would be intended to translate the word 'Exit' in the context of the main menu's File menu. If,
		// this text is not translated, we remove the prefixing, and just return the word 'Exit'. If the text actually needs
		// to contain a vertical bar, we start the text with a vertical bar to 'escape' this processing.
		if (s[0]) {
			if (s[0] != _T('|')) {
				T* m = _tcsrchr(s, _T('|'));
				if (m != NULL) {
					s = m + 1;
				}
			}
			else {
				s++;
			}
		}
		stringset::const_iterator it = m_setTranslations.insert(m_setTranslations.begin(), std::basic_string<T>(s));
		return const_cast<T*>(it->c_str());
	}

#ifdef _UNICODE

	/// \brief A Unicode-version of GNU gettext
	/// \param s The ASCII string to translate
	/// \return The translated string in Unicode (UTF-16) form
	const wchar_t* CGettext::Gettext(const char* sMsgId) {
		std::auto_ptr<wchar_t> utf16(Utf16Gettext(sMsgId));

		if (utf16.get() == NULL) {
			return L"AxLib::CGettext::Gettext() Error in call to MultiByteToWideChar()";
		}

		return SaveReturn<wchar_t>(utf16.get());
	}

#else

	/// \brief A Ansi-version of GNU gettext
	/// \param s The ASCII string to translate
	/// \return The translated string in Ansi form
	const char* CGettext::Gettext(const char* sMsgId) {
		std::auto_ptr<wchar_t> utf16(Utf16Gettext(sMsgId));

		if (utf16.get() == NULL) {
			return "AxLib::tgettext() Error in call to MultiByteToWideChar()";
		}

		int cb = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, utf16.get(), -1, NULL, 0, NULL, NULL);
		if (cb <= 0) {
			return "AxLib::tgettext() Error in call to WideCharToMultiByte()";
		}
		std::auto_ptr<char> ansi(new char[cb]);
		cb = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, utf16.get(), -1, ansi.get(), cb, NULL, NULL);
		if (cb <= 0) {
			return "AxLib::tgettext() Error in call to WideCharToMultiByte()";
		}

		return SaveReturn<char>(ansi.get());
	}

#endif

	const char* CGettext::TextDomain(const char* sDomainName) {
		return pftextdomain(sDomainName);
	}

	const char* CGettext::BindTextDomain(const char* sDomainName, const char* sDirName) {
		return pfbindtextdomain(sDomainName, sDirName);
	}

	const char* CGettext::BindTextDomainCodeset(const char* sDomainName, const char* sCodeset) {
		return pfbind_textdomain_codeset(sDomainName, sCodeset);
	}

	/// \brief Get stuff which should not be translated - but may need be different in different versions - from resources
	///
	/// The function is included in this gettext-wrapper for easier full-feature useage in a Windows-environment. The wrapper
	/// is anyway fully Windows-dependent. In a Unix-situation, a different wrapper is needed. It should be noted that
	/// the idea is to use string resources (in lieu of the alternative - to use non-translated strings) for things which
	/// are not language-dependendent, but version/issue dependent. Truly constant stuff, such as pure internal error messages
	/// should still use non-translated _T()/_TT()-style strings (in a Unix-port, treat _T and _TT like _N).
	/// \param uID The identifier of the text-resource to get
	/// \return Pointer to a text that should be regarded as statically allocated.
	const _TCHAR* CGettext::GetStringResource(unsigned int uID) {
		uintstringmap::const_iterator it = m_mapStringResources.find(uID);
		if (it != m_mapStringResources.end()) {
			return it->second.c_str();
		}

		int cc = 50, ccCopied = 0;
		std::auto_ptr<_TCHAR> s;
		do {
			cc += cc;
			s.reset(new _TCHAR[cc]);
			ccCopied = LoadString(GetModuleHandle(NULL), uID, s.get(), cc);
			if (ccCopied == 0) {
				return _T("");
			}
		} while (ccCopied >= (cc - 1));
		// Ensure nul-termination
		s.get()[cc - 1] = _T('\0');
		return (m_mapStringResources[uID] = std::basic_string<_TCHAR>(s.get())).c_str();
	}

	int CGettext::sntprintf(_TCHAR* sBuffer, size_t cc, const _TCHAR* sFormat, ...) {
		va_list args;
		int retval;

		va_start(args, sFormat);

		retval = pfvsntprintf(sBuffer, cc, sFormat, args);
		va_end(args);
		return retval;
	}
} // namespace AxLib