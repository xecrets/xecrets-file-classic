#pragma once
/*! \file
    \brief AxDecrypt - Stand-alone Ax Crypt-decrypter and self-extractor.

    @(#) $Id$

    AxDecrypt - Stand-alone Ax Crypt-decrypter and self-extractor.

    Copyright (C) 2004 Svante Seleborg/Axon Data, All rights reserved.

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
*/

#ifndef WINVER
#define WINVER 0x0600           // Allow use of features specific to Windows Vista or later.
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600     // Allow use of features specific to Windows Vista or later.
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0600        // Specifies that the minimum required platform is Internet Explorer 6.0.
#endif

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#define _CRT_RAND_S

#ifdef NDEBUG
#define _SECURE_SCL 0
#endif

// Windows Header Files:
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>

// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>

//// Some tricks to avoid inclusion of exception handling.
//// Disable warning about empty statement in <list> caused by dummy defines below
#pragma warning ( push )
//#pragma warning ( disable : 4390 )
//#include <xstddef>
//#undef _TRY_BEGIN                           /// Dummy to avoid exception code included
//#undef _CATCH                               /// Dummy to avoid exception code included
//#undef _CATCH_ALL                           /// Dummy to avoid exception code included
//#undef _CATCH_END                           /// Dummy to avoid exception code included
//#undef _RAISE                               /// Dummy to avoid exception code included
//#undef _RERAISE                             /// Dummy to avoid exception code included
//#undef _THROW0                              /// Dummy to avoid exception code included
//#undef _THROW1                              /// Dummy to avoid exception code included
//#undef _THROW                               /// Dummy to avoid exception code included
//#define _TRY_BEGIN  if (true) {             ///< Dummy to avoid exception code included
//#define _CATCH(x)   } else {                ///< Dummy to avoid exception code included
//#define _CATCH_ALL  } else {                ///< Dummy to avoid exception code included
//#define _CATCH_END  }                       ///< Dummy to avoid exception code included
//
///// \brief Dummy to avoid exception code included
//#define _RAISE(x)       MessageBox(NULL, _T("Internal error - _RAISE(x)"), _T("AxDecrypt"), MB_OK|MB_ICONSTOP)
//
///// \brief Dummy to avoid exception code included
//#define _RERAISE        MessageBox(NULL, _T("Internal error - _RERAISE"), _T("AxDecrypt"), MB_OK|MB_ICONSTOP)
//
//inline void _NOOP() { }
//#define _THROW0()                           ///< Dummy to avoid exception code included
//#define _THROW1(x)                          ///< Dummy to avoid exception code included
//#define _THROW(x, y) _NOOP()                 ///< Dummy to avoid exception code included

// The template library generates 'conditional expression is constant'
#pragma warning ( disable : 4127 )
#include <list>
#pragma warning ( pop )
using namespace std;

#define NO_GZIP

// Local Header Files
#include "AxDecrypt.h"
#include "Passphrase.h"