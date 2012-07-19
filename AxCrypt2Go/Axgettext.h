#ifndef AXGETTEXT_H
#define AXGETTEXT_H
/*! \file
    \brief Axgettext.h - Interface to GNU gettext routines

    @(#) $Id$

    Axgettext.h - Interface to GNU gettext routines

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
----
*/
//#include "libintl.h"
#include <memory>
#include <set>
#include <map>
#include <string>

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "Axgettext.h"

namespace AxLib {
    class CGettext {
    private:
        typedef std::set<std::basic_string<_TCHAR> > stringset;
        static stringset m_setTranslations;
        static wchar_t *Utf16Gettext(const char * s);
        template<class T> static T *SaveReturn(T * s);

        typedef std::map<unsigned int, std::basic_string<_TCHAR> > uintstringmap;
        static uintstringmap m_mapStringResources;
    public:
        static const _TCHAR *Gettext(const char *sMsgId);
        static const _TCHAR *GetStringResource(unsigned int uID);
        static int sntprintf(_TCHAR *sBuffer, size_t cc, const _TCHAR *sFormat, ...);
        static const char *TextDomain(const char *sDomainName);
        static const char *BindTextDomain(const char *sDomainName, const char *sDirName);
        static const char *BindTextDomainCodeset(const char *sDomainName, const char *sCodeset);
    };
}

#endif AXGETTEXT_H