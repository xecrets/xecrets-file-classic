#pragma once
/*! \file
    \brief Implement launch-and-wait functionality for a document.

    @(#) $Id$

    Given a document path, launch an associated application, and do not return until the application is
    done with the document.

    Copyright (C) 2008 Svante Seleborg/Axantum Software AB, All rights reserved.

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
    IDocumentAppLaunch.h
*/

namespace awl {
    class IDocumentAppLaunch {
    public:
        static IDocumentAppLaunch *New(); ///< Create an instance of CDocumentAppLaunch
        virtual bool LaunchAndWait(const wchar_t *wzDocumentPath) = 0; ///< Launch the app. Return true if all went well.
        virtual const wchar_t *ErrorMessage(); ///< If an error, an error message is kept here.
        virtual ~IDocumentAppLaunch() = 0;
    };
}
