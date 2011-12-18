#ifndef AXCRYPT2GOWIN_H
#define AXCRYPT2GOWIN_H
/*! \file
    \brief AxCrypt2GoWin.h - The Windows implementation of AxCrypt2Go

    Windows-specific global stuff, there should be no internal other include-dependencies for this data

    @(#) $Id$

    AxCrypt2Go - Stand-Alone Install-free AxCrypt for the road.

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

    The author may be reached at mailto:axcrypt@axantum.com and http://axcrypt.sourceforge.net

    Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
    YYYY-MM-DD              Reason
    2005-08-06              Initial
\endverbatim
*/

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "AxCrypt2GoWin.h"

/// \brief Windows messages used by the application. WM_USER is reserved.
enum {
    WM_USER_WORKERTHREAD = WM_USER + 1,     ///< Create a worker-thread
    WM_USER_CREATEPROGRESS,                 ///< Create a progress window
    WM_USER_DESTROYPROGRESS,                ///< Destroy a progress window
    WM_USER_CHANGENOTIFICATION,             ///< Something has changed in the list view
};

#endif // AXCRYPT2GOWIN_H
