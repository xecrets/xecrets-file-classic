#pragma once
/*! \file
    \brief Support routines for Vista or later

    @(#) $Id$

    Various things that are special for Vista or later

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

    The author may be reached at mailto:svante@axantum.com and http://wwww.axantum.com
----
    VistaOrLater.h
*/
namespace awl {
    extern bool IsVistaOrLater(); ///< Determine if we're running Vista or later
    extern bool NeedsAndCanElevateOnVista(); ///< Determine if we need and can elevate to admin rights
    extern bool IsAdminOnVista(); ///< Are we running as admin one way or another on Vista?
    extern bool RelaunchElevatedOnVista(DWORD *pdwReturnCode, HWND hWnd = NULL, int nShowCmd = SW_SHOWNORMAL); ///< Actually elevate on Vista
}
