#ifndef CFMTMSG_H
#define CFMTMSG_H
/*
    @(#) $Id$

    The purpose of this class is to encapsulate functionality for dynamically
    allocating strings that is the result for printf-like functionality. I'm
    not sure how this should be done portably for a MacIntosh or Unix-platform...

    Copyright (C) 2001-2022 Svante Seleborg/Axon Data, All rights reserved.

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
    CFmtMsg.h                       Actions on temporary files and directories

    E-mail                          YYYY-MM-DD              Reason
    support@axantum.com             2002-10-07              Initial

*/

#include    <stdarg.h>

class CFmtMsg {
    TCHAR *m_szFmtMsg;
public:
    CFmtMsg(const TCHAR *szMsg, ...);
    CFmtMsg(CFmtMsg& fmtmsg);
    CFmtMsg(void);

    void Fmt(const TCHAR *szMsg, ...);
    ~CFmtMsg();
    TCHAR *Get();
};

#endif