#ifndef CSHELLMGRWIN_H
#define CSHELLMGRWIN_H
/*! \file
    \brief ShellMgr.h - The Windows implementation of AxCrypt2Go

    This code builds heavily on the sample code distributed with Windows Template Library,
    which does not name any contributor or author, nor specify any kind of restrictions of
    use. Whilst this particular file is in this form licensed under GNU GPL as per below,
    this is not an attempt to claim authorship of that original code. The intention is only
    to protect the modified work as it is published here.

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

#include "CDialogsWin.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CShellMgrWin.h"

class CShellItemIDList {
public:
    LPITEMIDLIST m_pidl;

    CShellItemIDList(LPITEMIDLIST pidl = NULL) : m_pidl(pidl) {
    }

    ~CShellItemIDList() {
        ::CoTaskMemFree(m_pidl);
    }

    void Attach(LPITEMIDLIST pidl) {
        ::CoTaskMemFree(m_pidl);
        m_pidl = pidl;
    }

    LPITEMIDLIST Detach() {
        LPITEMIDLIST pidl = m_pidl;
        m_pidl = NULL;
        return pidl;
    }

    bool IsNull() const {
        return (m_pidl == NULL);
    }

    CShellItemIDList& operator =(LPITEMIDLIST pidl) {
        Attach(pidl);
        return *this;
    }

    LPITEMIDLIST* operator &() {
        return &m_pidl;
    }

    operator LPITEMIDLIST() {
        return m_pidl;
    }

    operator LPCTSTR() const {
        return (LPCTSTR)m_pidl;
    }

    operator LPTSTR() {
        return (LPTSTR)m_pidl;
    }

    void CreateEmpty(UINT cbSize) {
        ::CoTaskMemFree(m_pidl);
        m_pidl = (LPITEMIDLIST)::CoTaskMemAlloc(cbSize);
        ATLASSERT(m_pidl != NULL);
        if(m_pidl != NULL)
            memset(m_pidl, 0, cbSize);
    }
};

/// \brief Our own custom data per list view item
typedef struct _LVItemData {    
    CComPtr<IShellFolder> spParentFolder;
    CShellItemIDList lpi;
    CShellItemIDList lpifq;
} LVITEMDATA, *LPLVITEMDATA;

/// \brief Our own custom data per tree view item
typedef struct _TVItemData {
    CComPtr<IShellFolder> spParentFolder;    
    CShellItemIDList lpi;
    CShellItemIDList lpifq;
} TVITEMDATA, *LPTVITEMDATA;

class CShellMgr;
struct WorkerThreadParam;
typedef DWORD (CShellMgr::*TWorkerFunctionPtr)(WorkerThreadParam*);

struct WorkerThreadParam {
    TWorkerFunctionPtr pWorkerFunction;
    LPSHELLFOLDER lpsf;
    CShellItemIDList lpi;
    CShellMgr* pShellMgr;
    DWORD (*ThreadFunc)(WorkerThreadParam *pParam);
    CDlgProgress m_DlgProgress;
    HWND hWndParent;
    POINT point;

public:
    ~WorkerThreadParam() {
        lpsf->Release();
    }
};

class CShellMgr {
public:
    int GetIconIndex(LPITEMIDLIST lpi, UINT uFlags);

    void GetNormalAndSelectedIcons(LPITEMIDLIST lpifq, LPTVITEM lptvitem);

    LPITEMIDLIST ConcatPidls(LPCITEMIDLIST pidl1, LPCITEMIDLIST pidl2);

    static BOOL GetName(LPSHELLFOLDER lpsf, LPITEMIDLIST lpi, DWORD dwFlags, LPTSTR lpFriendlyName, size_t cbFriendlyName);
    LPITEMIDLIST Next(LPCITEMIDLIST pidl);
    UINT GetSize(LPCITEMIDLIST pidl);
    LPITEMIDLIST CopyITEMID(LPITEMIDLIST lpi);

    LPITEMIDLIST GetFullyQualPidl(LPSHELLFOLDER lpsf, LPITEMIDLIST lpi);

    BOOL DoContextMenu(HWND hwnd, LPSHELLFOLDER lpsfParent, LPITEMIDLIST lpi, POINT point);

    // These are here, for now anyway. They are called by the worker thread to do the work of encryption
    // or decryption of lists of pidls.
private:
    static DWORD Worker(WorkerThreadParam* pParam);
private:
    void WorkerDispatch(TWorkerFunctionPtr pWorkerFunction, HWND hWnd, LPSHELLFOLDER lpsfParent, LPITEMIDLIST lpi, POINT point);
private:
    DWORD WorkerEncrypt(WorkerThreadParam* pParam);
private:
    DWORD WorkerDecrypt(WorkerThreadParam* pParam);
};

#endif //CSHELLMGRWIN_H
