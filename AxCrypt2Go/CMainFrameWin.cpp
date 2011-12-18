/*! \file
    \brief CMainFrame.cpp - The Windows implementation of AxCrypt2Go

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

#include "stdafx.h"

//#include <shlobj.h>
//#include <shlguid.h>
//#include <ntquery.h>

//#include <atlframe.h>
//#include <atlsplit.h>
//#include <atlmisc.h>
//#include <atlctrls.h>
//#include <atlctrlw.h>
//#include <atlctrlx.h>

#include "AxCrypt2GoWin.h"
#include "CMainFrameWin.h"
#include "CDialogsWin.h"
#include "CConfigWin.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CMainFrameWin.cpp"

BOOL CMainFrame::FillListView(LPTVITEMDATA lptvid, LPSHELLFOLDER pShellFolder)
{
    ATLASSERT(pShellFolder != NULL);

    CComPtr<IEnumIDList> spEnumIDList;
    HRESULT hr = pShellFolder->EnumObjects(m_wndListView.GetParent(), SHCONTF_FOLDERS | SHCONTF_NONFOLDERS, &spEnumIDList);
    if (FAILED(hr)) {
        return FALSE;
    }

    CShellItemIDList lpifqThisItem;
    CShellItemIDList lpi;
    ULONG ulFetched = 0;
    UINT uFlags = 0;
    LVITEM lvi = { 0 };
    lvi.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    int iCtr = 0;

    while (spEnumIDList->Next(1, &lpi, &ulFetched) == S_OK)
    {
        // Get some memory for the ITEMDATA structure.
        LPLVITEMDATA lplvid = new LVITEMDATA;
        if (lplvid == NULL) {
            return FALSE;
        }

        lpifqThisItem = m_ShellMgr.ConcatPidls(lptvid->lpifq, lpi);

        lvi.iItem = iCtr;
        lvi.iSubItem = 0;
        lvi.pszText = LPSTR_TEXTCALLBACK;
        lvi.cchTextMax = MAX_PATH;
        uFlags = SHGFI_PIDL | SHGFI_SYSICONINDEX | SHGFI_SMALLICON;
        lvi.iImage = I_IMAGECALLBACK;

        lplvid->spParentFolder = pShellFolder;
        pShellFolder->AddRef();

        // Now make a copy of the ITEMIDLIST
        lplvid->lpi = m_ShellMgr.CopyITEMID(lpi);
        lplvid->lpifq = m_ShellMgr.ConcatPidls(lptvid->lpifq, lpi);

        lvi.lParam = (LPARAM)lplvid;

        // Add the item to the list view control
        int n = m_wndListView.InsertItem(&lvi);
        m_wndListView.AddItem(n, 1, LPSTR_TEXTCALLBACK, I_IMAGECALLBACK);
        m_wndListView.AddItem(n, 2, LPSTR_TEXTCALLBACK, I_IMAGECALLBACK);
        m_wndListView.AddItem(n, 3, LPSTR_TEXTCALLBACK, I_IMAGECALLBACK);
        m_wndListView.AddItem(n, 4, LPSTR_TEXTCALLBACK, I_IMAGECALLBACK);

        iCtr++;
        lpifqThisItem = NULL;
        lpi = NULL;   // free PIDL the shell gave you
    }

    SortData sd(m_nSort, m_bReverseSort);
    m_wndListView.SortItems(CMainFrame::ListViewCompareProc, (LPARAM)&sd);

    return TRUE;
}

int CALLBACK CMainFrame::ListViewCompareProc(LPARAM lparam1, LPARAM lparam2, LPARAM lParamSort)
{
    ATLASSERT(lParamSort != NULL);

    LPLVITEMDATA lplvid1 = (LPLVITEMDATA)lparam1;
    LPLVITEMDATA lplvid2 = (LPLVITEMDATA)lparam2;
    SortData* pSD = (SortData*)lParamSort;

    HRESULT hr = 0;
    if(pSD->bReverseSort)
        hr = lplvid1->spParentFolder->CompareIDs(0, lplvid2->lpi, lplvid1->lpi);
    else
        hr = lplvid1->spParentFolder->CompareIDs(0, lplvid1->lpi, lplvid2->lpi);

    return (int)(short)HRESULT_CODE(hr);
}

HRESULT CMainFrame::FillTreeView(IShellFolder* pShellFolder, LPITEMIDLIST lpifq, HTREEITEM hParent)
{
    if(pShellFolder == NULL)
        return E_POINTER;

    CComPtr<IEnumIDList> spIDList;
    HRESULT hr = pShellFolder->EnumObjects(m_hWnd, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS, &spIDList);
    if (FAILED(hr))
    {
        return hr;
    }

    CShellItemIDList lpi;
    CShellItemIDList lpifqThisItem;
    LPTVITEMDATA lptvid = NULL;
    ULONG ulFetched = 0;

    TCHAR szBuff[256] = { 0 };

    TVITEM tvi = { 0 };             // TreeView Item
    TVINSERTSTRUCT tvins = { 0 };   // TreeView Insert Struct
    HTREEITEM hPrev = NULL;         // Previous Item Added
    COMBOBOXEXITEM cbei = { 0 };

    // Hourglass on
    CWaitCursor wait;

    int iCnt = 0;
    while (spIDList->Next(1, &lpi, &ulFetched) == S_OK)
    {
        // Create a fully qualified path to the current item
        // The SH* shell api's take a fully qualified path pidl,
        // (see GetIcon above where I call SHGetFileInfo) whereas the
        // interface methods take a relative path pidl.
        // We're not checking for sub folders, because that may be a very time-consuming operation
        // for zip-archives etc. Note that there are items such as 'MSN' that may indicate they
        // have subfolers - but are not folders.
        // We use the SFGAO_STREAM to detect container objects such as zip-files - we do not want them to appear as folders here.
        ULONG ulAttrs = SFGAO_FOLDER|SFGAO_STREAM;
        pShellFolder->GetAttributesOf(1, (LPCITEMIDLIST*)&lpi, &ulAttrs);
        if ((ulAttrs & SFGAO_STREAM) != 0)
        {
            continue;
        }
        if ((ulAttrs & SFGAO_FOLDER) == 0)
        {
            continue;
        }

        // Now check if we have subfolders. This is very slow for zip-files for example, so be careful here -
        // there might be other cases that need filtering out before doing this.
        ulAttrs = SFGAO_HASSUBFOLDER;
        pShellFolder->GetAttributesOf(1, (LPCITEMIDLIST*)&lpi, &ulAttrs);

        tvi.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
        cbei.mask = CBEIF_TEXT | CBEIF_INDENT | CBEIF_IMAGE | CBEIF_SELECTEDIMAGE;

        // The first time the user clicks on the item, we'll populate the
        // sub-folders then.
        if ((ulAttrs & SFGAO_HASSUBFOLDER) != 0)
        {
            tvi.cChildren = 1;
            tvi.mask |= TVIF_CHILDREN;
        }

        // OK, let's get some memory for our ITEMDATA struct
        lptvid = new TVITEMDATA;
        if (lptvid == NULL)
        {
            return E_FAIL;
        }

        // Now get the friendly name that we'll put in the treeview...
        if (!m_ShellMgr.GetName(pShellFolder, lpi, SHGDN_NORMAL, szBuff, sizeof szBuff))
        {
            return E_FAIL;
        }

        tvi.pszText = szBuff;
        tvi.cchTextMax = MAX_PATH;

        cbei.pszText = szBuff;
        cbei.cchTextMax = MAX_PATH;

        lpifqThisItem = m_ShellMgr.ConcatPidls(lpifq, lpi);

        // Now, make a copy of the ITEMIDLIST
        lptvid->lpi = m_ShellMgr.CopyITEMID(lpi);

        m_ShellMgr.GetNormalAndSelectedIcons(lpifqThisItem, &tvi);

        lptvid->spParentFolder = pShellFolder;    // Store the parent folders SF
        pShellFolder->AddRef();

        lptvid->lpifq = m_ShellMgr.ConcatPidls(lpifq, lpi);

        tvi.lParam = (LPARAM)lptvid;

        tvins.item = tvi;
        tvins.hInsertAfter = hPrev;
        tvins.hParent = hParent;

        // Add the item to the tree and combo
        hPrev = TreeView_InsertItem(m_wndTreeView.m_hWnd, &tvins);
        cbei.iItem = iCnt++;    
        cbei.iImage = tvi.iImage;
        cbei.iSelectedImage = tvi.iSelectedImage;

        int nIndent = 0;
        while (NULL != (hPrev = (HTREEITEM)m_wndTreeView.SendMessage(TVM_GETNEXTITEM, TVGN_PARENT, (LPARAM)hPrev)))
        {
            nIndent++;
        }

        cbei.iIndent = nIndent;
        m_wndCombo.SendMessage(CBEM_INSERTITEM, 0, (LPARAM)&cbei);
    }

    return S_OK;
}

int CALLBACK CMainFrame::TreeViewCompareProc(LPARAM lparam1, LPARAM lparam2, LPARAM /*lparamSort*/)
{
    LPTVITEMDATA lptvid1 = (LPTVITEMDATA)lparam1;
    LPTVITEMDATA lptvid2 = (LPTVITEMDATA)lparam2;

    HRESULT hr = lptvid1->spParentFolder->CompareIDs(0, lptvid1->lpi, lptvid2->lpi);

    return (int)(short)HRESULT_CODE(hr);
}

HWND CMainFrame::CreateAddressBarCtrl(HWND hWndParent)
{
    RECT rc = { 50, 0, 300, 100 };
    m_wndCombo.Create(hWndParent, rc, NULL, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | CBS_DROPDOWN | CBS_AUTOHSCROLL);
    m_wndCombo.SetFont(AtlGetDefaultGuiFont());

    return m_wndCombo;
}

LRESULT CMainFrame::OnCreate(UINT, WPARAM, LPARAM, BOOL&)
{
    ASSAPI(SetWindowText(CConfig::ShortProductName().c_str()));
    
    // create command bar window
    RECT rcCmdBar = { 0, 0, 100, 100 };
    HWND hWndCmdBar = m_wndCmdBar.Create(m_hWnd, rcCmdBar, NULL, ATL_SIMPLE_CMDBAR_PANE_STYLE);
    // atach menu
    m_wndCmdBar.AttachMenu(GetMenu());
    // load command bar images
    m_wndCmdBar.LoadImages(IDR_MAINFRAME);
    // remove old menu
    SetMenu(NULL);

    HWND hWndToolBar = CreateSimpleToolBarCtrl(m_hWnd, IDR_MAINFRAME, FALSE, ATL_SIMPLE_TOOLBAR_PANE_STYLE);
    HWND hWndAddressBar = CreateAddressBarCtrl(m_hWnd);

    CreateSimpleReBar(ATL_SIMPLE_REBAR_NOBORDER_STYLE);

    AddSimpleReBarBand(hWndCmdBar);
    AddSimpleReBarBand(hWndToolBar, NULL, TRUE);
    // Need const_cast here, since the API for REBARBANDINFO uses the same parameter when getting band information, but
    // here we're only setting the title...
    AddSimpleReBarBand(hWndAddressBar, const_cast<LPTSTR>(_("ReBar|Address")), TRUE);

    CreateSimpleStatusBar();

    m_hWndClient = m_wndSplitter.Create(m_hWnd, rcDefault, NULL, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);

    m_wndFolderTree.Create(m_wndSplitter, _("FolderTree|Folders"), WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);
    
    m_wndTreeView.Create(m_wndFolderTree, rcDefault, NULL, 
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | 
        TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS, 
        WS_EX_CLIENTEDGE);

    m_wndFolderTree.SetClient(m_wndTreeView);

    m_wndListView.Create(m_wndSplitter, rcDefault, NULL, 
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | 
        LVS_REPORT | LVS_AUTOARRANGE | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS,
        WS_EX_CLIENTEDGE);
    m_wndListView.SetExtendedListViewStyle(LVS_EX_TRACKSELECT | LVS_EX_ONECLICKACTIVATE | LVS_EX_UNDERLINEHOT);
    
    InitViews();

    UpdateLayout();

    m_wndSplitter.SetSplitterPanes(m_wndFolderTree, m_wndListView);

    RECT rect;
    GetClientRect(&rect);
    m_wndSplitter.SetSplitterPos((rect.right - rect.left) / 4);

    UIAddToolBar(hWndToolBar);
    UISetCheck(ID_VIEW_TOOLBAR, 1);
    // Hide the address bar for now. Should probably be removed altogtether in the end
    BOOL bHandled = FALSE;
    (void)OnViewAddressBar(0, 0, NULL, bHandled);
    UISetCheck(ID_VIEW_STATUS_BAR, 1);
    UISetCheck(ID_VIEW_DETAILS, 1);
    UISetCheck(ID_VIEW_SORT_NAME, 1);

    CMessageLoop* pLoop = _Module.GetMessageLoop();
    pLoop->AddMessageFilter(this);
    pLoop->AddIdleHandler(this);

    ASSCHK(SetTimer(m_TimerIndex, m_RefreshTimerInterval, NULL) != 0, _T("SetTimer() failed"));

    return 0;
}

void CMainFrame::OnDestroy() {
    ASSCHK(KillTimer(m_TimerIndex), _T("KillTimer() failed"));

    if (m_hChangeNotification != INVALID_HANDLE_VALUE) {
        ASSAPI(CloseHandle(m_hChangeNotification));
        m_hChangeNotification = INVALID_HANDLE_VALUE;
    }
    SetMsgHandled(false);
}


LRESULT CMainFrame::OnViewChange(WORD, WORD wID, HWND, BOOL&)
{
    UISetCheck(ID_VIEW_ICONS, FALSE);
    UISetCheck(ID_VIEW_SMALL_ICONS, FALSE);
    UISetCheck(ID_VIEW_LIST, FALSE);
    UISetCheck(ID_VIEW_DETAILS, FALSE);
    UISetCheck(wID, TRUE);
    DWORD dwNewStyle = 0;
    switch (wID) {
        case ID_VIEW_ICONS:
            dwNewStyle = LVS_ICON;
            break;
        case ID_VIEW_SMALL_ICONS:
            dwNewStyle = LVS_SMALLICON;
            break;
        case ID_VIEW_LIST:
            dwNewStyle = LVS_LIST;
            break;
        case ID_VIEW_DETAILS:
            dwNewStyle = LVS_REPORT;
            break;
        default:
            ASSCHK(false, _T("Unexpected viewstyle"));
    }
    m_wndListView.SetViewType(dwNewStyle);

    return 0;
}

LRESULT CMainFrame::OnComboGo(WORD, WORD, HWND, BOOL&)
{
//  TCHAR szBuff[MAX_PATH] = { 0 };
//  m_wndCombo.GetWindowText(szBuff, MAX_PATH);
//      
//  m_wndTreeView.SelectItem(NULL);
    //m_wndCombo.SetEditSel(0, -1);
    //FillListView(m_wndListView, szBuff);

    MessageBox(_T("Not yet implemented!"), CConfig::ShortProductName().c_str(), MB_OK | MB_ICONINFORMATION);

    return 0;
}

void CMainFrame::ListViewRefresh() {
    HTREEITEM hti = m_wndTreeView.GetSelectedItem();
    LPTVITEMDATA lptvid = (LPTVITEMDATA)m_wndTreeView.GetItemData(hti);

    if (lptvid != NULL) {
        CComPtr<IShellFolder> spFolder;
        HRESULT hr = lptvid->spParentFolder->BindToObject(lptvid->lpi, 0, IID_IShellFolder, (LPVOID *)&spFolder);
        ASSCOM(hr);
        
        if (m_wndListView.GetItemCount() > 0) {
            m_wndListView.DeleteAllItems();
        }

        // Don't redraw the window during the update
        m_wndListView.SetRedraw(FALSE);
        FillListView(lptvid, spFolder);
        m_wndListView.SetRedraw(TRUE);

        // Get the name of the folder, and setup a watch so we know if we should update or not. Some shell extensions
        // will return immediately, but actually do their work in a separate window/process. In this case we'll miss the
        // event the way this code is written now. Probably, we should set up the watcher outside of this, and let it
        // work independently in a different thread.
        {
            TCHAR szFolder[MAX_PATH];
            if (m_ShellMgr.GetName(lptvid->spParentFolder, lptvid->lpi, SHGDN_FORPARSING, szFolder, sizeof szFolder)) {
                if (m_hChangeNotification != INVALID_HANDLE_VALUE) {
                    ASSAPI(CloseHandle(m_hChangeNotification));
                }
                m_hChangeNotification = FindFirstChangeNotification(szFolder, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_DIR_NAME|FILE_NOTIFY_CHANGE_ATTRIBUTES|FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE|FILE_NOTIFY_CHANGE_SECURITY);
                // We don't really care if we failed to set a watcher, since it depends on what we're viewing - some things are not
                // possible to set a watcher on, so then we just don't...
                //ASSAPI(m_hChangeNotification != INVALID_HANDLE_VALUE);
            }
        }
    }
}

LRESULT CMainFrame::OnViewRefresh(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
    ListViewRefresh();
    return 0;
}

LRESULT CMainFrame::OnViewSort(WORD, WORD wID, HWND, BOOL&)
{
    UISetCheck(ID_VIEW_SORT_NAME, FALSE);
    UISetCheck(ID_VIEW_SORT_SIZE, FALSE);
    UISetCheck(ID_VIEW_SORT_TYPE, FALSE);
    UISetCheck(ID_VIEW_SORT_TIME, FALSE);
    UISetCheck(ID_VIEW_SORT_ATTR, FALSE);
    UISetCheck(wID, TRUE);
    m_bReverseSort = false;
    switch (wID) {
        case ID_VIEW_SORT_NAME:
            m_nSort = 0;
            break;
        case ID_VIEW_SORT_SIZE:
            m_nSort = 1;
            break;
        case ID_VIEW_SORT_TYPE:
            m_nSort = 2;
            break;
        case ID_VIEW_SORT_TIME:
            m_nSort = 3;
            break;
        case ID_VIEW_SORT_ATTR:
            m_nSort = 4;
            break;
        default:
            ASSCHK(false, _T("Unexpected sort order"));
    }
    SortData sd(m_nSort, m_bReverseSort);
    m_wndListView.SortItems(CMainFrame::ListViewCompareProc, (LPARAM)&sd);

    return 0;
}

LRESULT CMainFrame::OnTVSelChanged(int, LPNMHDR pnmh, BOOL&)
{
    LPNMTREEVIEW lpTV = (LPNMTREEVIEW)pnmh;
    LPTVITEMDATA lptvid = (LPTVITEMDATA)lpTV->itemNew.lParam;

    if (lptvid != NULL) {
        CComPtr<IShellFolder> spFolder;
        HRESULT hr = lptvid->spParentFolder->BindToObject(lptvid->lpi, 0, IID_IShellFolder, (LPVOID *)&spFolder);
        if (FAILED(hr)) {
            return hr;
        }

        //if(m_wndListView.GetItemCount() > 0)
        //    m_wndListView.DeleteAllItems();
        //FillListView(lptvid, spFolder);
        ListViewRefresh();
        
        TCHAR psz[MAX_PATH] = { 0 };
        m_ShellMgr.GetName(lptvid->spParentFolder, lptvid->lpi, SHGDN_FORPARSING, psz, sizeof psz);
        
        if (StrChr(psz, _T('{'))) {   //special case
            m_ShellMgr.GetName(lptvid->spParentFolder, lptvid->lpi, SHGDN_NORMAL, psz, sizeof psz);
        }
    
        int nImage = 0;
        int nSelectedImage = 0;
        m_wndTreeView.GetItemImage(lpTV->itemNew.hItem, nImage, nSelectedImage);
        COMBOBOXEXITEM cbei;
        cbei.mask = CBEIF_TEXT | CBEIF_INDENT |CBEIF_IMAGE| CBEIF_SELECTEDIMAGE;
        cbei.iItem = -1; //Editbox of the comboboxex
        cbei.pszText = psz;
        cbei.cchTextMax = MAX_PATH;
        if (m_wndTreeView.ItemHasChildren(lpTV->itemNew.hItem)) {
            cbei.iImage = nImage;
            cbei.iSelectedImage = nImage;
        } else {
            cbei.iImage = nSelectedImage;
            cbei.iSelectedImage = nSelectedImage;
        }
        cbei.iIndent = 1;
        
        m_wndCombo.SetItem(&cbei);
        
    }

    return 0L;
}

LRESULT CMainFrame::OnTVItemExpanding(int, LPNMHDR pnmh, BOOL&)
{
    CWaitCursor wait;
    LPNMTREEVIEW pnmtv = (LPNMTREEVIEW)pnmh;
    if ((pnmtv->itemNew.state & TVIS_EXPANDEDONCE)) {
         return 0L;
    }

    LPTVITEMDATA lptvid = (LPTVITEMDATA)pnmtv->itemNew.lParam;
    
    CComPtr<IShellFolder> spFolder;
    HRESULT hr=lptvid->spParentFolder->BindToObject(lptvid->lpi, 0, IID_IShellFolder, (LPVOID *)&spFolder);
    if (FAILED(hr)) {
        return hr;
    }
    
    // Don't redraw the window during the update
    m_wndTreeView.SetRedraw(FALSE);
    FillTreeView(spFolder, lptvid->lpifq, pnmtv->itemNew.hItem);
    m_wndTreeView.SetRedraw(TRUE);
    
    TVSORTCB tvscb;
    tvscb.hParent = pnmtv->itemNew.hItem;
    tvscb.lpfnCompare = CMainFrame::TreeViewCompareProc;
    tvscb.lParam = 0;

    TreeView_SortChildrenCB(m_wndTreeView.m_hWnd, &tvscb, 0);
    
    return 0L;

}

LRESULT CMainFrame::OnTVDeleteItem(int, LPNMHDR pnmh, BOOL&)
{
    LPNMTREEVIEW pnmtv = (LPNMTREEVIEW)pnmh;
    LPTVITEMDATA lptvid = (LPTVITEMDATA)pnmtv->itemOld.lParam;
    delete lptvid;

    return 0;
}

LRESULT CMainFrame::OnLVGetDispInfo(int, LPNMHDR pnmh, BOOL&)
{
    NMLVDISPINFO* plvdi = (NMLVDISPINFO*)pnmh;
    if(plvdi == NULL)
        return 0L;

    LPLVITEMDATA lplvid = (LPLVITEMDATA)plvdi->item.lParam;

    HTREEITEM hti = m_wndTreeView.GetSelectedItem();
    TVITEM tvi = { 0 };
    tvi.mask = TVIF_PARAM;
    tvi.hItem = hti;

    m_wndTreeView.GetItem(&tvi);
    if (tvi.lParam <= 0) {
        return 0L;
    }

    LPTVITEMDATA lptvid = (LPTVITEMDATA)tvi.lParam;
    if (lptvid == NULL) {
        return 0L;
    }
    
    if (plvdi->item.mask & LVIF_IMAGE) {
        plvdi->item.iImage = m_MyImageListSmall.GetIconIndex(CShellItemIDList(m_ShellMgr.ConcatPidls(lptvid->lpifq, lplvid->lpi)), SHGFI_ICON | SHGFI_PIDL | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
        //plvdi->item.iImage = m_ShellMgr.GetIconIndex(CShellItemIDList(m_ShellMgr.ConcatPidls(lptvid->lpifq, lplvid->lpi)), SHGFI_PIDL | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    }

    // If we're looking for the file name and icon
    if (plvdi->item.iSubItem == 0 && (plvdi->item.mask & LVIF_TEXT)) {
        m_ShellMgr.GetName(lplvid->spParentFolder, lplvid->lpi, SHGDN_NORMAL, plvdi->item.pszText, plvdi->item.cchTextMax * sizeof plvdi->item.pszText[0]);

        if (plvdi->item.mask & LVIF_IMAGE) {
            // If the name represents and encrypted file, we change the icon. (The system assigns an icon to unknown files too.)
            if (CConfigWin::IsEncryptedFileName(plvdi->item.pszText)) {
                plvdi->item.iImage = m_MyImageListSmall.GetAxCryptIconIndex();
            }
        }
    } else if (plvdi->item.mask & LVIF_TEXT) {
        // ...we want additional info, like size, type, date modified
        CComPtr<IShellFolder2> spFolder2;
        HRESULT hr = lptvid->spParentFolder->QueryInterface(IID_IShellFolder2, (void**)&spFolder2);
        if (FAILED(hr)) {
            return hr;
        }

        SHELLDETAILS sd = { 0 };
        sd.fmt = LVCFMT_CENTER;
        sd.cxChar = 15;
        
        // The interface uses hardcoded indices for the size, type and date modified info - which just happen
        // to correspond to our listview subitem indices. So here we simply get the text associated with
        // the appropriate column.
        hr = spFolder2->GetDetailsOf(lplvid->lpi, plvdi->item.iSubItem, &sd);
        if (FAILED(hr)) {
            return hr;
        }

        // Now do the conversion dance depending on what is returned...
        if(sd.str.uType == STRRET_WSTR) {
            StrRetToBuf(&sd.str, lplvid->lpi.m_pidl, m_szListViewBuffer, MAX_PATH);
            plvdi->item.pszText=m_szListViewBuffer;
        } else if(sd.str.uType == STRRET_OFFSET) {
            plvdi->item.pszText = (LPTSTR)lptvid->lpi + sd.str.uOffset;
        } else if(sd.str.uType == STRRET_CSTR) {
            USES_CONVERSION;
            plvdi->item.pszText = A2T(sd.str.cStr);
        }
    }
    
    plvdi->item.mask |= LVIF_DI_SETITEM;

    return 0L;
}

LRESULT CMainFrame::OnLVColumnClick(int /*idCtrl*/, LPNMHDR pnmh, BOOL& /*bHandled*/)
{
    LPNMLISTVIEW lpLV = (LPNMLISTVIEW)pnmh;
    if(m_nSort == lpLV->iSubItem)
        m_bReverseSort = !m_bReverseSort;
    else
        m_nSort = lpLV->iSubItem;
    ATLASSERT(m_nSort >= 0 && m_nSort <= 4);
    SortData sd(m_nSort, m_bReverseSort);
    m_wndListView.SortItems(CMainFrame::ListViewCompareProc, (LPARAM)&sd);

    return 0;
}

LRESULT CMainFrame::OnNMRClick(int, LPNMHDR pnmh, BOOL&)
{
    POINT pt = { 0, 0 };
    ::GetCursorPos(&pt);
    POINT ptClient = pt;
    if(pnmh->hwndFrom != NULL)
        ::ScreenToClient(pnmh->hwndFrom, &ptClient);
    
    if(pnmh->hwndFrom == m_wndTreeView.m_hWnd)
    {
        TVHITTESTINFO tvhti = { 0 };
        tvhti.pt = ptClient;
        m_wndTreeView.HitTest(&tvhti);
        if ((tvhti.flags & TVHT_ONITEMLABEL) != 0)
        {
            TVITEM tvi = { 0 };
            tvi.mask = TVIF_PARAM;
            tvi.hItem = tvhti.hItem;
            if (m_wndTreeView.GetItem(&tvi) != FALSE)
            {
                LPTVITEMDATA lptvid = (LPTVITEMDATA)tvi.lParam;
                if (lptvid != NULL)
                    m_ShellMgr.DoContextMenu(m_hWnd, lptvid->spParentFolder, lptvid->lpi, pt);
            }
        }
    }
    else if(pnmh->hwndFrom == m_wndListView.m_hWnd)
    {
        LVHITTESTINFO lvhti = { 0 };
        lvhti.pt = ptClient;
        m_wndListView.HitTest(&lvhti);
        if ((lvhti.flags & LVHT_ONITEMLABEL) != 0)
        {
            LVITEM lvi = { 0 };
            lvi.mask = LVIF_PARAM;
            lvi.iItem = lvhti.iItem;
            if (m_wndListView.GetItem(&lvi) != FALSE)
            {
                LPLVITEMDATA lptvid = (LPLVITEMDATA)lvi.lParam;
                if (lptvid != NULL)
                    m_ShellMgr.DoContextMenu(m_hWnd, lptvid->spParentFolder, lptvid->lpi, pt);
            }
        }
    }

    return 0L;
}

LRESULT CMainFrame::OnLVItemClick(int, LPNMHDR pnmh, BOOL&)
{
    if (pnmh->hwndFrom != m_wndListView.m_hWnd) {
        return 0L;
    }

    POINT pt;
    ::GetCursorPos((LPPOINT)&pt);
    m_wndListView.ScreenToClient(&pt);

    LVHITTESTINFO lvhti;
    lvhti.pt = pt;
    m_wndListView.HitTest(&lvhti);
    LVITEM lvi;

    if (lvhti.flags & LVHT_ONITEM) {
        m_wndListView.ClientToScreen(&pt);
        lvi.mask = LVIF_PARAM;
        lvi.iItem = lvhti.iItem;
        lvi.iSubItem = 0;

        if (!m_wndListView.GetItem(&lvi)) {
            return 0;
        }

        LPLVITEMDATA lplvid = (LPLVITEMDATA)lvi.lParam;

        if (lplvid == NULL) {
            return 0L;
        }
        // Since you are interested in the display attributes as well as other attributes, 
        // you need to set ulAttrs to SFGAO_DISPLAYATTRMASK before calling GetAttributesOf()
        ULONG ulAttribs = SFGAO_DISPLAYATTRMASK;
        HRESULT hr = lplvid->spParentFolder->GetAttributesOf(1, (const struct _ITEMIDLIST **)&lplvid->lpi, &ulAttribs);
        if (FAILED(hr)) {
            return 0;
        }

        // If we did not click on a folder, lets do the default thing.
        if (!(ulAttribs & SFGAO_FOLDER)) {
            HRESULT hr;
            CComPtr<IContextMenu> spContextMenu;
            HWND hWnd = ::GetParent(m_wndListView.m_hWnd);

            hr = lplvid->spParentFolder->GetUIObjectOf(hWnd, 1, const_cast<LPCITEMIDLIST *>(&lplvid->lpi), IID_IContextMenu, 0, reinterpret_cast<void **>(&spContextMenu));
            ASSCOM(hr);

            // We must give QueryContextMenu a HMENU to work on for CMF_DEFAULTONLY to work.
            HMENU hMenuPopup;
            hMenuPopup = ::CreatePopupMenu();
            hr = spContextMenu->QueryContextMenu(hMenuPopup, 0, 0, 0x7fff, CMF_DEFAULTONLY);
            ASSCOM(hr);

            // Useful for debugging.
            int nextId;
            nextId = HRESULT_CODE(hr);
            nextId;

            UINT defaultId;
            defaultId = ::GetMenuDefaultItem(hMenuPopup, FALSE, 0);
            if (defaultId == (UINT)-1) {
                // If we didn't get a default action, just do nothing.
                return 0;
            }

            // Now invoke the default command by Id - which works in XP as well as Vista
            CMINVOKECOMMANDINFO cmi = { 0 };
            cmi.cbSize = sizeof cmi;
            cmi.lpVerb = MAKEINTRESOURCEA(defaultId);
            cmi.nShow = SW_SHOWNORMAL;
            hr = spContextMenu->InvokeCommand(reinterpret_cast<CMINVOKECOMMANDINFO *>(&cmi));
            ASSCOM(hr);

            //// Something like this is what we would have wanted to do - but InvokeCommand with lpVerb (or lpVerbW)
            //// set to a string seems to be hosed in Windows Vista (works fine in XP). ShellExecuteEx will indirectly
            //// to InvokeCommand, and appears to fail in the same as when we try to use InvokeCOmmand with a string
            //// verb (returns ok - nothing happens). So instead we do the above manual stuff to get hold of the default
            //// action from the shell context handers to handle double-click.
            //SHELLEXECUTEINFO sei =
            //{
            //    sizeof(SHELLEXECUTEINFO),
            //    SEE_MASK_INVOKEIDLIST,               // fMask
            //    ::GetParent(m_wndListView.m_hWnd),   // hwnd of parent
            //    _T("open"),                          // lpVerb
            //    NULL,                                // lpFile
            //    NULL,  
            //    NULL,                                // lpDirectory
            //    SW_SHOWNORMAL,                       // nShow
            //    0,                                   // hInstApp
            //    (LPVOID)NULL,                        // lpIDList...will set below
            //    NULL,                                // lpClass
            //    0,                                   // hkeyClass
            //    0,                                   // dwHotKey
            //    NULL                                 // hIcon
            //};
            //BOOL bResult;
            //sei.lpIDList = m_ShellMgr.GetFullyQualPidl(lplvid->spParentFolder, lplvid->lpi);
            //bResult = ::ShellExecuteEx(&sei);
            //bResult;
            //MessageBox(_T("Nothing happens"));
        } else {
            // Recursively descend, expand and finally select in the treeview.
            SelectFolder(m_wndTreeView.GetSelectedItem(), lplvid->lpifq);
        }
    }

    return 0L;
}

bool
CMainFrame::SelectFolder(CTreeItem treeItem, LPITEMIDLIST lpItemIdList) {
    if (treeItem.IsNull()) {
        return true;
    }
    for (;;) {
        LPTVITEMDATA lptvid;
        lptvid = (LPTVITEMDATA)treeItem.GetData();
        if (ILIsEqual(lptvid->lpifq, lpItemIdList)) {
            treeItem.Select();
            return true;
        }
        if (ILIsParent(lptvid->lpifq, lpItemIdList, FALSE)) {
            treeItem.Expand();
            SelectFolder(treeItem.GetChild(), lpItemIdList);
            return true;
        }
        treeItem = treeItem.GetNextSibling();
        if (treeItem.IsNull()) {
            return false;
        }
    }
}

LRESULT CMainFrame::OnLVDeleteItem(int /*idCtrl*/, LPNMHDR pnmh, BOOL& /*bHandled*/)
{
    LPNMLISTVIEW pnmlv = (LPNMLISTVIEW)pnmh;

    LVITEM lvi;
    lvi.mask = LVIF_PARAM;
    lvi.iItem = pnmlv->iItem;
    lvi.iSubItem = 0;

    if (!m_wndListView.GetItem(&lvi))
        return 0;

    LPLVITEMDATA lplvid = (LPLVITEMDATA)lvi.lParam;
    delete lplvid;

    return 0;
}

LRESULT CMainFrame::OnFileExit(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    PostMessage(WM_CLOSE);
    return 0;
}

LRESULT CMainFrame::OnFileNew(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    // TODO: add code to initialize document

    return 0;
}

LRESULT CMainFrame::OnFileNewWindow(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    ::PostThreadMessage(_Module.m_dwMainThreadID, WM_USER, 0, 0L);
    return 0;
}

LRESULT CMainFrame::OnViewToolBar(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    static BOOL bNew = TRUE;    // initially visible
    bNew = !bNew;
    ::SendMessage(m_hWndToolBar, RB_SHOWBAND, 1, bNew); // toolbar is band #1
    UISetCheck(ID_VIEW_TOOLBAR, bNew);
    UpdateLayout();
    return 0;
}

LRESULT CMainFrame::OnViewAddressBar(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    static BOOL bNew = TRUE;    // initially visible
    bNew = !bNew;
    ::SendMessage(m_hWndToolBar, RB_SHOWBAND, 2, bNew); // address bar is band #2
    UISetCheck(ID_VIEW_ADDRESS_BAR, bNew);
    UpdateLayout();
    return 0;
}

LRESULT CMainFrame::OnViewStatusBar(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    BOOL bNew = !::IsWindowVisible(m_hWndStatusBar);
    ::ShowWindow(m_hWndStatusBar, bNew ? SW_SHOWNOACTIVATE : SW_HIDE);
    UISetCheck(ID_VIEW_STATUS_BAR, bNew);
    UpdateLayout();
    return 0;
}

LRESULT CMainFrame::OnAppAbout(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    CAboutDlg dlgAbout;
    dlgAbout.DoModal();
    return 0;
}

/// \brief Start a worker thread
LRESULT
CMainFrame::OnWorkerThread(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM lParam, BOOL& /*bHandled*/)
{
    // Setup a progress-dialog - this is best done here, since we want the progress dialog window to be
    // handled by our main message loop in the main thread. The worker thread does not have a message loop.
    WorkerThreadParam* pThreadParam = reinterpret_cast<WorkerThreadParam*>(lParam);
    pThreadParam->m_DlgProgress.Create(m_hWnd);
    CProgressBarCtrl wndProgress = pThreadParam->m_DlgProgress.GetDlgItem(IDC_PROGRESS);
    wndProgress.SetRange(0, 100);

    ::PostThreadMessage(_Module.m_dwMainThreadID, WM_USER_WORKERTHREAD, 0, lParam);
    return 0;
}

/// \brief Destroy a progress window
LRESULT
CMainFrame::OnDestroyProgress(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM lParam, BOOL& /*bHandled*/)
{
    // The progress window must be destroyed by the same thread that created it, that's why we're here
    WorkerThreadParam* pThreadParam = reinterpret_cast<WorkerThreadParam*>(lParam);
    ASSAPI(pThreadParam->m_DlgProgress.DestroyWindow());

    return 0;
}

/// \brief The timer has expired, check for changes and if any, call the appropriate thing and restart the timer.
void CMainFrame::OnTimer(UINT_PTR wParam) {
    if (wParam == m_TimerIndex) {
        if (m_hChangeNotification != INVALID_HANDLE_VALUE) {
            if (WaitForSingleObject(m_hChangeNotification, 0) == WAIT_OBJECT_0) {
                SendMessage(WM_USER_CHANGENOTIFICATION, 0, 0);
            }
        }
        ASSCHK(SetTimer(m_TimerIndex, m_RefreshTimerInterval, NULL) != 0, _T("SetTimer() failed"));
    }
}

/// \brief Send a message here, indicating that something has changed in the list view folder
///
/// The idea is that a timer is running, checking a FindFirstChangeNotification handle for changes whenever
/// it expires. If there are any changes, we'll uppdate the view in as good a manner as possible
LRESULT
CMainFrame::OnChangeNotification(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
    // Only do updates when there's no worker thread active
    if (!_Module.IsWorkerActive()) {
        ListViewRefresh();
    }
    return 0;
}

void CMainFrame::InitViews()
{
    // Get Desktop folder
    CShellItemIDList spidl;
    HRESULT hRet = ::SHGetSpecialFolderLocation(m_hWnd, CSIDL_DESKTOP, &spidl);
    hRet;   // avoid level 4 warning
    ATLASSERT(SUCCEEDED(hRet));

    // Get system image lists
    SHFILEINFO sfi = { 0 };
    HIMAGELIST hImageList = (HIMAGELIST)::SHGetFileInfo(spidl, 0, &sfi, sizeof(sfi), SHGFI_PIDL | SHGFI_SYSICONINDEX | SHGFI_ICON);
    ATLASSERT(hImageList != NULL);

    memset(&sfi, 0, sizeof(SHFILEINFO));
    HIMAGELIST hImageListSmall = (HIMAGELIST)::SHGetFileInfo(spidl, 0, &sfi, sizeof(sfi), SHGFI_PIDL | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    ATLASSERT(hImageListSmall != NULL);

    // Set address bar combo box image list
    m_wndCombo.SetImageList(hImageListSmall);

    // Set tree view image list
    m_wndTreeView.SetImageList(hImageListSmall, 0);

    // Create list view columns
    m_wndListView.InsertColumn(0, _("ListView|Column|Name"), LVCFMT_LEFT, 200, 0);
    m_wndListView.InsertColumn(1, _("ListView|Column|Size"), LVCFMT_RIGHT, 100, 1);
    m_wndListView.InsertColumn(2, _("ListView|Column|Type"), LVCFMT_LEFT, 100, 2);
    m_wndListView.InsertColumn(3, _("ListView|Column|Modified"), LVCFMT_LEFT, 100, 3);
    m_wndListView.InsertColumn(4, _("ListView|Column|Attributes"), LVCFMT_RIGHT, 100, 4);

    // Set list view image lists
    m_wndListView.SetImageList(hImageList, LVSIL_NORMAL);

    m_MyImageListSmall.Init(hImageListSmall);
    m_wndListView.SetImageList(m_MyImageListSmall.GetImageList(), LVSIL_SMALL);
}
