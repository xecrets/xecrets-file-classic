#ifndef CMAINFRAME_H
#define CMAINFRAME_H
/*! \file
	\brief MainFrm.h - The Windows implementation of XecretsFile2Go

	This code builds heavily on the sample code distributed with Windows Template Library,
	which does not name any contributor or author, nor specify any kind of restrictions of
	use. Whilst this particular file is in this form licensed under GNU GPL as per below,
	this is not an attempt to claim authorship of that original code. The intention is only
	to protect the modified work as it is published here.

	@(#) $Id$

	XecretsFile2Go - Stand-Alone Install-free Xecrets File for the road.

	Copyright (C) 2005-2022 Svante Seleborg/Axantum Software AB, All rights reserved.

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-08-06              Initial
\endverbatim
*/

#include "resource.h"

#include "XecretsFile2GoWin.h"
#include "CExplorerComboWin.h"
#include "CShellMgrWin.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CMainFrame.h"

/// \brief The application container class
class CMyAppModule : public CAppModule {
	typedef CAppModule base;
private:
	LONG volatile m_nWorkerCount;           ///< Number of active worker threads

public:
	CMyAppModule() : base() {
		m_nWorkerCount = 0;
	}

public:
	/// \brief true if there's a worker active.
	/// The idea is that for example view updates may not be performed when there's a worker
	/// thread active, there may be other uses of this too.
	bool IsWorkerActive() {
		bool fWorkerActive = ::InterlockedDecrement(&m_nWorkerCount) >= 0;
		::InterlockedIncrement(&m_nWorkerCount);
		return fWorkerActive;
	}

public:
	/// \brief Call as you start another worker thread
	void AddWorker() {
		::InterlockedIncrement(&m_nWorkerCount);
	}

public:
	/// \brief Call as you're exiting a worker thread
	void SubWorker() {
		::InterlockedDecrement(&m_nWorkerCount);
	}
};

extern CMyAppModule _Module;

/// \brief Wrap the system icon-list slightly to allow special handling of the Xecrets File icon
class CMyImageList {
private:
	/// \brief This maps System Image List indices to our private indices.
	/// When we look for an icon, we look it up in the
	/// system icon list. If we find it there, we check to see if that index is a key in this map. If so, we use
	/// that index instead. If the index is not a key in the map, it's the first time we see this icon - then we
	/// copy the icon to our image list, update the map and use our index instead.
	std::map<int, int> mapSystemToMy;

	HIMAGELIST m_hMyImageList;              ///< Our cloned copy of the image list
	HIMAGELIST m_hSystemImageList;          ///< The base system image list

public:
	CMyImageList() : m_hMyImageList(NULL) {
	}

public:
	/// \brief Dupliate the image-list and get the Xecrets File-icon
	void Init(HIMAGELIST hSystemImageList) {
		// This is complicated. We need to make a clone of the system image list, and then provide
		// a map between our indices and the 'real' indices. We start by duplicating the current
		// image list.
		int n = ::ImageList_GetImageCount(hSystemImageList);
		m_hMyImageList = ::ImageList_Duplicate(hSystemImageList);

		// Create the initial identity-mapping for the just-duplicated image list
		for (int i = 0; i < n; i++) {
			mapSystemToMy[i] = i;
		}

		// Get the dimensions of the icon in the system image-list, so we can get the same for the Xecrets File icon
		int cx, cy;
		ASSCHK(::ImageList_GetIconSize(m_hMyImageList, &cx, &cy) == TRUE, _T("ImageList_GetIconSize()"));

		// get the Xecrets File icon from our loaded module
		HICON hAxCryptIcon = (HICON)::LoadImage(_Module.GetModuleInstance(), MAKEINTRESOURCE(IDR_MAINFRAME), IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR);
		ASSAPI(hAxCryptIcon != NULL);

		int nXecretsFile2GoIconIndex = ::ImageList_ReplaceIcon(m_hMyImageList, -1, hAxCryptIcon);
		ASSCHK(nXecretsFile2GoIconIndex == n, _T("ImageList_ReplaceIcon() failed"));
		ASSAPI(::DestroyIcon(hAxCryptIcon));

		// Finally, insert the dummy-mapping of -1 to our index for the Xecrets File icon
		mapSystemToMy[-1] = nXecretsFile2GoIconIndex;
	}

public:
	~CMyImageList() {
		if (m_hMyImageList != NULL) {
			ASSCHK(::ImageList_Destroy(m_hMyImageList) == TRUE, _T("ImageList_Destroy()"));
			m_hMyImageList = NULL;
		}
	}

public:
	HIMAGELIST GetImageList() {
		return m_hMyImageList;
	}

public:
	int
		GetIconIndex(const CShellItemIDList& pidl, UINT uFlags) {
		// Find the system-assigned icon, move it into our own image list if it's new and remember its position for future reference
		SHFILEINFO sfi = { 0 };
		DWORD_PTR dwRet = ::SHGetFileInfo((LPCTSTR)pidl, 0, &sfi, sizeof sfi, uFlags);

		// If we found an icon in the system icon list
		if (dwRet != 0) {
			std::map<int, int>::const_iterator it = mapSystemToMy.find(sfi.iIcon);
			if (it != mapSystemToMy.end()) {
				return it->second;
			}
			else {
				int i = ::ImageList_ReplaceIcon(m_hMyImageList, -1, sfi.hIcon);
				ASSCHK(i != -1, _T("ImageList_ReplaceIcon()"));

				return mapSystemToMy[sfi.iIcon] = i;
			}
		}
		else {
			// This is probably more or less an error situation. Still...
			return -1;
		}
	}

public:
	int
		GetAxCryptIconIndex() {
		return mapSystemToMy.find(-1)->second;
	}
};

class CMyPaneContainer : public CPaneContainerImpl<CMyPaneContainer>
{
public:
	DECLARE_WND_CLASS_EX(_T("WtlExplorer_PaneContainer"), 0, -1)

	void DrawPaneTitle(CDCHandle dc)
	{
		RECT rect = { 0 };
		GetClientRect(&rect);

		if (IsVertical())
		{
			rect.right = rect.left + m_cxyHeader;
			dc.DrawEdge(&rect, EDGE_ETCHED, BF_LEFT | BF_TOP | BF_BOTTOM | BF_ADJUST);
			dc.FillRect(&rect, COLOR_3DFACE);
		}
		else
		{
			rect.bottom = rect.top + m_cxyHeader;
			// we don't want this edge
			//			dc.DrawEdge(&rect, EDGE_ETCHED, BF_LEFT | BF_TOP | BF_RIGHT | BF_ADJUST);
			dc.FillRect(&rect, COLOR_3DFACE);
			// draw title only for horizontal pane container
			dc.SetTextColor(::GetSysColor(COLOR_WINDOWTEXT));
			dc.SetBkMode(TRANSPARENT);
			HFONT hFontOld = dc.SelectFont(GetTitleFont());
			rect.left += m_cxyTextOffset;
			rect.right -= m_cxyTextOffset;
			if (m_tb.m_hWnd != NULL)
				rect.right -= m_cxToolBar;;
#ifndef _WIN32_WCE
			dc.DrawText(m_szTitle, -1, &rect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
#else // CE specific
			dc.DrawText(m_szTitle, -1, &rect, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
#endif //_WIN32_WCE
			dc.SelectFont(hFontOld);
		}
	}
};

class CMainFrame :
	public CFrameWindowImpl<CMainFrame>,
	public CUpdateUI<CMainFrame>,
	public CMessageFilter,
	public CIdleHandler
{
private:
	struct SortData
	{
		SortData(int nSortNum, bool bReverse) : nSort(nSortNum), bReverseSort(bReverse)
		{ }

		int nSort;
		bool bReverseSort;
	};

	CCommandBarCtrl m_wndCmdBar;
	CSplitterWindow m_wndSplitter;
	///	CPaneContainer m_wndFolderTree;
	CMyPaneContainer m_wndFolderTree;
	CTreeViewCtrlEx m_wndTreeView;
	CListViewCtrl m_wndListView;
	CExplorerCombo m_wndCombo;

	CShellMgr m_ShellMgr;

	CMyImageList m_MyImageListSmall;

	int m_nSort;
	bool m_bReverseSort;

	bool m_bFirstIdle;

	// Buffer for OnLVGetDispInfo
	TCHAR m_szListViewBuffer[MAX_PATH];

private:
	/// \brief Each timer in Window has an index, this is the one we use here
	static const int m_TimerIndex = 1;

	/// \brief The interval for list-view refresh, in milliseconds.
	static const int m_RefreshTimerInterval = 1000;

	bool SelectFolder(CTreeItem treeItem, LPITEMIDLIST lpItemIdList);

	HANDLE m_hChangeNotification;
public:
	DECLARE_FRAME_WND_CLASS(CConfig::InternalName().c_str(), IDR_MAINFRAME)

	CMainFrame() : m_nSort(0), m_bReverseSort(false), m_bFirstIdle(true) {
		m_hChangeNotification = INVALID_HANDLE_VALUE;
	}

	virtual BOOL PreTranslateMessage(MSG* pMsg)
	{
		return CFrameWindowImpl<CMainFrame>::PreTranslateMessage(pMsg);
	}

	virtual BOOL OnIdle()
	{
		if (m_bFirstIdle)
		{
			CComPtr<IShellFolder> spFolder;
			HRESULT hr = ::SHGetDesktopFolder(&spFolder);
			if (SUCCEEDED(hr))
			{
				CWaitCursor wait;

				m_bFirstIdle = false;

				FillTreeView(spFolder, NULL, TVI_ROOT);
				m_wndTreeView.Expand(m_wndTreeView.GetRootItem());
				m_wndTreeView.SelectItem(m_wndTreeView.GetRootItem());
			}
		}

		UIUpdateToolBar();

		return FALSE;
	}

	HWND CreateAddressBarCtrl(HWND hWndParent);

	void InitViews();

	HRESULT FillTreeView(LPSHELLFOLDER lpsf, LPITEMIDLIST lpifq, HTREEITEM hParent);
	static int CALLBACK CMainFrame::TreeViewCompareProc(LPARAM lparam1, LPARAM lparam2, LPARAM lparamSort);

	BOOL FillListView(LPTVITEMDATA lptvid, LPSHELLFOLDER pShellFolder);
	static int CALLBACK ListViewCompareProc(LPARAM lparam1, LPARAM lparam2, LPARAM lparamSort);

	void ListViewRefresh();                 ///< Refresh the current list views as selected in the three

	BEGIN_MSG_MAP(CMainFrame)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		COMMAND_ID_HANDLER(ID_VIEW_ICONS, OnViewChange)
		COMMAND_ID_HANDLER(ID_VIEW_SMALL_ICONS, OnViewChange)
		COMMAND_ID_HANDLER(ID_VIEW_DETAILS, OnViewChange)
		COMMAND_ID_HANDLER(ID_VIEW_LIST, OnViewChange)
		COMMAND_ID_HANDLER(ID_VIEW_SORT_NAME, OnViewSort)
		COMMAND_ID_HANDLER(ID_VIEW_SORT_SIZE, OnViewSort)
		COMMAND_ID_HANDLER(ID_VIEW_SORT_TYPE, OnViewSort)
		COMMAND_ID_HANDLER(ID_VIEW_SORT_TIME, OnViewSort)
		COMMAND_ID_HANDLER(ID_VIEW_SORT_ATTR, OnViewSort)
		COMMAND_ID_HANDLER(ID_COMBO_GO, OnComboGo)
		COMMAND_ID_HANDLER(ID_VIEW_REFRESH, OnViewRefresh)

		NOTIFY_CODE_HANDLER(NM_RCLICK, OnNMRClick)

		NOTIFY_CODE_HANDLER(TVN_SELCHANGED, OnTVSelChanged)
		NOTIFY_CODE_HANDLER(TVN_ITEMEXPANDING, OnTVItemExpanding)
		NOTIFY_CODE_HANDLER(TVN_DELETEITEM, OnTVDeleteItem)

		NOTIFY_CODE_HANDLER(LVN_GETDISPINFO, OnLVGetDispInfo)
		NOTIFY_CODE_HANDLER(LVN_COLUMNCLICK, OnLVColumnClick)
		NOTIFY_CODE_HANDLER(LVN_DELETEITEM, OnLVDeleteItem)
		NOTIFY_CODE_HANDLER(NM_CLICK, OnLVItemClick)
		NOTIFY_CODE_HANDLER(NM_DBLCLK, OnLVItemClick)

		COMMAND_ID_HANDLER(ID_APP_EXIT, OnFileExit)
		COMMAND_ID_HANDLER(ID_FILE_NEW, OnFileNew)
		COMMAND_ID_HANDLER(ID_FILE_NEW_WINDOW, OnFileNewWindow)
		COMMAND_ID_HANDLER(ID_VIEW_TOOLBAR, OnViewToolBar)
		COMMAND_ID_HANDLER(ID_VIEW_ADDRESS_BAR, OnViewAddressBar)
		COMMAND_ID_HANDLER(ID_VIEW_STATUS_BAR, OnViewStatusBar)
		COMMAND_ID_HANDLER(ID_APP_ABOUT, OnAppAbout)

		MSG_WM_TIMER(OnTimer)
		MESSAGE_HANDLER(WM_USER_WORKERTHREAD, OnWorkerThread);
	MESSAGE_HANDLER(WM_USER_DESTROYPROGRESS, OnDestroyProgress);
	MESSAGE_HANDLER(WM_USER_CHANGENOTIFICATION, OnChangeNotification);
	MSG_WM_DESTROY(OnDestroy);

	CHAIN_MSG_MAP(CUpdateUI<CMainFrame>)
		CHAIN_MSG_MAP(CFrameWindowImpl<CMainFrame>)
	END_MSG_MAP()

	BEGIN_UPDATE_UI_MAP(CMainFrame)
		UPDATE_ELEMENT(ID_VIEW_TOOLBAR, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_ADDRESS_BAR, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_STATUS_BAR, UPDUI_MENUPOPUP)

		UPDATE_ELEMENT(ID_VIEW_ICONS, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_SMALL_ICONS, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_LIST, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_DETAILS, UPDUI_MENUPOPUP)

		UPDATE_ELEMENT(ID_VIEW_SORT_NAME, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_SORT_SIZE, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_SORT_TYPE, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_SORT_TIME, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_SORT_ATTR, UPDUI_MENUPOPUP)
	END_UPDATE_UI_MAP()

	LRESULT OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnViewChange(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnComboGo(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnViewRefresh(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnViewSort(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnNMRClick(int, LPNMHDR pnmh, BOOL&);
	LRESULT OnTVSelChanged(int /*idCtrl*/, LPNMHDR pnmh, BOOL& /*bHandled*/);
	LRESULT OnTVItemExpanding(int /*idCtrl*/, LPNMHDR pnmh, BOOL& /*bHandled*/);
	LRESULT OnTVDeleteItem(int /*idCtrl*/, LPNMHDR pnmh, BOOL& /*bHandled*/);
	LRESULT OnLVGetDispInfo(int /*idCtrl*/, LPNMHDR pnmh, BOOL& /*bHandled*/);
	LRESULT OnLVColumnClick(int /*idCtrl*/, LPNMHDR pnmh, BOOL& /*bHandled*/);
	LRESULT OnLVDeleteItem(int /*idCtrl*/, LPNMHDR pnmh, BOOL& /*bHandled*/);
	LRESULT OnLVItemClick(int, LPNMHDR pnmh, BOOL&);
	LRESULT OnFileExit(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnFileNew(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnFileNewWindow(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnViewToolBar(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnViewAddressBar(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnViewStatusBar(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
	LRESULT OnAppAbout(WORD, WORD, HWND, BOOL&);
	LRESULT OnWorkerThread(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnDestroyProgress(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnChangeNotification(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	void OnTimer(UINT_PTR wParam);
	void OnDestroy();
};

#endif // CMAINFRAME_H