#pragma once
/*! \file
	\brief Create static hyper link in dialogbox

	@(#) $Id$

	Copyright (C) 2009-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	IStaticHyperlink.h
*/
namespace awl {
	class IStaticHyperlink {
	public:
		static IStaticHyperlink& GetInstance();
		virtual bool EnableHyperlink(HWND hWndControl) = 0;
		virtual ~IStaticHyperlink() = 0;
	};

	BOOL ConvertStaticToHyperlink(HWND hwndCtl);
	BOOL ConvertStaticToHyperlink(HWND hwndParent, UINT uiCtlId);
}
