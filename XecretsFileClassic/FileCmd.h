#ifndef	_FILECMD_H
#define	_FILECMD_H
/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	FileCmd.h						Implementation of file operation commands from main code.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001-12-02				Initial for 0.0b4

*/

DWORD CmdEncryptZFile(CCmdParam* pCmdParam);
DWORD CmdEncryptZCFile(CCmdParam* pCmdParam);
DWORD CmdSfxEncNewFile(CCmdParam* pCmdParam);
DWORD CmdDecryptFile(CCmdParam* pCmdParam);
DWORD CmdDecryptCFile(CCmdParam* pCmdParam);
DWORD CmdDecryptOpenLaunch(CCmdParam* pCmdParam);
DWORD CmdWipe(CCmdParam* pCmdParam);
DWORD CmdWipeSilent(CCmdParam* pCmdParam);
DWORD CmdClearKeys(CCmdParam* pCmdParam);
DWORD CmdAddKey(CCmdParam* pCmdParam);
DWORD CmdMakeKeyFile(CCmdParam* pCmdParam);
DWORD CmdPromptKey(CCmdParam* pCmdParam);
DWORD CmdAnonRename(CCmdParam* pCmdParam);
DWORD CmdTestHaveKey(CCmdParam* pCmdParam);
DWORD CmdShowIdTag(CCmdParam* pCmdParam);
DWORD CmdBruteForce(CCmdParam* pCmdParam);
DWORD CmdInstallInRegistry(CCmdParam* pCmdParam);
DWORD CmdRemoveFromRegistry(CCmdParam* pCmdParam);
DWORD CmdLicenseMgr(CCmdParam* pCmdParam);
DWORD CmdRegistration(CCmdParam* pCmdParam);

typedef DWORD(*pfCmdT)(CCmdParam*);
DWORD FileExpand(pfCmdT pfCmd, CCmdParam* pCmdParam, const TCHAR* szDir, const TCHAR* szPattern);

#endif	_FILECMD_H