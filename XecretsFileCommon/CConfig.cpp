/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2004-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	CConfig.cpp                     Operations on basic encryption types (hashes, keys etc).

	E-mail                          YYYY-MM-DD              Reason
	support@axantum.com             2004-09-13              Initial

*/
#include "stdafx.h"
#include "CConfig.h"
#include "../AxPipe/AxPipe.h"
#include "../AxPipe/CFileMap.h"
#include "../AxPipe/CSinkAxMLite.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CConfig.cpp"

#pragma warning(disable : 4267 4661)

/// \brief Point to the signature XML to use
/// If unsuccessful, get the error with GetLastError() and is also indicated
/// GetSigsXML returning NULL. If a path is given, it is prepended along with
/// a slash to the path to the sigs file.
/// \param sSigs a file system path to the signature XML
/// \param sPath a file system path to the folder of the signature XML
CConfig::CConfig(const axpl::ttstring& sSigs, const axpl::ttstring& sPath) {
	// Load the XML from the signature XML-file, and save the XML object pointer
	try {
		m_pSigsXML = auto_ptr<const XNode>(LoadXML(m_sSigs = (sPath.empty() ? sSigs : sPath + _TT("/") + sSigs)));
	}
	catch (...) {
		m_pSigsXML = auto_ptr<const XNode>(NULL);
	}
	if (m_pSigsXML.get() == NULL) {
		m_sLastError = _TT("Error loading signature XML from '") + sSigs + _TT("'");
	}
}

/// \brief Get the last error message saved
/// \return A std::string with the message
axpl::ttstring
CConfig::GetLastErrorMsg() {
	return m_sLastError;
}

/// \brief Get the XML from a file into an in-memory object
/// If an error occurrs, NULL is returned and there is an error message
/// to get with GetLastError();
/// \param sFileXML The path to a XML-file
/// \return A pointer to an in-memory structure representing the parsed XML
const XNode*
CConfig::LoadXML(const axpl::ttstring& sFileXML) {
	AxPipe::Stock::CSinkAxMLite* psinkAxMLite = new AxPipe::Stock::CSinkAxMLite;
	ASSPTR(psinkAxMLite);

	AxPipe::CSourceMemFile file;
	file.Init(sFileXML.c_str());
	file.Append(psinkAxMLite);

	// Read, Parse and Store in memory object
	file.Open()->Drain()->Close();

	// The psinkAxMLite gets deleted when 'file' goes out of scope below.
	if (file.GetErrorCode() != 0) {
		m_sLastError = file.GetErrorMsg();
		return NULL;
	}
	else {
		return psinkAxMLite->ReleaseXNode();
	}
}

// Get the Signature XML object. Do not delete...
const XNode*
CConfig::GetSigsXML() {
	return m_pSigsXML.get();
}
// Get the Configuration XML object. Do not delete...
const XNode*
CConfig::GetConfigXML() {
	return m_pConfigXML.get();
}

/// \brief Find an element in XML
/// Find the first node in the tree that matches the given name.
/// \param pXML The node to start with
/// \param sName the (case-insensitive) element to look for
/// \return The found element node or NULL
const XNode*
CConfig::GetElementXML(const XNode* pXML, const axpl::ttstring& sElement) {
	const XNode* pCandidate;
	if (pXML) {
		if (axpl::TTStringCompareIgnoreCase(pXML->name, sElement)) {
			return pXML;
		}
		for (XNodes::const_iterator it = pXML->childs.begin(); it != pXML->childs.end(); it++) {
			if ((pCandidate = GetElementXML(*it, sElement)) != NULL) {
				return pCandidate;
			}
		}
	}
	return NULL;
}

/// \brief Find an element in the configuration XML
/// Use the internally kept Configuration XML to find an element, and
/// return it's value as a string
/// \param sElement The name of the element to look for
/// \return The value of the found element, or ""
axpl::ttstring
CConfig::GetElementConfig(const axpl::ttstring& sElement) {
	const XNode* pNode = GetElementXML(GetConfigXML(), sElement);
	if (pNode != NULL) {
		return pNode->value;
	}
	return axpl::ttstring(_TT(""));
}

/// \brief Find an attribute of an element in the configuration XML
/// Return the value of an attribute of an element as a string
/// \param sElement The name of the element to look for
/// \param sAttribute The name of the attribute to look for
/// \return The value of the found attribute, or ""
axpl::ttstring
CConfig::GetElementAttributeConfig(const axpl::ttstring& sElement, const axpl::ttstring& sAttribute) {
	const XNode* pNode = GetElementXML(GetConfigXML(), sElement);
	if (pNode == NULL) {
		return axpl::ttstring(_TT(""));
	}
	for (XAttrs::const_iterator it = pNode->attrs.begin(); it != pNode->attrs.end(); it++) {
		if (axpl::TTStringCompareIgnoreCase((*it)->name, sAttribute)) {
			return (*it)->value;
		}
	}
	return axpl::ttstring(_TT(""));
}

/// \brief Find an elmement possibly with a matching attribute required
/// Search a tree for an element of a given name, regardless of depth. It may
/// also need an attribute to mathch. The first found is returned.
/// \param pXNode The XML tree to search.
/// \param sElement The name of the element to search for.
/// \param sAttribute A name of an attribute to search for (and return). Optional.
/// \return A pair of strings representing the values of the element and the attribute (optional).
axpl::ttstringpair
CConfig::GetFromXML(const XNode* pXML, const axpl::ttstring& sElement, const axpl::ttstring& sAttribute) {
	if (pXML) {
		const XNode* pCandidate = GetElementXML(pXML, sElement);
		if (pCandidate) {
			if (sAttribute.empty()) {
				return axpl::ttstringpair(pCandidate->value, _TT(""));
			}

			for (XAttrs::const_iterator it = pCandidate->attrs.begin(); it != pCandidate->attrs.end(); it++) {
				if (axpl::TTStringCompareIgnoreCase((*it)->name, sAttribute)) {
					return axpl::ttstringpair(pCandidate->value, (*it)->value);
				}
			}
		}
		for (XNodes::const_iterator it = pXML->childs.begin(); it != pXML->childs.end(); it++) {
			axpl::ttstringpair res = GetFromXML(*it, sElement, sAttribute);
			if (!res.first.empty()) {
				return res;
			}
		}
	}
	return axpl::ttstringpair(_TT(""), _TT(""));
}

/// \brief Load the XML from the configuration file
/// We assume that the configuration signature has been verified already.
/// We find the configuration file by looking in the XML after the first occurrence
/// of a 'config' element.
/// \param pXML A XML-tree to look in
/// \return true if found.
bool
CConfig::LoadConfig(const XNode* pXML, const axpl::ttstring& sPath) {
	// Get the name of the configuration file from the File attribute of the (first) signature,
	// in the first config element.
	pXML = GetElementXML(pXML, _TT("Config"));
	if (pXML) {
		// use the attribute to load the XML and save the result.
		m_sConfig = GetFromXML(pXML, _TT("signature"), _TT("file")).second;
		if (!m_sConfig.empty()) {
			// Actually load the XML - we did assume that it was signed...
			m_pConfigXML = auto_ptr<const XNode>(LoadXML(sPath.empty() ? m_sConfig : sPath + _TT("/") + m_sConfig));
			return m_pConfigXML.get() != NULL;
		}
	}
	m_sLastError = _TT("No Configuration XML file found!");
	return false;
}

/// \brief Check that we have the correct name, or that we do not have this requirement
/// \param pXML A XML-tree to look in
/// \param sName the name of our own executable
/// \return true If this is the name found as the 'file' attribute of the first 'Self' element found
bool
CConfig::VerifyName(const XNode* pXML, const axpl::ttstring& sName, const axpl::ttstring& sElement, const axpl::ttstring& sAttrib) {
	axpl::ttstring sSelfName = GetFromXML(pXML, sElement, sAttrib).second;
	return sSelfName.empty() || axpl::TTStringCompareIgnoreCase(sSelfName, sName);
}