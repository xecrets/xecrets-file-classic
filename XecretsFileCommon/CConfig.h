#ifndef CCONFIG_H
#define CCONFIG_H
/*
    @(#) $Id$

    Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
    Server or Web Storage of Document Files.

    Copyright (C) 2004-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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
    CConfig.h                       Manage configuration XML
*/
#include "../AxWinLib/AxMLite.h"

/// \brief Interface to XML-based, signed configuration files.
/// A main, unsigned XML file typically named Sigs.XML contains information
/// pointing to a real configuration file, which is signed. The signature
/// is stored in Sigs.XML along with the reference to the file. The Sigs.XML
/// file may also contain signed licenses etc.
/// The configuration XML, typically named Config.XML, is signed and can
/// therefore be trusted. It contains signatures of various files and other
/// information about the application that is static after release (since it
/// is signed).
class CConfig {
protected:
    axpl::ttstring m_sSigs;                           ///< The file name of the Signature XML
    axpl::ttstring m_sConfig;                         ///< The file name of the Configuration XML
    axpl::ttstring m_sLastError;                      ///< Keep the text from the most recent error here.
    std::auto_ptr<const XNode> m_pSigsXML;            ///< The Signature XML in-memory representation
    std::auto_ptr<const XNode> m_pConfigXML;          ///< The Configuration XML in-memory representation

    // Load XML from a file into a XML object
    const XNode * LoadXML(const axpl::ttstring &sFileXML);

public:
    // Point to the signature XML to use
    CConfig(const axpl::ttstring &sSigs, const axpl::ttstring &sPath = _TT(""));
    // Return the last error message
    axpl::ttstring GetLastErrorMsg();
    // Get the Signature XML object. Do not delete...
    const XNode *GetSigsXML();
    // Get the Configuration XML object. Do not delete...
    const XNode *GetConfigXML();
    /// \brief Find an elmement possibly with a matching attribute required
    axpl::ttstringpair GetFromXML(const XNode *pXML, const axpl::ttstring &sElement, const axpl::ttstring &sAttribute = _TT(""));
    /// \brief Find an element in XML
    const XNode *GetElementXML(const XNode *pXML, const axpl::ttstring &sElement);
    /// \brief Find an element in the configuration XML
    axpl::ttstring GetElementConfig(const axpl::ttstring &sElement);
    /// \brief Find an attribute of an element in the configuration XML
    axpl::ttstring GetElementAttributeConfig(const axpl::ttstring &sElement, const axpl::ttstring &sAttribute);
    /// \brief Load the XML from the configuration file
    bool LoadConfig(const XNode *pXML, const axpl::ttstring &sPath = _TT(""));
    /// \brief Check that we have the correct name
    bool VerifyName(const XNode *pXML, const axpl::ttstring &sName, const axpl::ttstring &sElement = _TT("Self"), const axpl::ttstring &sAttrib = _TT("File"));
};
#endif