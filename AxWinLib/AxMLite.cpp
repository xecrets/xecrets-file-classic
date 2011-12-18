// Originally by bro ( Cho,Kyung Min: bro@shinbiro.com ) 2002-10-30
//
// Modified by Svante Seleborg/Axantum Data AB. This code, whilst very useful
// for the limited use intended when this is written, needs serious rewriting.
// There are many things that need fixing, from style to bugs.
// Please contact the original author with bug-reports etc. The use by me
// is in an extremely limited context, where the XML parsed is mostly digitally
// signed, thus stable. Regardless of all the caveats, credit is due to the
// original author - this saved me many hours.
//
// I have corrected some bugs, and mostly in a quick and dirty manner converted
// from MFC CString to STL ttstring.
//
// XMLite.cpp: implementation of the XMLite class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "AxMLite.h"
#include <iostream>
#include <sstream>
#include <string>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
//#define new DEBUG_NEW
#endif

static const TCHAR chXMLTagOpen     = '<';
static const TCHAR chXMLTagClose    = '>';
static const TCHAR chXMLTagPre  = '/';
static const TCHAR chXMLEscape = '\\';  // for value field escape


static const XENTITY x_EntityTable[] = {
        { '&', _T("&amp;"), 5 } ,
        { '\"', _T("&quot;"), 6 } ,
        { '\'', _T("&apos;"), 6 } ,
        { '<', _T("&lt;"), 4 } ,
        { '>', _T("&gt;"), 4 } 
    };

PARSEINFO piDefault;
DISP_OPT optDefault;
XENTITYS entityDefault((LPXENTITY)x_EntityTable, sizeof(x_EntityTable)/sizeof(x_EntityTable[0]) );
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////


//========================================================
// Name   : _tcschrs
// Desc   : same with _tcspbrk 
// Param  :
// Return :
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPTSTR _tcschrs(LPCTSTR psz, LPCTSTR pszchs)
{
    while (psz && *psz) {
        if ( _tcschr(pszchs, *psz)) {
            return (LPTSTR)psz;
        }
        psz++;
    }
    return NULL;
}

//========================================================
// Name   : _tcsskip
// Desc   : skip space
// Param  : 
// Return : skiped string
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPTSTR _tcsskip(LPCTSTR psz) {
    //while( psz && *psz == ' ' && *psz == 13 && *psz == 10 ) psz++;
    while (psz && _istspace(*psz)) {
        psz++;
    }
        
    return (LPTSTR)psz;
}

//========================================================
// Name   : _tcsechr
// Desc   : similar with _tcschr with escape process
// Param  : escape - will be escape character
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPTSTR _tcsechr(LPCTSTR psz, int ch, int escape) {
    LPTSTR pch = (LPTSTR)psz;

    while (pch && *pch) {
        if (*pch == escape) {
            pch++;
        } else {
            if (*pch == ch) { 
                return (LPTSTR)pch;
            }
        }
        pch++;
    }
    return pch;
}

//========================================================
// Name   : _tcselen
// Desc   : similar with _tcslen with escape process
// Param  : escape - will be escape character
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
int _tcselen(int escape, LPTSTR srt, LPTSTR end = NULL) {
    int len = 0;
    LPTSTR pch = srt;
    // ????/SS if( end==NULL ) end = (LPTSTR)sizeof(long);
    LPTSTR prev_escape = NULL;
    while (pch && *pch && ((end == NULL) || (pch < end))) {
        if (*pch == escape && prev_escape == NULL) {
            prev_escape = pch;
        } else {
            prev_escape = NULL;
            len++;
        }
        pch++;
    }
    return len;
}

//========================================================
// Name   : _tcsecpy
// Desc   : similar with _tcscpy with escape process
// Param  : escape - will be escape character
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
void _tcsecpy(LPTSTR psz, int escape, LPTSTR srt, LPTSTR end = NULL) {
    LPTSTR pch = srt;
    // ????/SS if( end==NULL ) end = (LPTSTR)sizeof(long);
    LPTSTR prev_escape = NULL;
    while (pch && *pch && ((end == NULL) || (pch<end))) {
        if (*pch == escape && prev_escape == NULL) {
            prev_escape = pch;
        } else {
            prev_escape = NULL;
            *psz++ = *pch;
        }
        pch++;
    }
    *psz = '\0';
}

//========================================================
// Name   : _tcsepbrk
// Desc   : similar with _tcspbrk with escape process
// Param  : escape - will be escape character
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPTSTR _tcsepbrk(LPCTSTR psz, LPCTSTR chset, int escape) {
    LPTSTR pch = (LPTSTR)psz;
    LPTSTR prev_escape = NULL;
    while (pch && *pch) {
        if (*pch == escape && prev_escape == NULL) {
            prev_escape = pch;
        } else {
            prev_escape = NULL;
            if (_tcschr( chset, *pch )) {
                return (LPTSTR)pch;     
            }
        }
        pch++;
    }
    return pch;
}

//========================================================
// Name   : _SetString
// Desc   : put string of (psz~end) on ps string. end points just past last char to copy
// Param  : trim - will be trim?
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
void _SetString(LPTSTR psz, LPTSTR end, axpl::ttstring* ps, bool trim = FALSE, int escape = 0) {
    //trim
    if (trim) {
        while (psz && psz < end && _istspace(*psz)) {
            psz++;
        }
        while (*(end-1) && psz < (end-1) && _istspace(*(end-1))) {
            end--;
        }
    }
    size_t len = end - psz;

    if (len <= 0) {
        return;
    }

    if (escape) {
        len = _tcselen(escape, psz, end);
        //if (ps->length() < len) {
            ps->resize(len);
        //}
        _tcsecpy(&*ps->begin(), escape, psz, end);

        //LPTSTR pss = ps->GetBufferSetLength( len );
        //_tcsecpy( pss, escape, psz, end );
    } else {
        //if (ps->length() < len) {
            ps->resize(len);
        //}
        memcpy(&*ps->begin(), psz, len * sizeof *psz);
        //LPTSTR pss = ps->GetBufferSetLength(len + 1 );
        //memcpy( pss, psz, len );
        //pss[len] = '\0';
    }
}

_tagXMLNode::~_tagXMLNode() {
    Close();
}

void _tagXMLNode::Close()
{
    for( size_t i = 0 ; i < childs.size(); i ++)
    {
        LPXNode p = childs[i];
        if( p )
        {
            delete p; childs[i] = NULL;
        }
    }
    childs.clear();
    
    for( size_t i = 0 ; i < attrs.size(); i ++)
    {
        LPXAttr p = attrs[i];
        if( p )
        {
            delete p; attrs[i] = NULL;
        }
    }
    attrs.clear();
}
    
// attr1="value1" attr2='value2' attr3=value3 />
//                                            ^- return pointer
//========================================================
// Name   : LoadAttributes
// Desc   : loading attribute plain xml text
// Param  : pszAttrs - xml of attributes
//          pi = parser information
// Return : advanced string pointer. (error return NULL)
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPTSTR _tagXMLNode::LoadAttributes(LPCTSTR pszAttrs , LPPARSEINFO pi /*= &piDefault*/)
{
    LPTSTR xml = (LPTSTR)pszAttrs;

    while( xml && *xml )
    {
        if( xml = _tcsskip( xml ) )
        {
            // close tag
            if( *xml == chXMLTagClose || *xml == chXMLTagPre )
                // wel-formed tag
                return xml;

            // XML Attr Name
            TCHAR* pEnd = _tcspbrk( xml, _T(" =") );
            if( pEnd == NULL ) 
            {
                // error
                if( pi->erorr_occur == false ) 
                {
                    pi->erorr_occur = true;
                    pi->error_pointer = xml;
                    pi->error_code = PIE_ATTR_NO_VALUE;
                    pi->error_string.assign(_T("<")).append(name).append(_T("> attribute has error "));
                    //pi->error_string.Format( _T("<%s> attribute has error "), name );
                }
                return NULL;
            }
            
            LPXAttr attr = new XAttr;
            attr->parent = this;

            // XML Attr Name
            _SetString( xml, pEnd, &attr->name );
            
            // add new attribute
            attrs.push_back( attr );
            xml = pEnd;
            
            // XML Attr Value
            if( xml = _tcsskip( xml ) )
            {
                //if( xml = _tcschr( xml, '=' ) )
                if( *xml == '=' )
                {
                    if( xml = _tcsskip( ++xml ) )
                    {
                        // if " or '
                        // or none quote
                        int quote = *xml;
                        if( quote == '"' || quote == '\'' )
                            pEnd = _tcsechr( ++xml, quote, chXMLEscape );
                        else
                        {
                            //attr= value> 
                            // none quote mode
                            //pEnd = _tcsechr( xml, ' ', '\\' );
                            pEnd = _tcsepbrk( xml, _T(" >"), chXMLEscape );
                        }

                        bool trim = pi->trim_value;
                        TCHAR escape = pi->escape_value;
                        //_SetString( xml, pEnd, &attr->value, trim, chXMLEscape ); 
                        _SetString( xml, pEnd, &attr->value, trim, escape );
                        xml = pEnd;
                        // ATTRVALUE 
                        if( pi->entity_value && pi->entitys )
                            attr->value = pi->entitys->Ref2Entity(attr->value.c_str());

                        if( quote == '"' || quote == '\'' )
                            xml++;
                    }
                }
            }
        }
    }

    // not wel-formed tag
    return NULL;
}

// <TAG attr1="value1" attr2='value2' attr3=value3 >
// </TAG>
// or
// <TAG />
//        ^- return pointer
//========================================================
// Name   : Load
// Desc   : load xml plain text
// Param  : pszXml - plain xml text
//          pi = parser information
// Return : advanced string pointer  (error return NULL)
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPTSTR _tagXMLNode::Load( LPCTSTR pszXml, LPPARSEINFO pi /*= &piDefault*/ )
{
    // Close it
    Close();

    LPTSTR xml = (LPTSTR)pszXml;

    xml = _tcschr( xml, chXMLTagOpen );
    if( xml == NULL )
        return NULL;

    // Close Tag
    if( *(xml+1) == chXMLTagPre ) // </Close
        return xml;

    // XML Node Tag Name Open
    xml++;
    TCHAR* pTagEnd = _tcspbrk( xml, _T(" />") );
    _SetString( xml, pTagEnd, &name );
    xml = pTagEnd;
    // Generate XML Attributte List
    if( xml = LoadAttributes( xml, pi ) )
    {
        // alone tag <TAG ... />
        if( *xml == chXMLTagPre )
        {
            xml++;
            if( *xml == chXMLTagClose )
                // wel-formed tag
                return ++xml;
            else
            {
                // error: <TAG ... / >
                if( pi->erorr_occur == false ) 
                {
                    pi->erorr_occur = true;
                    pi->error_pointer = xml;
                    pi->error_code = PIE_ALONE_NOT_CLOSED;
                    pi->error_string = _T("Element must be closed.");
                }
                // not wel-formed tag
                return NULL;
            }
        }
        else
        // open/close tag <TAG ..> ... </TAG>
        //                        ^- current pointer
        {
            // text value가 없으면 넣도록한다.
            //if( this->value.IsEmpty() || this->value == _T("") )
            if( XIsEmptyString( value.c_str() ) )
            {
                // Text Value 
                TCHAR* pEnd = _tcsechr( ++xml, chXMLTagOpen, chXMLEscape );
                if( pEnd == NULL ) 
                {
                    if( pi->erorr_occur == false ) 
                    {
                        pi->erorr_occur = true;
                        pi->error_pointer = xml;
                        pi->error_code = PIE_NOT_CLOSED;
                        pi->error_string.assign(name).append(_T(" must be closed with </")).append(name).append(_T(">"));
//                        pi->error_string.Format(_T("%s must be closed with </%s>"), name );
                    }
                    // error cos not exist CloseTag </TAG>
                    return NULL;
                }
                
                bool trim = pi->trim_value;
                TCHAR escape = pi->escape_value;
                //_SetString( xml, pEnd, &value, trim, chXMLEscape );
                _SetString( xml, pEnd, &value, trim, escape );

                xml = pEnd;
                // TEXTVALUE reference
                if( pi->entity_value && pi->entitys )
                    value = pi->entitys->Ref2Entity(value.c_str());
            }

            // generate child nodes
            while( xml && *xml )
            {
                LPXNode node = new XNode;
                node->parent = this;
                
                xml = node->Load( xml,pi );
                if (!node->name.empty()) {
                    childs.push_back( node );
                } else {
                    delete node;
                }

                // open/close tag <TAG ..> ... </TAG>
                //                             ^- current pointer
                // CloseTag case
                if( xml && *xml && *(xml+1) && *xml == chXMLTagOpen && *(xml+1) == chXMLTagPre )
                {
                    // </Close>
                    xml+=2; // C
                    
                    if( xml = _tcsskip( xml ) )
                    {
                        axpl::ttstring closename;
                        TCHAR* pEnd = _tcspbrk( xml, _T(" >") );
                        if( pEnd == NULL ) 
                        {
                            if( pi->erorr_occur == false ) 
                            {
                                pi->erorr_occur = true;
                                pi->error_pointer = xml;
                                pi->error_code = PIE_NOT_CLOSED;
                                pi->error_string.assign(_T("it must be closed with </")).append(name);
//                                pi->error_string.Format(_T("it must be closed with </%s>"), name );
                            }
                            // error
                            return NULL;
                        }
                        _SetString( xml, pEnd, &closename );
                        if( closename == this->name )
                        {
                            // wel-formed open/close
                            xml = pEnd+1;
                            // return '>' or ' ' after pointer
                            return xml;
                        }
                        else
                        {
                            xml = pEnd+1;
                            // not welformed open/close
                            if( pi->erorr_occur == false ) 
                            {
                                pi->erorr_occur = true;
                                pi->error_pointer = xml;
                                pi->error_code = PIE_NOT_NESTED;
                                pi->error_string.assign(_T("'<")).append(name).append(_T("> ... </")).append(closename).append(_T(">' is not wel-formed."));
//                                pi->error_string.Format(_T("'<%s> ... </%s>' is not wel-formed."), name, closename );
                            }
                            return NULL;
                        }
                    }
                }
                else    // Alone child Tag Loaded
                        // else 해야하는지 말아야하는지 의심간다.
                {
                    
                    //if( xml && this->value.IsEmpty() && *xml !=chXMLTagOpen )
                    if( xml && XIsEmptyString( value.c_str() ) && *xml !=chXMLTagOpen )
                    {
                        // Text Value 
                        TCHAR* pEnd = _tcsechr( xml, chXMLTagOpen, chXMLEscape );
                        if( pEnd == NULL ) 
                        {
                            // error cos not exist CloseTag </TAG>
                            if( pi->erorr_occur == false )  
                            {
                                pi->erorr_occur = true;
                                pi->error_pointer = xml;
                                pi->error_code = PIE_NOT_CLOSED;
                                pi->error_string.assign(_T("it must be closed with </")).append(name).append(_T(">"));
//                                pi->error_string.Format(_T("it must be closed with </%s>"), name );
                            }
                            return NULL;
                        }
                        
                        bool trim = pi->trim_value;
                        TCHAR escape = pi->escape_value;
                        //_SetString( xml, pEnd, &value, trim, chXMLEscape );
                        _SetString( xml, pEnd, &value, trim, escape );

                        xml = pEnd;
                        //TEXTVALUE
                        if( pi->entity_value && pi->entitys )
                            value = pi->entitys->Ref2Entity(value.c_str());
                    }
                }
            }
        }
    }

    return xml;
}

//========================================================
// Name   : GetXML
// Desc   : convert plain xml text from parsed xml attirbute
// Param  :
// Return : converted plain string
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
axpl::ttstring _tagXMLAttr::GetXML( LPDISP_OPT opt /*= &optDefault*/ )
{
    axpl::ttstring os;
    os.assign(name).append(_T("=")).push_back(opt->value_quotation_mark);
    os.append((opt->reference_value && opt->entitys) ? opt->entitys->Entity2Ref(value.c_str()) : value.c_str());
    os.push_back(opt->value_quotation_mark);
    os.append(_T(" "));
    return os;
/*
    std::ostringstream os;
    //os << (LPCTSTR)name << "='" << (LPCTSTR)value << "' ";
    
    os << (LPCTSTR)name << "=" << (char)opt->value_quotation_mark 
        << (LPCTSTR)(opt->reference_value&&opt->entitys?opt->entitys->Entity2Ref(value):value) 
        << (char)opt->value_quotation_mark << " ";
    return os.str().c_str();
*/
}

//========================================================
// Name   : GetXML
// Desc   : convert plain xml text from parsed xml node
// Param  :
// Return : converted plain string
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
axpl::ttstring _tagXMLNode::GetXML( LPDISP_OPT opt /*= &optDefault*/ )
{
    axpl::ttstring os;

    os = _T("");

    // tab
    if (opt && opt->newline) {
        if (opt && opt->newline) {
            os += _T("\r\n");
        }
        for (int i = 0 ; i < opt->tab_base ; i++) {
            os += _T('\t');
        }
    }

    // <TAG
    os += _T("<");
    os += name;

    // <TAG Attr1="Val1" 
    if (!attrs.empty()) {
        os += _T(' ');
    }
    for (size_t i = 0 ; i < attrs.size(); i++) {
        os += attrs[i]->GetXML(opt);
    }
    
    if (childs.empty() && value.empty()) {
        // <TAG Attr1="Val1"/> alone tag 
        os += _T("/>");
    } else {
        // <TAG Attr1="Val1"> and get child
        os += _T(">");
        if (opt && opt->newline && !childs.empty()) {
            opt->tab_base++;
        }

        for (size_t i = 0 ; i < childs.size(); i++) {
            os += childs[i]->GetXML(opt);
        }
        
        // Text Value
        if (!XIsEmptyString(value.c_str())) {
            if (opt && opt->newline && !childs.empty()) {
                if (opt && opt->newline) {
                    os += _T("\r\n");
                }
                for (int i = 0; i < opt->tab_base; i++) {
                    os += _T('\t');
                }
            }
            os += (opt->reference_value && opt->entitys) ? opt->entitys->Entity2Ref(value.c_str()) : value;
//            os << (LPCTSTR)(opt->reference_value&&opt->entitys?opt->entitys->Entity2Ref(value):value);
        }

        // </TAG> CloseTag
        if (opt && opt->newline && !childs.empty()) {
            os += _T("\r\n");
            for (int i = 0 ; i < opt->tab_base-1 ; i++) {
                os += _T('\t');
            }
        }
        os += _T("</");
        os += name;
        os += _T(">");

        if (opt && opt->newline) {
            if (!childs.empty()) {
                opt->tab_base--;
            }
        }
    }
    
    return os;
}

//========================================================
// Name   : GetAttr
// Desc   : get attribute with attribute name
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXAttr _tagXMLNode::GetAttr( LPCTSTR attrname ) {
    for (size_t i = 0 ; i < attrs.size(); i++ ) {
        LPXAttr attr = attrs[i];
        if (attr) {
            if (attr->name == attrname) {
                return attr;
            }
        }
    }
    return NULL;
}

//========================================================
// Name   : GetAttrs
// Desc   : find attributes with attribute name, return its list
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
XAttrs _tagXMLNode::GetAttrs(LPCTSTR name)
{
    XAttrs attrs;
    for (size_t i = 0 ; i < attrs.size(); i++) {
        LPXAttr attr = attrs[i];
        if (attr) {
            if (attr->name == name) {
                attrs.push_back(attr);
            }
        }
    }
    return attrs;
}

//========================================================
// Name   : GetAttrValue
// Desc   : get attribute with attribute name, return its value
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPCTSTR _tagXMLNode::GetAttrValue(LPCTSTR attrname) {
    XAttr *attr = GetAttr(attrname);
    return attr ? attr->value.c_str() : NULL;
}

XNodes _tagXMLNode::GetChilds() {
    return childs;
}

//========================================================
// Name   : GetChilds
// Desc   : Find childs with name and return childs list
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
XNodes _tagXMLNode::GetChilds(LPCTSTR name) {
    XNodes nodes;
    for (size_t i = 0 ; i < childs.size(); i++) {
        LPXNode node = childs[i];
        if (node) {
            if(node->name == name) {
                nodes.push_back(node);
            }
        }
    }
    return nodes;   
}

//========================================================
// Name   : GetChild
// Desc   : get child node with index
// Param  :
// Return : NULL return if no child.
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
XNode *_tagXMLNode::GetChild(size_t i) {
    if (i >= 0 && i < childs.size()) {
        return childs[i];
    }
    return NULL;
}

//========================================================
// Name   : GetChildCount
// Desc   : get child node count
// Param  :
// Return : 0 return if no child
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-12-26
//========================================================
size_t _tagXMLNode::GetChildCount()
{
    return childs.size();
}

//========================================================
// Name   : GetChild
// Desc   : Find child with name and return child
// Param  :
// Return : NULL return if no child.
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXNode _tagXMLNode::GetChild(LPCTSTR name) {
    for (size_t i = 0 ; i < childs.size(); i++ ) {
        LPXNode node = childs[i];
        if (node) {
            if (node->name == name) {
                return node;
            }
        }
    }
    return NULL;
}

//========================================================
// Name   : GetChildValue
// Desc   : Find child with name and return child's value
// Param  :
// Return : NULL return if no child.
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPCTSTR _tagXMLNode::GetChildValue( LPCTSTR name )
{
    LPXNode node = GetChild(name);
    return (node != NULL) ? node->value.c_str() : NULL;
}

LPXAttr _tagXMLNode::GetChildAttr( LPCTSTR name, LPCTSTR attrname )
{
    LPXNode node = GetChild(name);
    return node ? node->GetAttr(attrname) : NULL;
}

LPCTSTR _tagXMLNode::GetChildAttrValue( LPCTSTR name, LPCTSTR attrname )
{
    LPXAttr attr = GetChildAttr( name, attrname );
    return attr ? attr->value.c_str() : NULL;
}


//========================================================
// Name   : GetChildIterator
// Desc   : get child nodes iterator
// Param  :
// Return : NULL return if no childs.
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
XNodes::iterator _tagXMLNode::GetChildIterator( LPXNode node )
{
    XNodes::iterator it = childs.begin();
    for( ; it != childs.end() ; ++(it) )
    {
        if( *it == node )
            return it;
    }
    return childs.end();
}

//========================================================
// Name   : AppendChild
// Desc   : add node
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXNode _tagXMLNode::AppendChild( LPCTSTR name /*= NULL*/, LPCTSTR value /*= NULL*/ )
{
    return AppendChild( CreateNode( name, value ) );
}

//========================================================
// Name   : AppendChild
// Desc   : add node
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXNode _tagXMLNode::AppendChild( LPXNode node )
{
    node->parent = this;
    childs.push_back( node );
    return node;
}

//========================================================
// Name   : RemoveChild
// Desc   : detach node and delete object
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
bool _tagXMLNode::RemoveChild( LPXNode node )
{
    XNodes::iterator it = GetChildIterator( node );
    if( it != childs.end())
    {
        delete *it;
        childs.erase( it );
        return true;
    }
    return false;
}

//========================================================
// Name   : GetAttr
// Desc   : get attribute with index in attribute list
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
XAttr *_tagXMLNode::GetAttr(size_t i) {
    if (i >= 0 && i < attrs.size()) {
        return attrs[i];
    }
    return NULL;
}

//========================================================
// Name   : GetAttrIterator
// Desc   : get attribute iterator
// Param  : 
// Return : std::vector<LPXAttr>::iterator
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
XAttrs::iterator _tagXMLNode::GetAttrIterator( LPXAttr attr )
{
    XAttrs::iterator it = attrs.begin();
    for( ; it != attrs.end() ; ++(it) )
    {
        if( *it == attr )
            return it;
    }
    return attrs.end();
}

//========================================================
// Name   : AppendAttr
// Desc   : add attribute
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXAttr _tagXMLNode::AppendAttr( LPXAttr attr )
{
    attr->parent = this;
    attrs.push_back( attr );
    return attr;
}

//========================================================
// Name   : RemoveAttr
// Desc   : detach attribute and delete object
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
bool _tagXMLNode::RemoveAttr( LPXAttr attr )
{
    XAttrs::iterator it = GetAttrIterator( attr );
    if( it != attrs.end())
    {
        delete *it;
        attrs.erase( it );
        return true;
    }
    return false;
}

//========================================================
// Name   : CreateNode
// Desc   : Create node object and return it
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXNode _tagXMLNode::CreateNode( LPCTSTR name /*= NULL*/, LPCTSTR value /*= NULL*/ )
{
    LPXNode node = new XNode;
    node->name = name;
    node->value = value;
    return node;
}

//========================================================
// Name   : CreateAttr
// Desc   : create Attribute object and return it
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXAttr _tagXMLNode::CreateAttr( LPCTSTR name /*= NULL*/, LPCTSTR value /*= NULL*/ )
{
    LPXAttr attr = new XAttr;
    attr->name = name;
    attr->value = value;
    return attr;
}

//========================================================
// Name   : AppendAttr
// Desc   : add attribute
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXAttr _tagXMLNode::AppendAttr( LPCTSTR name /*= NULL*/, LPCTSTR value /*= NULL*/ )
{
    return AppendAttr( CreateAttr( name, value ) );
}

//========================================================
// Name   : DetachChild
// Desc   : no delete object, just detach in list
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXNode _tagXMLNode::DetachChild( LPXNode node )
{
    XNodes::iterator it = GetChildIterator( node );
    if( it != childs.end() )
    {
        childs.erase( it );
        return node;
    }
    return NULL;
}

//========================================================
// Name   : DetachAttr
// Desc   : no delete object, just detach in list
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXAttr _tagXMLNode::DetachAttr( LPXAttr attr )
{
    XAttrs::iterator it = GetAttrIterator( attr );
    if( it != attrs.end() )
    {
        attrs.erase( it );
        return attr;
    }
    return NULL;
}

//========================================================
// Name   : CopyNode
// Desc   : copy current level node with own attributes
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
void _tagXMLNode::CopyNode(LPXNode node) {
    Close();

    parent = node->parent;
    name = node->name;
    value = node->value;

    // copy attributes
    for (size_t i = 0 ; i < node->attrs.size(); i++) {
        LPXAttr attr = node->attrs[i];
        if (attr) {
            AppendAttr(attr->name.c_str(), attr->value.c_str());
        }
    }
}

//========================================================
// Name   : _CopyBranch
// Desc   : recursive internal copy branch 
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
void _tagXMLNode::_CopyBranch(LPXNode node) {
    CopyNode( node );

    for (size_t i = 0; i < node->childs.size(); i++) {
        LPXNode child = node->childs[i];
        if (child) {
            LPXNode mychild = new XNode;
            mychild->CopyNode( child );
            AppendChild( mychild );

            mychild->_CopyBranch( child );
        }
    }
}

//========================================================
// Name   : AppendChildBranch
// Desc   : add child branch ( deep-copy )
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
LPXNode _tagXMLNode::AppendChildBranch( LPXNode node )
{
    LPXNode child = new XNode;
    child->CopyBranch( node );

    return AppendChild( child );
}

//========================================================
// Name   : CopyBranch
// Desc   : copy branch ( deep-copy )
// Param  :
// Return : 
//--------------------------------------------------------
// Coder    Date                      Desc
// bro      2002-10-29
//========================================================
void _tagXMLNode::CopyBranch( LPXNode branch )
{
    Close();
    
    _CopyBranch( branch );
}


_tagXMLEntitys::_tagXMLEntitys( LPXENTITY entities, size_t count )
{
    for( size_t i = 0; i < count; i++) {
        push_back( entities[i] );
    }
}

LPXENTITY _tagXMLEntitys::GetEntity(int entity) {
    for (size_t i = 0 ; i < size(); i ++ ) {
        if (at(i).entity == entity) {
            return LPXENTITY(&at(i));
        }
    }
    return NULL;
}

LPXENTITY _tagXMLEntitys::GetEntity(LPTSTR entity) {
    for (size_t i = 0 ; i < size(); i ++ ) {
        LPTSTR ref = (LPTSTR)at(i).ref;
        LPTSTR ps = entity;
        while (ref && *ref) {
            if (*ref++ != *ps++) {
                break;
            }
        }
        if (ref && !*ref) {  // found!
            return LPXENTITY(&at(i));
        }
    }
    return NULL;
}

size_t _tagXMLEntitys::GetEntityCount( LPCTSTR str )
{
    size_t nCount = 0;
    LPTSTR ps = (LPTSTR)str;
    while( ps && *ps ) {
        if( GetEntity( *ps++ ) ) nCount ++;
    }
    return nCount;
}

// Does not include a nul char in the result
size_t
_tagXMLEntitys::Ref2Entity(LPCTSTR estr, LPTSTR str, size_t strlen) {
    LPTSTR pes = (LPTSTR)estr;
    LPTSTR ps = str;
    LPTSTR ps_end = ps+strlen;
    while (pes && *pes && ps < ps_end) {
        LPXENTITY ent = GetEntity( pes );
        if (ent) {
            // copy entity meanning char
            *ps = ent->entity;
            pes += ent->ref_len;
        } else {
            *ps = *pes++;   // default character copy
        }
        ps++;
    }
    //*ps = '\0';
    
    // total copied characters
    return ps-str;  
}

// Does not include a nul char in the result
size_t
_tagXMLEntitys::Entity2Ref(LPCTSTR str, LPTSTR estr, size_t estrlen) {
    LPTSTR ps = (LPTSTR)str;
    LPTSTR pes = (LPTSTR)estr;
    LPTSTR pes_end = pes + estrlen;
    while (ps && *ps && pes < pes_end) {
        LPXENTITY ent = GetEntity(*ps);
        if (ent) {
            // copy entity string
            LPTSTR ref = (LPTSTR)ent->ref;
            while (ref && *ref) {
                *pes++ = *ref++;
            }
        } else {
            *pes++ = *ps;   // default character copy
        }
        ps++;
    }
    //*pes = '\0';
    
    // total copied characters
    return pes-estr;
}

axpl::ttstring
_tagXMLEntitys::Ref2Entity(LPCTSTR estr) {
    axpl::ttstring es;
    if (estr) {
        size_t len = _tcslen(estr);
        _TCHAR *buf = new _TCHAR[len];
        len = Ref2Entity(estr, buf, len);
        es.assign(buf, len);
        delete[] buf;
    }
    return es;
}

axpl::ttstring
_tagXMLEntitys::Entity2Ref(LPCTSTR str) {
    axpl::ttstring s;
    if (str) {
        size_t nEntityCount = GetEntityCount(str);
        if (nEntityCount == 0) {
            return axpl::ttstring(str);
        }
        // Expand to entity reference format, i.e. &amp; etc. Reserve a bit of room for expansion.
        size_t len = _tcslen(str) + nEntityCount*10 ;
        _TCHAR *buf = new _TCHAR[len];
        len = Entity2Ref(str, buf, len);
        s.assign(buf, len);
        delete[] buf;
    }
    return s;
}

axpl::ttstring XRef2Entity( LPCTSTR estr )
{
    return entityDefault.Ref2Entity( estr );
}

axpl::ttstring XEntity2Ref( LPCTSTR str )
{
    return entityDefault.Entity2Ref( str );
}