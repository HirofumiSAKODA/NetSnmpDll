// CmSnmpApi.cpp : 実装ファイル
//

#include "stdafx.h"
#include "CmSnmpApi.h"

// CmSnmpApi メンバー関数
// SnmpApi.cpp: CmSnmpApi クラスのインプリメンテーション
//
//////////////////////////////////////////////////////////////////////
// #include <stdafx.h>
// #include "CmSnmpApi.h"
#include "./OID.h"
// #include "../SPNMS/SPNMS.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CString ConvShortNameVarBind(CString szIn);

// CmSnmpApi

CmSnmpApi::CmSnmpApi()
{
}

CmSnmpApi::~CmSnmpApi()
{
}



//////////////////////////////////////////////////////////////////////
// 構築/消滅
//////////////////////////////////////////////////////////////////////

CmSnmpApi::CmSnmpApi()
: m_nSnmpMode(0)
, m_szPasswd(_T(""))
, m_szComOrUser(_T(""))
, m_bBulkMode(FALSE)
{
	m_wTimeOut =50;
	m_wRetry = 2;
	m_szIP.Empty();
	m_wTime = 0;
	m_wStatus = SNMP_READY;
	m_wRetCode =SNMP_NOERROR;
	m_slVarList.RemoveAll();
	m_bMIBOver = FALSE;
	m_pSnmpSession = NULL;
// YMI Added 2009.3.7
	m_szSEngID.Empty();
	m_szCEngID.Empty();
	m_nEngBoots =0;
	m_nEngTime =0;
}

CmSnmpApi::~CmSnmpApi()
{
	if( m_pSnmpSession != NULL ) {
		snmp_close(m_pSnmpSession);
		m_pSnmpSession = NULL;
	}
}


oid *CmSnmpApi::snmp_pars_oOid(char *argv,oid *root,size_t *rootlen)
{
	size_t savlen = *rootlen;
	if (read_objid(argv,root,rootlen)) {
		return root;
    }
    *rootlen = savlen;
    if (get_node(argv,root,rootlen)) {
		return root;
    }
	return NULL;
}


BOOL CmSnmpApi::SendReq()
{
	if( m_slVarList.IsEmpty() ) {
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		return FALSE;
	}
	m_wStatus = SNMP_DOING;
    struct snmp_session session;
    struct snmp_pdu *pdu;
    oid name[MAX_OID_LEN];
    size_t name_length;
    int status;
	char szIP[64];
	char szComOrUser[2560];
	char szPasswd[2560];

	m_slRet.RemoveAll();

	snmp_sess_init(&session);
    session.local_port = SNMP_DEFAULT_REMPORT;
    session.callback = ReqCallback; 
    session.callback_magic = this; 
    session.authenticator = NULL;
    session.retries = m_wRetry;	/* Number of retries before timeout. */
    session.timeout = m_wTimeOut*1000;    /* Number of uS until first timeout, then exponential backoff */
	strcpy_s(szIP,sizeof(szIP),m_szIP);
    session.peername = szIP;	/* Domain name or dotted IP address of default peer */
	m_wTime = GetTickCount();

	strcpy_s(szComOrUser,sizeof(szComOrUser),m_szComOrUser);
	strcpy_s(szPasswd,sizeof(szPasswd),m_szPasswd);
	switch (m_nSnmpMode ) {
	case SNMP_MODE_V1:
	    session.version = SNMP_VERSION_1;
	    session.community = (unsigned char*)szComOrUser;
		session.community_len = strlen(szComOrUser);
		break;
	case SNMP_MODE_V2C:
	    session.version = SNMP_VERSION_2c;
	    session.community = (unsigned char*)szComOrUser;
		session.community_len = strlen(szComOrUser);
		break;
	case SNMP_MODE_V3_MD5:
		session.version = SNMP_VERSION_3;
		session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
		session.securityAuthProto = usmHMACMD5AuthProtocol;
		session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		session.securityName = szComOrUser;
		session.securityNameLen = strlen(szComOrUser);
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityAuthKey,
                        &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		break;

	case SNMP_MODE_V3_MD5_DES:
	    session.version = SNMP_VERSION_3;
		session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		session.securityAuthProto = usmHMACMD5AuthProtocol;
		session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		session.securityPrivProto = usmDESPrivProtocol;
		session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
		session.securityName = szComOrUser;
		session.securityNameLen = strlen(szComOrUser);
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityAuthKey,
                        &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		session.securityPrivKeyLen = USM_PRIV_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityPrivKey,
                        &session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }

		break;
	// YMI Added 2009.7.31
	case SNMP_MODE_V3_SHA:
		session.version = SNMP_VERSION_3;
		session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
		session.securityAuthProto = usmHMACSHA1AuthProtocol;
		session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
		session.securityName = szComOrUser;
		session.securityNameLen = strlen(szComOrUser);
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityAuthKey,
                        &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		break;
	case SNMP_MODE_V3_SHA_AES:
	    session.version = SNMP_VERSION_3;
		session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		session.securityAuthProto = usmHMACSHA1AuthProtocol;
		session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
		session.securityPrivProto = usmAESPrivProtocol;
		session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
		session.securityName = szComOrUser;
		session.securityNameLen = strlen(szComOrUser);
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityAuthKey,
                        &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		session.securityPrivKeyLen = USM_PRIV_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityPrivKey,
                        &session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		break;
	default:
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		return FALSE;
	}
	if(session.version == SNMP_VERSION_3 ) {
		struct snmp_session *pSnmpSession; 
	    session.retries = 1;	/* Number of retries before timeout. */
		session.timeout = 100*1000;    /* Number of uS until first timeout, then exponential backoff */
		session.flags &= ~SNMP_FLAGS_DONT_PROBE; //YMI Added 2009.8.5
		pSnmpSession = snmp_open(&session);
		if( pSnmpSession == NULL ) {
			m_wRetCode = SNMP_TIMEOUT;
			m_wStatus = SNMP_DONE;
			return TRUE;
		}
		snmp_close(pSnmpSession);
		session.retries = m_wRetry;	/* Number of retries before timeout. */
	    session.timeout = m_wTimeOut*1000;    /* Number of uS until first timeout, then exponential backoff */

	}

    /* 
     * Open an SNMP session.
     */
    m_pSnmpSession = snmp_open(&session);
    if (m_pSnmpSession == NULL){
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		return FALSE;
    }
    /* 
     * Create PDU for GET request and add object names to request.
     */
	if( m_wReqType == SNMP_WALK && m_bBulkMode ) {
        pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
		pdu->non_repeaters = 0;
		pdu->max_repetitions = 4;    /* fill the packet */
	} else {
	    pdu = snmp_pdu_create(m_wReqType == SNMP_GET ? SNMP_MSG_GET: SNMP_MSG_GETNEXT);
	}

	while( !m_slVarList.IsEmpty() ) {
		CString s = m_slVarList.RemoveHead();
		char szName[1024];
		strcpy_s(szName,sizeof(szName),s);
	      name_length = MAX_OID_LEN;
		  if (!snmp_parse_oid(szName, name, &name_length)) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			snmp_free_pdu(pdu);
			snmp_close(m_pSnmpSession);
			m_pSnmpSession = NULL;
			return (FALSE);
		  } else {
			snmp_add_null_var(pdu, name, name_length);
		  }
    }

    /* 
     * Perform the request.
     *
     * If the Get Request fails, note the OID that caused the error,
     * "fix" the PDU (removing the error-prone OID) and retry.
     */
    status = snmp_async_send(m_pSnmpSession,pdu,ReqCallback,this);
	if(status == 0 &&  pdu ) snmp_free_pdu(pdu);
	return(status > 1);
}

BOOL CmSnmpApi::SendSetReq()
{
	if( m_slVarList.IsEmpty() ) {
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		return FALSE;
	}
	m_wStatus = SNMP_DOING;
    struct snmp_session session;
    struct snmp_pdu *pdu;
    oid name[MAX_OID_LEN];
    size_t name_length;
    int status;
	char szIP[64];
	char szComOrUser[2560];
	char szPasswd[2560];


	m_slRet.RemoveAll();
	snmp_sess_init(&session);
    session.local_port = SNMP_DEFAULT_REMPORT;
    session.callback = ReqCallback; 
    session.callback_magic = this; 
    session.authenticator = NULL;
    session.retries = m_wRetry;	/* Number of retries before timeout. */
    session.timeout = m_wTimeOut*1000;    /* Number of uS until first timeout, then exponential backoff */
	strcpy_s(szIP,sizeof(szIP),m_szIP);
    session.peername = szIP;	/* Domain name or dotted IP address of default peer */

	strcpy_s(szComOrUser,sizeof(szComOrUser),m_szComOrUser);
	strcpy_s(szPasswd,sizeof(szPasswd),m_szPasswd);

	switch (m_nSnmpMode ) {
	case SNMP_MODE_V1:
	    session.version = SNMP_VERSION_1;
	    session.community = (unsigned char*)szComOrUser;
		session.community_len = strlen(szComOrUser);
		break;
	case SNMP_MODE_V2C:
	    session.version = SNMP_VERSION_2c;
	    session.community = (unsigned char*)szComOrUser;
		session.community_len = strlen(szComOrUser);
		break;
	case SNMP_MODE_V3_MD5:
		session.version = SNMP_VERSION_3;
		session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
		session.securityAuthProto = usmHMACMD5AuthProtocol;
		session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		session.securityName = szComOrUser;
		session.securityNameLen = strlen(szComOrUser);
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityAuthKey,
                        &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		break;

	case SNMP_MODE_V3_MD5_DES:
	    session.version = SNMP_VERSION_3;
		session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		session.securityAuthProto = usmHMACMD5AuthProtocol;
		session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		session.securityPrivProto = usmDESPrivProtocol;
		session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
		session.securityName = szComOrUser;
		session.securityNameLen = strlen(szComOrUser);
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityAuthKey,
                        &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		session.securityPrivKeyLen = USM_PRIV_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityPrivKey,
                        &session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }

		break;
	// YMI Added 2009.7.31
	case SNMP_MODE_V3_SHA:
		session.version = SNMP_VERSION_3;
		session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
		session.securityAuthProto = usmHMACSHA1AuthProtocol;
		session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
		session.securityName = szComOrUser;
		session.securityNameLen = strlen(szComOrUser);
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityAuthKey,
                        &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		break;
	case SNMP_MODE_V3_SHA_AES:
	    session.version = SNMP_VERSION_3;
		session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		session.securityAuthProto = usmHMACSHA1AuthProtocol;
		session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
		session.securityPrivProto = usmAESPrivProtocol;
		session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
		session.securityName = szComOrUser;
		session.securityNameLen = strlen(szComOrUser);
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityAuthKey,
                        &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		session.securityPrivKeyLen = USM_PRIV_KU_LEN;
        if (generate_Ku(session.securityAuthProto,
                        session.securityAuthProtoLen,
                        (u_char *) szPasswd, strlen(szPasswd),
                        session.securityPrivKey,
                        &session.securityPrivKeyLen) != SNMPERR_SUCCESS) {
			m_wRetCode = SNMP_INTERROR;
			m_wStatus = SNMP_DONE;
			return FALSE;
        }
		break;
	default:
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		return FALSE;
	}

    /* 
     * Open an SNMP session.
     */
    m_pSnmpSession = snmp_open(&session);
    if (m_pSnmpSession == NULL){
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		return FALSE;
    }
    /* 
     * Create PDU for SET request and add object names to request.
     */
    pdu = snmp_pdu_create(SNMP_MSG_SET);
	int nVar = 0;
	while( !m_slVarList.IsEmpty() ) {
		CString s;
		CString sName;
		CString sVal;
		char cType =(char)0;
		s = m_slVarList.RemoveHead();
		int j = s.Find("=");
		if( j == -1 ) continue;
		sName = s.Left(j);
		sVal = s.Mid(j+1);
		char szName[1024];
		char szVal[2560];
		j = sName.Find(":");
		if( j != -1 ) {
			// YMI Fix Set Type 2006.4.10
			cType = (char)sName.GetAt(j+1);
			sName = sName.Left(j);
		}
		strcpy_s(szName,sizeof(szName),sName);
		strcpy_s(szVal,sizeof(szVal),sVal);
		name_length = MAX_OID_LEN;
		if (!snmp_parse_oid(szName, name, &name_length)) continue;
		j = sName.Find(".");
		if( j != -1 ) {
			sName = sName.Left(j);
		}
		strcpy_s(szName,sizeof(szName),sName);
		if( cType == (char)0 ) {
			cType = GetType(szName);
		}
		if (snmp_add_var(pdu, name, name_length, cType, szVal)) continue;
		nVar++;
    }
	if( nVar < 1 ) {
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		snmp_free_pdu(pdu);
		snmp_close(m_pSnmpSession);
		m_pSnmpSession = NULL;
		return (FALSE);
	}

    /* 
     * Perform the request.
     *
     * If the Get Request fails, note the OID that caused the error,
     * "fix" the PDU (removing the error-prone OID) and retry.
     */
    status = snmp_async_send(m_pSnmpSession,pdu,ReqCallback,this);
	if(status == 0 &&  pdu ) snmp_free_pdu(pdu);

	return(status > 1);
}


BOOL CmSnmpApi::GetReq(int nMode,CString szIP, CString szComOrUser,CString szPasswd, CString szVarList, int wTimeOut, int wRetry)
{
	if( szIP.IsEmpty() ||	szVarList.IsEmpty() ) return(FALSE);
	m_szIP = szIP;
	m_wTimeOut = wTimeOut*1000;
	m_wRetry = wRetry;
	m_szComOrUser = szComOrUser;
	m_nSnmpMode = nMode;
	m_szPasswd = szPasswd;
	m_bBulkMode = FALSE;
	m_wReqType = SNMP_GET;
	SetVarList(szVarList,"\t \n\r");
	return(SendReq());


}

BOOL CmSnmpApi::GetNextReq(int nMode,CString szIP, CString szComOrUser,CString szPasswd, CString szVarList, int wTimeOut, int wRetry)
{
	if( szIP.IsEmpty() ||	szVarList.IsEmpty() ) return(FALSE);
	m_szIP = szIP;
	m_wTimeOut = wTimeOut*1000;
	m_wRetry = wRetry;
	m_szComOrUser = szComOrUser;
	m_nSnmpMode = nMode;
	m_szPasswd = szPasswd;
	m_wReqType = SNMP_GETNEXT;
	m_bBulkMode = FALSE;

	SetVarList(szVarList,"\t \n\r");
	return(SendReq());

}



BOOL CmSnmpApi::Walk(int nMode,CString szIP, CString szComOrUser,CString szPasswd, CString szVarList,BOOL bBulkMode, int wTimeOut, int wRetry)
{
	if( szIP.IsEmpty() ||	szVarList.IsEmpty() ) return(FALSE);
	m_bMIBOver = FALSE;
	if ( nMode >= SNMP_MODE_V2C)  {
		m_bBulkMode = bBulkMode;
	} else {
		m_bBulkMode = FALSE;
	}
	m_szIP = szIP;
	m_wTimeOut = wTimeOut*1000;
	m_wRetry = wRetry;
	m_szComOrUser = szComOrUser;
	m_nSnmpMode = nMode;
	m_szPasswd = szPasswd;
	m_wReqType = SNMP_WALK;

	SetVarList(szVarList,"\t \n\r");
	if( m_slVarList.IsEmpty() ) return(FALSE);
	CString szRootOID = m_slVarList.GetHead();
	if( m_bBulkMode) {
		while( m_slVarList.GetCount() > 1 ) {
			m_slVarList.RemoveTail();
		}
	}
	m_nRootOIDLen  = MAX_OID_LEN;
	snmp_parse_oid(szRootOID,m_RootOID, &m_nRootOIDLen);
	return(SendReq());
}

char CmSnmpApi::GetType(char *szName) 
{
	struct tree *tp;
	tp= get_tree_head();
	tp = find_node(szName,tp);
	if( tp == NULL ) return ' ';
	CString typ;
    switch (tp->type) {
    case TYPE_OBJID:		return('o');
    case TYPE_OCTETSTR:		return('s');
    case TYPE_INTEGER:		return('i');
    case TYPE_NETADDR:		return('x');
    case TYPE_IPADDR:		return('a');
    case TYPE_COUNTER:		return('u');
    case TYPE_GAUGE:		return('u');
    case TYPE_TIMETICKS:	return('t');
    case TYPE_UINTEGER:		return('u');
	case TYPE_UNSIGNED32:   return('u');
	case TYPE_INTEGER32:    return('i');

    default:			    return('s');
    }
	return(' ');
}



BOOL CmSnmpApi::SetReq(int nMode,CString szIP, CString szComOrUser,CString szPasswd, CString szVarList, int wTimeOut, int wRetry)
{
	if( szIP.IsEmpty() ||	szVarList.IsEmpty() ) return(FALSE);
	m_szIP = szIP;
	m_wTimeOut = wTimeOut*1000;
	m_wRetry = wRetry;
	m_szComOrUser = szComOrUser;
	m_nSnmpMode = nMode;
	m_szPasswd = szPasswd;
	m_wReqType = SNMP_SET;
	m_bBulkMode = FALSE;
	SetVarList(szVarList,"\t\n\r");
	return(SendSetReq());
	return(TRUE);

}


void CmSnmpApi::ClearReq()
{
	m_wTimeOut =50;
	m_wRetry = 3;
	m_szIP ="";
	m_wTime = 0;
	m_wStatus = SNMP_READY;
	m_wRetCode = SNMP_NOERROR;
	m_TrapList.RemoveAll();
	m_slRet.RemoveAll();
	if( m_pSnmpSession != NULL ) {
		snmp_close(m_pSnmpSession);
		m_pSnmpSession = NULL;
	}

}

void CmSnmpApi::SetVarList(CString & szVarList,CString szSep)
{
	CString szTmp;
	szTmp = szVarList;
	szTmp.TrimLeft();
	szTmp.TrimRight();
	int i;
	m_slVarList.RemoveAll();
	i = szTmp.FindOneOf(szSep);
	while( i != -1 ) {
		CString s;
		s = szTmp.Left(i);
		szTmp = szTmp.Mid(i+1);
		szTmp.TrimLeft();
		szTmp.TrimRight();
		if( !szTmp.IsEmpty() ) {
			m_slVarList.AddTail(s);
		}
		i = szTmp.FindOneOf(szSep);
	}
	if( !szTmp.IsEmpty() ) {
		m_slVarList.AddTail(szTmp);
	}
}


/* Call Back of SNMP Req */
int CmSnmpApi::ReqCallback(int op,struct snmp_session *session,int reqid,struct snmp_pdu *pdu,void *magic)
{
    CmSnmpApi* p = (CmSnmpApi*)magic;
	if( p == 0 ) return(1);
    struct variable_list *vars;
	char szTmp[2048];
//	char szName[1024];
	switch (op ) {
		case  NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
			{
				if( pdu->command == SNMP_MSG_REPORT ) return(1); // SNMPv3のエンジン検索を無視する。
				if (pdu->errstat == SNMP_ERR_NOERROR){
					if( p->m_wReqType == SNMP_WALK ) {
						if( p->m_bBulkMode ) {
							struct variable_list *last_vars=NULL;
							for( vars = pdu->variables;vars;vars = vars->next_variable) {
								if( ( vars->type != SNMP_ENDOFMIBVIEW) &&
									(vars->type != SNMP_NOSUCHOBJECT) &&
									(vars->type != SNMP_NOSUCHINSTANCE)) {
										snprint_variable(szTmp,sizeof(szTmp),vars->name, vars->name_length, vars);
										ConvKanjiCode(vars,szTmp,sizeof(szTmp));
										if( netsnmp_oid_is_subtree(p->m_RootOID,p->m_nRootOIDLen,vars->name,vars->name_length) ==0  ) {
											p->m_slRet.AddTail(p->GetVBStr(szTmp,vars->type == ASN_OBJECT_ID));
											last_vars = vars;
										}
								}
							}
							if( last_vars ) {
								netsnmp_pdu *npdu = snmp_pdu_create(SNMP_MSG_GETBULK);
								if( npdu ) {
									npdu->non_repeaters = 0;
									npdu->max_repetitions = 4;    /* fill the packet */
									snmp_add_null_var(npdu, last_vars->name, last_vars->name_length);
									if( snmp_async_send(session,npdu,ReqCallback,p) > 1) {
										return(1);
									}
								}
							} else {
								if( !p->m_slRet.IsEmpty() ) {
									p->m_wRetCode = SNMP_NOERROR;
								} else {
									p->m_wRetCode = SNMP_NOSUCHNAME;
								}
								p->m_wStatus = SNMP_DONE;
							}
						} else {
							struct variable_list *last_vars=NULL;
							for( vars = pdu->variables;vars;vars = vars->next_variable) {
								if( ( vars->type != SNMP_ENDOFMIBVIEW) &&
									(vars->type != SNMP_NOSUCHOBJECT) &&
									(vars->type != SNMP_NOSUCHINSTANCE)) {
										snprint_variable(szTmp,sizeof(szTmp),vars->name, vars->name_length, vars);
										ConvKanjiCode(vars,szTmp,sizeof(szTmp));
										if( vars == pdu->variables ) {
											if( netsnmp_oid_is_subtree(p->m_RootOID,p->m_nRootOIDLen,vars->name,vars->name_length) ==0  ) {
												p->m_slRet.AddTail(p->GetVBStr(szTmp,vars->type == ASN_OBJECT_ID));
												last_vars = vars;
											}
										} else if( last_vars) {
											p->m_slRet.AddTail(p->GetVBStr(szTmp,vars->type == ASN_OBJECT_ID));
										}
								}
							}
							if( last_vars ) {
								netsnmp_pdu *npdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
								if( npdu ) {
									for( vars = pdu->variables;vars;vars = vars->next_variable) {
										snmp_add_null_var(npdu, vars->name, vars->name_length);
									}
									if( snmp_async_send(session,npdu,ReqCallback,p) > 1) {
										return(1);
									}
								}
							} 
							if( !p->m_slRet.IsEmpty() ) {
								p->m_wRetCode = SNMP_NOERROR;
							} else {
								p->m_wRetCode = SNMP_NOSUCHNAME;
							}
							p->m_wStatus = SNMP_DONE;
						}
					} else {
						for(vars = pdu->variables; vars; vars = vars->next_variable){
							snprint_variable(szTmp,sizeof(szTmp),vars->name, vars->name_length, vars);
							ConvKanjiCode(vars,szTmp,sizeof(szTmp));
							p->m_slRet.AddTail(p->GetVBStr(szTmp,vars->type == ASN_OBJECT_ID));
						}
						p->m_wRetCode = SNMP_NOERROR;
						p->m_wStatus = SNMP_DONE;
					}
					if( session->version== SNMP_VERSION_3){
						p->GetSnmpV3Info(session);
					}
				} else {
					if (pdu->errstat < 5){
						p->m_wRetCode = pdu->errstat;
						p->m_wStatus = SNMP_DONE;
					} else {
						p->m_wRetCode = SNMP_GENERROR;
						p->m_wStatus = SNMP_DONE;
					}
				}  /* endif -- SNMP_ERR_NOERROR */
			}
			break;
		case NETSNMP_CALLBACK_OP_TIMED_OUT:
			p->m_wRetCode = SNMP_TIMEOUT;
			p->m_wStatus = SNMP_DONE;
			break;
		case NETSNMP_CALLBACK_OP_SEND_FAILED:
			p->m_wRetCode = SNMP_TIMEOUT;
			p->m_wStatus = SNMP_DONE;
			break;
		default:
			p->m_wRetCode = SNMP_INTERROR;
			p->m_wStatus = SNMP_DONE;
			break;
	}
	if( p->m_wStatus==SNMP_DONE) {
		p->m_wTime = GetTickCount() -p->m_wTime;
	}
	return 1;
}



// TRAP受信の都度 callback される。
int CmSnmpApi::TrapRcv(int op,struct snmp_session *session,int reqid,struct snmp_pdu *pdu,void *magic)
{
    using namespace msnmp;

    struct variable_list *vars;
    char oid_buf [SPRINT_MAX_LEN];
	CString szTrap;
	char szTmp[2048];
	char szAgentIP[32];
	szTrap.Empty();
	if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE){
		if (pdu->command == SNMP_MSG_TRAP){
			oid stdTrapOidRoot[] = { 1, 3, 6, 1, 6, 3, 1, 1, 5 };
			oid snmpTrapOid[]    = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
			oid trapOid[MAX_OID_LEN+2] = {0};
			int trapOidLen;
			char szAgentIP[32];

		sprintf_s(szAgentIP,sizeof(szAgentIP),"%d.%d.%d.%d"
				,pdu->agent_addr[0]
				,pdu->agent_addr[1]
				,pdu->agent_addr[2]
				,pdu->agent_addr[3]);
			/*
			* Convert v1 traps into a v2-style trap OID
			*    (following RFC 2576)
			*/
			if (pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC) { // Generic:6
				trapOidLen = pdu->enterprise_length;
				memcpy(trapOid, pdu->enterprise, sizeof(oid) * trapOidLen);
				if (trapOid[trapOidLen - 1] != 0) {
					trapOid[trapOidLen++] = 0;
				}
				trapOid[trapOidLen++] = pdu->specific_type;
			} else {
				memcpy(trapOid, stdTrapOidRoot, sizeof(stdTrapOidRoot));
				trapOidLen = OID_LENGTH(stdTrapOidRoot);  /* 9 */
				trapOid[trapOidLen++] = pdu->trap_type+1; // Generic:7
			}


			snprint_objid (oid_buf,sizeof(oid_buf), trapOid, trapOidLen);

			CString szTrapOid = oid_buf;
			szTrapOid = CmSnmpApi::GetShortName(szTrapOid);
			szTrap.Format("%s\t sysUpTime.0 =  %u\t  snmpTrapOID.0 = %s",
				szAgentIP,
				pdu->time,
				szTrapOid);
			for(vars = pdu->variables; vars; vars = vars->next_variable) {
				snprint_variable(szTmp,sizeof(szTmp),vars->name, vars->name_length, vars);
				ConvKanjiCode(vars,szTmp,sizeof(szTmp));
				szTrap +="\t  ";
				CString s = CmSnmpApi::ConvShortNameVarBind(szTmp);
				if( s.Find("Hex-") !=-1 ){ 
					s.Replace("\n"," ");
					s.Replace("\r"," ");
					s.Replace("\t"," ");
				}
				szTrap += s;
			}
		} else if (pdu->command == SNMP_MSG_TRAP2 || pdu->command == SNMP_MSG_INFORM ){
			void *ps = snmp_sess_pointer(session);
			strcpy_s(szAgentIP,sizeof(szAgentIP),"0.0.0.0");
			if( ps != NULL ) {
				struct netsnmp_transport_s  *t = snmp_sess_transport(ps);
				if( t != NULL ) {
					char *p = t->f_fmtaddr(t,pdu->transport_data,pdu->transport_data_length);
					if( p ){
						strcpy_s(szAgentIP,sizeof(szAgentIP),p);
						free(p);
					}
				}
			}
			szTrap.Format("%s",
				szAgentIP);
			// YMI Fix 2008.9.13
			int j = szTrap.Find("[");
			if( j != -1 ) 	szTrap = szTrap.Mid(j+1);
			j = szTrap.Find("]");
			if( j != -1 ) szTrap = szTrap.Left(j); 
			szTrap.Trim();
			// Cut UDP:[xxx.xxx.xxx.xxx]:
			if( session->s_snmp_errno == SNMPERR_USM_AUTHENTICATIONFAILURE) {
				szTrap += "\tSNMPv3認証エラー";
			}
			for (vars = pdu->variables; vars; vars = vars->next_variable) {
				snprint_variable(szTmp,sizeof(szTmp),vars->name, vars->name_length, vars);
				ConvKanjiCode(vars,szTmp,sizeof(szTmp));
				szTrap +="\t  ";
				CString s = CmSnmpApi::ConvShortNameVarBind(szTmp);
				if( s.Find("Hex-") !=-1 ){ 
					s.Replace("\n"," ");
					s.Replace("\r"," ");
					s.Replace("\t"," ");
				}
				szTrap += s;
			}
			if (pdu->command == SNMP_MSG_INFORM) {
				netsnmp_pdu *reply = snmp_clone_pdu(pdu);
				if (reply != NULL) {
					reply->command = SNMP_MSG_RESPONSE;
					reply->errstat = 0;
					reply->errindex = 0;
					if (!snmp_send(session, reply)) {
						snmp_free_pdu(reply);
					}
				}
			}

		}
	}
	if( magic && !szTrap.IsEmpty() ) {
		CmSnmpApi *p = (CmSnmpApi*) magic;
        CSingleLock syncObj(&(p->m_TrapSema));
        syncObj.Lock();
		p->m_TrapList.AddTail(szTrap);
        syncObj.Unlock();
        // @@@  MainLoop 内の Lock を解除する。
        CSPNMSApp *ap = (CSPNMSApp*) AfxGetApp();
        ap->m_pTrapRecvThead->Event->SetEvent();
	}
	return 1;
}




BOOL CmSnmpApi::StartTrapRcv(int wPort)
{
	char szIP[64];
	m_TrapList.RemoveAll();
	m_wStatus = SNMP_RCVTRAP;
	m_wTrapPort = wPort;
    struct snmp_session session;

	sprintf_s(szIP,sizeof(szIP),"0.0.0.0:%d",wPort);
    memset(&session, 0, sizeof(struct snmp_session));
    session.peername = szIP;
    session.version = SNMP_DEFAULT_VERSION;
    session.community_len = SNMP_DEFAULT_COMMUNITY_LEN;
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;  
    session.local_port = m_wTrapPort;
    session.callback = TrapRcv; 
    session.callback_magic = this; 
    session.authenticator = NULL;
    session.isAuthoritative = SNMP_SESS_UNKNOWNAUTH;

    /* 
     * Open an SNMP session.
     */
    m_pSnmpSession = snmp_open(&session);
    if (m_pSnmpSession == NULL){
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		return (FALSE);
    }

	return( TRUE);
}

BOOL CmSnmpApi::CheckRcv()
{
    int count, numfds;
    fd_set fdset;
	struct timeval timeout, *tvp;
  	int block =0;
	numfds = 0;
	FD_ZERO(&fdset);
	tvp = &timeout;
	timerclear(tvp);
	tvp->tv_usec = 100;
	snmp_select_info(&numfds, &fdset, tvp, &block);
	count = select(numfds, &fdset, 0, 0, tvp);
	if (count > 0){
		snmp_read(&fdset);
	} else  if (count == 0 ) {
		snmp_timeout();
	} else {
		/* This is Internal Error */
		return(FALSE);
	}
	return(TRUE);
 }

int CmSnmpApi::GetSesCount(void)
{
    int numfds;
    fd_set fdset;
	struct timeval timeout, *tvp;
  	int block =0;
	int nActive;
	numfds = 0;
	FD_ZERO(&fdset);
	tvp = &timeout;
	timerclear(tvp);
	tvp->tv_usec = 100;
	nActive = snmp_select_info(&numfds, &fdset, tvp, &block);
	return(nActive);
 }


int CmSnmpApi::GetSessSock()
{
	void *ps =snmp_sess_pointer(m_pSnmpSession);
	if( ps == NULL ) return(-1);
	netsnmp_transport *pt = snmp_sess_transport(ps);
	if( pt == NULL) return(-1);
	return(pt->sock);
}

CString CmSnmpApi::GetTrap()
{
	if( m_TrapList.IsEmpty() ) return("");
	return(m_TrapList.RemoveHead());
}





BOOL CmSnmpApi::SendTrap(CString szIP, CString szCom, CString szEID, CString szVarList, int wGen, int wSpe)
{
    struct snmp_session session;
    struct snmp_pdu *pdu;
    oid name[MAX_OID_LEN];
    size_t name_length;
	char szTrapIP[128];
	char szComTrap[2560];
	if( szIP.IsEmpty() ||
		szCom.IsEmpty() ||
		szEID.IsEmpty() ) return(FALSE);
	m_szIP = szIP;
	SetVarList(szVarList,"\t\n\r");
	snmp_sess_init( &session );
    session.version =SNMP_VERSION_1;
    session.retries = 1;	/* Number of retries before timeout. */
    session.timeout = 1000;    /* Number of uS until first timeout, then exponential backoff */
	strcpy_s(szTrapIP,sizeof(szTrapIP),m_szIP);
    session.peername = szTrapIP;	/* Domain name or dotted IP address of default peer */
	session.remote_port = SNMP_TRAP_PORT;
	strcpy_s(szComTrap,sizeof(szComTrap),szCom);
    session.community = (unsigned char*)szComTrap;	        /* community for outgoing requests. */
    session.community_len = szCom.GetLength();      /* Length of community name. */
	
													/* 
													* Open an SNMP session.
	*/
    m_pSnmpSession = (struct snmp_session *)snmp_open(&session);
    if (m_pSnmpSession == NULL){
		m_wRetCode = SNMP_INTERROR;
		m_wStatus = SNMP_DONE;
		return (FALSE);
    }
	m_slRet.RemoveAll();
    /* 
	* Create PDU for GET request and add object names to request.
	*/
    pdu = snmp_pdu_create(SNMP_MSG_TRAP);
	while( !m_slVarList.IsEmpty() ) {
		CString s;
		CString sName;
		CString sVal;
		char cType;
		s = m_slVarList.RemoveHead();
		int j = s.Find("=");
		if( j == -1 ) continue;
		sName = s.Left(j);
		sVal = s.Mid(j+1);
		char szName[1024];
		char szVal[2560];
		strcpy_s(szName,sizeof(szName),sName);
		strcpy_s(szVal,sizeof(szVal),sVal);
		name_length = MAX_OID_LEN;
		if (!snmp_parse_oid(szName, name, &name_length)) continue;
		j = sName.Find(".");
		if( j != -1 ) {
			sName = sName.Left(j);
		}
		strcpy_s(szName,sizeof(szName),sName);
		cType = GetType(szName);
		if (snmp_add_var(pdu, name, name_length, cType, szVal)) continue;
    }
    struct sockaddr_in *pduIp;
	pduIp = (struct sockaddr_in *)&pdu->agent_addr;
    name_length = MAX_OID_LEN;
    if (!snmp_parse_oid(szEID, name, &name_length)) {
		return(FALSE);
    }
    pdu->enterprise = (oid *)malloc(name_length * sizeof(oid));
    memcpy(pdu->enterprise, name, name_length * sizeof(oid));
    pdu->enterprise_length = name_length;
	pduIp->sin_family = AF_INET;
	pduIp->sin_addr.s_addr = get_myaddr();
	pdu->trap_type = wGen;
	pdu->specific_type = wSpe;
    pdu->time = get_uptime();
	
	BOOL bRet = (snmp_send(m_pSnmpSession, pdu) != 0);
	snmp_close(m_pSnmpSession);
	return(bRet);
}

int CmSnmpApi::CmpOidByName(CString szName1, CString szName2)
{
	char szName[1024];
    oid name1[MAX_OID_LEN];
    size_t name1_length;
    oid name2[MAX_OID_LEN];
    size_t name2_length;
	strcpy_s(szName,sizeof(szName),szName1);
	name1_length = MAX_OID_LEN;
	if (!snmp_parse_oid(szName, name1, &name1_length)) {
		return(-1);
	}
	strcpy_s(szName,sizeof(szName),szName2);
	name2_length = MAX_OID_LEN;
	if (!snmp_parse_oid(szName, name2, &name2_length)) {
		return(1);
	}
	return(snmp_oid_compare(name1,name1_length,name2,name2_length));
}




void CmSnmpApi::StopTrapRcv()
{
	if( m_pSnmpSession != NULL ) {
		snmp_close(m_pSnmpSession);
		m_pSnmpSession = NULL;
	}
	m_wStatus = SNMP_DONE;
	m_wTrapPort = 0;
}

static UINT_PTR nIDTimer =0;

// 
void CmSnmpApi::InitSnmpApi(CString szType, CString szBaseDir, CString szLogFile)
{
	CString szTmpDir;
	CString szConfDir;
	CString szMibDir;
	szTmpDir.Format("%s\\Tmp",szBaseDir);
	szConfDir.Format("%s\\Config",szBaseDir);
	szMibDir.Format("%s\\Mibs",szBaseDir);
	CString s;
	s.Format("MIBDIRS=%s",szMibDir);
	_putenv(s);
	s.Format("MIBS=ALL");
	_putenv(s);
	s.Format("SNMPCONFPATH=%s;%s",szConfDir,szTmpDir);
	_putenv(s);

//	s.Format("SNMP_PERSISTENT_FILE=%s\\%s.conf",szConfDir,szType);
//	s.Replace("\\Config","\\Tmp");
//	_putenv(s);

	s.Format("SNMP_PERSISTENT_DIR=%s",szTmpDir);
	_putenv(s);
	char  szType2[2560];
	strcpy_s(szType2,sizeof(szType2),szType);
    netsnmp_ds_toggle_boolean(NETSNMP_DS_LIBRARY_ID, 
					  NETSNMP_DS_LIB_SAVE_MIB_DESCRS);
    netsnmp_ds_toggle_boolean(NETSNMP_DS_LIBRARY_ID, 
					  NETSNMP_DS_LIB_MIB_REPLACE);
/*    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, 
		NETSNMP_DS_LIB_QUICKE_PRINT, 1);
    netsnmp_ds_toggle_boolean(NETSNMP_DS_LIBRARY_ID, 
		NETSNMP_DS_LIB_QUICK_PRINT);*/

    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, 
		NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,NETSNMP_OID_OUTPUT_SUFFIX);

// YMI Added 2007.1.19
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,NETSNMP_DS_LIB_DONT_BREAKDOWN_OIDS,1);

	init_usm_conf(szType2); //YMI Added 2008.10.3
    init_snmp(szType2);
#ifdef _DEBUG
	snmp_disable_log();
//	snmp_enable_syslog();
	szLogFile="c:\test.log";
	if( !szLogFile.IsEmpty() ) {
		snmp_enable_filelog(szLogFile,1);
	}
#endif
    UINT nTime = 1;
	nIDTimer = ::SetTimer(NULL,123,nTime,TimerCallBack);


}

void CmSnmpApi::LoadMIB(CString szLogFile,CString szMibDescr)
{
	shutdown_mib();
	if( !szLogFile.IsEmpty() ) {
		snmp_enable_filelog(szLogFile,0);
	}
	init_mib();
	snmp_disable_filelog();
	if( !szMibDescr.IsEmpty() ) {
		FindMibDescr(szMibDescr);
	}
	return;
}


void CALLBACK CmSnmpApi::TimerCallBack(HWND hWnd,UINT uMsg,UINT_PTR idEvent,DWORD dwTime)
{
	CheckRcv();
}


void CmSnmpApi::CloseSnmpApi(CString szType)
{
	::KillTimer(NULL,nIDTimer);
	snmp_shutdown(szType);
}

CString CmSnmpApi::GetMibVal(CString &szIn, CString szMib)
{
	CString s1 = szMib+_T(" ");
	CString s2 = szMib+_T("=");
	int i = szIn.Find(s1);
	if( i == -1 ) {
		i = szIn.Find(s2);
		if( i == -1 ) {
// YMI 2010.5.16 Fix sysUpTime.0が
			if( szMib.Find("sysUpTime.0") != -1 ) {
				return(GetMibVal(szIn,"sysUpTimeInstance"));
			}
			return("");
		}
	}
	CString szTmp = szIn.Mid(i);
//	i = szTmp.Find("\n");  
	i = szTmp.FindOneOf("\n\t"); // YMI Fix 2005.1.19
	if( i != -1 ) {
		szTmp = szTmp.Left(i);
	}
	i = szTmp.Find("=");
	if( i == -1 ) return("");
	szTmp = szTmp.Mid(i+1);
	szTmp.TrimLeft();
	i = szTmp.Find(":");
	if( i != -1 ){
		szTmp = szTmp.Mid(i+1);
		szTmp.TrimLeft();
	}

	i = szTmp.Find("\"");
	if( i != -1 ){
		szTmp = szTmp.Mid(i+1);
		i = szTmp.Find("\"");
		if( i == -1 ) return(szTmp);
		return( szTmp.Left(i));
	}
	i = szTmp.Find("\t");
	if( i != -1 ) {
		szTmp= szTmp.Left(i);
	}
	szTmp.TrimLeft();
	szTmp.TrimRight();
	return(szTmp);
}

int CmSnmpApi::GetIntMibVal(CString &szVal)
{
	int i;
	CString s;
	s = szVal;
	i = s.Find(")");
	if( i != -1 ) s = s.Left(i);
	i = s.Find(":");
	if( i != -1 )  s = s.Mid(i+1);
	i = s.Find("(");
	if(i != -1 ){
		s = s.Mid(i+1);
	}
	s.TrimLeft();
	s.TrimRight();
	if( isdigit(s.GetAt(0)) || s.GetAt(0) == '+' || s.GetAt(0) == '-')  {
		DWORD nRet = (DWORD)atoi(s);
		if( errno == ERANGE) {
			nRet = (DWORD) _atoi64(s);
		}
		return((int)nRet);
	} 
	return(0);
}

int CmSnmpApi::GetIntMibVal(CString &szIn, CString szMib)
{
	CString szVal;
	szVal = GetMibVal(szIn,szMib);
	return(GetIntMibVal(szVal));
}

int CmSnmpApi::GetSocket(void)
{
	int nSock = -1;
	struct netsnmp_transport_s * pST;
	if( m_pSnmpSession == NULL ) return(-1);
	pST =	snmp_sess_transport(snmp_sess_pointer(this->m_pSnmpSession));
	if( pST == NULL ) return(-1);
	return( pST->sock);
}

// MIB name 込みの OID文字列(C言語型)を、全て数字形式OID(CString型)に変換する。
CString CmSnmpApi::GetOid(char *pLabel)
{
    oid name[MAX_OID_LEN];
    size_t name_length = MAX_OID_LEN;
    if (!snmp_parse_oid(pLabel, name, &name_length)) {
		return("UnknownOID");
	}
	CString szRet ="";
	unsigned int i;
	for(i = 0;i < name_length;i++ ){
		CString s;
		s.Format("%u",name[i]);
		if( !szRet.IsEmpty()) szRet+=".";
		szRet += s;
	}
	return(szRet);

}

CString CmSnmpApi::GetShortName(CString &szIn)
{
	CString szTmp;
	CString szLast;
	int i = szIn.Find("=");
	if( i == -1 ) {
		szTmp = szIn;
	} else {
		szTmp = szIn.Left(i);
	}
	i = szTmp.ReverseFind(':');
	if( i != -1 ) {
		szTmp = szTmp.Mid(i+1);
	}
	i = szTmp.Find(".");
	szLast.Empty();
	while( i != -1  && !isdigit(szTmp.GetAt(i+1)) && (szTmp.GetAt(i+1) != '\"')  ) {
		szLast = szTmp.Left(i);
		szTmp = szTmp.Mid(i+1);
		i = szTmp.Find(".");
	}
	if( i == -1  && !szLast.IsEmpty() ) {
		CString s;
		s.Format("%s.%s",szLast,szTmp);
		szTmp  = s;
	}
	szTmp.TrimLeft();
	szTmp.TrimRight();
	return(szTmp);

}

double CmSnmpApi::GetDoubleMibVal(CString &szVal)
{
	int i = szVal.Find("(");
	if(i == -1 ) return(atof(szVal));
	CString s = szVal.Mid(i+1);
	i = s.Find(")");
	if( i == -1 ) return(atof(s));
	s = s.Left(i);
	return(atof(s));
}

double CmSnmpApi::GetDoubleMibVal(CString &szIn, CString szMib)
{
	CString szVal;
	szVal = GetMibVal(szIn,szMib);
	return(GetDoubleMibVal(szVal));

}

CString CmSnmpApi::GetIPAddr(CString &szIPList, CString szIndex)
{
	CString s1;
	CString s2;
	CString szID;
	int nIndex = atoi(szIndex);
	s1 = szIPList;
	int i = s1.Find("\n");
	while (i != -1 ) {
		s2 = s1.Left(i);
		int j = s2.Find("=");
		if( j != -1 ) {
			szID = s2.Mid(j+1);
			szID.TrimRight();
			szID.TrimLeft();
			if (GetIntMibVal(szID)  == nIndex ) {
				s2 = GetShortName(s2);
				j = s2.Find(".");
				if( j != -1 ) {
					s2 = s2.Mid(j+1);
					s2.Trim();
					return(s2);
				}
			}
		}
		s1 = s1.Mid(i+1);
		i = s1.Find("\n");
	}
	return("");
}

int CmSnmpApi::GetIndexList(CString &szIn, CString szMib, CStringList &slIndex)
{
	slIndex.RemoveAll();
	szMib.TrimLeft();
	szMib.TrimRight();
	if( szMib.IsEmpty() )return(0);
	int i = szMib.Find(".");
	if( i == -1 ) szMib += ".";
	i = szIn.Find(szMib);
	while( i != -1 ) {
		int j,k;
		j = szIn.Find(".",i);
		if ( j != -1 ) {
			k = szIn.Find("=",i);
			if( k != -1  && k > j) {
				CString szIndex = szIn.Mid(j+1,k-j-1);
				szIndex.TrimLeft();
				szIndex.TrimRight();
				slIndex.AddTail(szIndex);
			}
		}
		i = szIn.Find(szMib,i+1);
	}
	return(slIndex.GetCount());
}

CString CmSnmpApi::GetTypeName(int wType)
{
	CString cp;
	switch (wType) {
        case TYPE_TRAPTYPE:
            cp = " TRAP-TYPE";
            break;
        case TYPE_NOTIFTYPE:
            cp = " NOTIFICATION-TYPE";
            break;
        case TYPE_OBJGROUP:
            cp = " OBJECT-GROUP";
            break;
        case TYPE_AGENTCAP:
            cp = " AGENT-CAPABILITIES";
            break;
        case TYPE_MODID:
            cp = " MODULE-IDENTITY";
            break;
        case TYPE_MODCOMP:
            cp = " MODULE-COMPLIANCE";
            break;
		case TYPE_OBJID:
			cp = "OBJECT IDENTIFIER";
			break;
		case TYPE_OCTETSTR:
			cp = "OCTET STRING";
			break;
		case TYPE_INTEGER:
			cp = "INTEGER";
			break;
		case TYPE_NETADDR:
			cp = "NetworkAddress";
			break;
		case TYPE_IPADDR:
			cp = "IpAddress";
			break;
		case TYPE_COUNTER:
			cp = "Counter32";
			break;
		case TYPE_GAUGE:
			cp = "Gauge32";
			break;
		case TYPE_TIMETICKS:
			cp = "TimeTicks";
			break;
		case TYPE_OPAQUE:
			cp = "Opaque";
			break;
		case TYPE_NULL:
			cp = "NULL";
			break;
		case TYPE_COUNTER64:
			cp = "Counter64";
			break;
		case TYPE_BITSTRING:
			cp = "BITS";
			break;
		case TYPE_NSAPADDRESS:
			cp = "NsapAddress";
			break;
		case TYPE_UINTEGER:
			cp = "UInteger32";
			break;
		case TYPE_UNSIGNED32:
			cp = "Unsigned32";
			break;
		case TYPE_INTEGER32:
			cp = "Integer32";
			break;
		default:
			cp = "TREE";
			break;
	}
	return(cp);


}


CString CmSnmpApi::ConvShortNameVarBind(CString szIn)
{
	CString szName;
	CString szVal;
	CString szRet;
	int i = szIn.Find("=");
	if( i == -1 ) {
		szName = szIn;
		szVal = "";
	} else {
		szName = szIn.Left(i);
		szVal = szIn.Mid(i);
	}
	szName = GetShortName(szName);
	szRet.Format("%s %s",szName,szVal);
	return(szRet);

}

CString CmSnmpApi::GetTrapDescr(int wTrap)
{
    switch(wTrap){
	case SNMP_TRAP_COLDSTART:
	    return "Cold Start";
	case SNMP_TRAP_WARMSTART:
	    return "Warm Start";
	case SNMP_TRAP_LINKDOWN:
	    return "Link Down";
	case SNMP_TRAP_LINKUP:
	    return "Link Up";
	case SNMP_TRAP_AUTHFAIL:
	    return "Authentication Failure";
	case SNMP_TRAP_EGPNEIGHBORLOSS:
	    return "EGP Neighbor Loss";
	case SNMP_TRAP_ENTERPRISESPECIFIC:
	    return "Enterprise Specific";
	default:
	    return "Unknown Type";
    }

}

CString CmSnmpApi::GetSubTree(tree *tree)
{
    struct tree *tp;
	CString szRet;
	CString s;
	s.Format("%s\t%s\t%s\n",tree->label, GetOid(tree->label),GetTypeName(tree->type));
	szRet = s;
	int i, j, count = 0;
    struct leave {
      u_long id;
      struct tree *tp;
    } *leaves, *lp;
    for(tp = tree->child_list,count =0; tp; tp = tp->next_peer) count++;
    if (count) {
		leaves = (struct leave *)calloc(count, sizeof(struct leave));
		for (tp = tree->child_list, count = 0; tp; tp = tp->next_peer) {
			for (i = 0, lp = leaves; i < count; i++, lp++) 
				if (lp->id >= tp->subid) break;
			for (j = count; j > i; j--) leaves[j] = leaves[j-1];
			lp->id = tp->subid;
			lp->tp = tp;
			count++;
		}
		for (i = 1, lp = leaves; i <= count; i++, lp++) {
	        szRet+= GetSubTree(lp->tp);
		}
		free(leaves);
    }
	return(szRet);
}

CString CmSnmpApi::GetVBStr(char *p,BOOL bOid)
{
	CString szRet;
	szRet.Empty();
	if( p == NULL ) return(szRet);
	int len = strlen(p);
	if( len < 1 ) return(szRet);
	int i;
	for(i = 0;i < len;i++ ) {
		if( p[i] < ' ' && p[i] >= 0 ) p[i]= ' ';
	}
	CString szName =p;
	szName = GetShortName(szName);
    CString szVal = p;
	i = szVal.Find("=");
	if( i == -1 ) return(szRet);
	if( isdigit(szName.GetAt(0)) ) szName = _T("mib_2.") + szName;
	szVal = szVal.Mid(i+1);
	if( bOid ) {
		szVal = GetShortName(szVal);
	}
	szVal.Trim();
	szName.Trim();
	szRet.Format("%s=%s",szName,szVal);
	return(szRet);

}	

CString CmSnmpApi::GetRetStr()
{
	CString szRet;
	szRet.Empty();
	POSITION pos = m_slRet.GetHeadPosition();
	while(pos) {
		szRet += m_slRet.GetNext(pos);
		szRet += "\n";
	}
	return(szRet);

}


void CmSnmpApi::FindMibDescr(CString szPath)
{
	CFileFind ff;
	CString szFind;
	szFind.Format("%s\\*.txt",szPath);
	BOOL bWk = ff.FindFile(szFind);
	while( bWk ) {
		bWk = ff.FindNextFile();
		if( ff.IsDirectory() ) continue;
		if( ff.IsDots() ) continue;
		if( ff.IsCompressed() ) continue;
		CString szFile =ff.GetFilePath(); 
		LoadMibDescr(szFile);
	}
	ff.Close();

}

void CmSnmpApi::LoadMibDescr(CString szFile)
{
	CFile f;
	if(! f.Open(szFile,CFile::modeRead) ) return;
	CArchive ar(&f,CArchive::load);

	CString szName;
	CString szDescr;
	int  nDescrState = 0;
	CString szLine;
	int i;
	while(ar.ReadString(szLine) ) {
		switch ( nDescrState ) {
		case 0:
			szLine.Trim();
			if( szLine.IsEmpty() ) continue;
			i = szLine.Find("#");
			if( i != 0 ) continue;
			szName = szLine.Mid(i+1);
			nDescrState = 1;
			break;
		case 1:
			i = szLine.Find("\"");
			if( i == -1 ) continue;
			szDescr = szLine.Mid(i+1);
			i = szDescr.Find("\"");
			if( i == -1 ) {
				nDescrState = 2;
			} else {
				szDescr = szDescr.Left(i);
				if( !szName.IsEmpty() ) {
					SetMibDescr(szName,szDescr);
					szName.Empty();
					szDescr.Empty();
				}
				nDescrState = 0;
			}
			break;
		case 2:
			i = szLine.Find("\"");
			if( i == -1 ) {
				szDescr += "\n             	 ";
				szDescr += szLine;
				continue;
			}
			szDescr += "\n             	 ";
			szDescr += szLine.Left(i);
			if( !szName.IsEmpty() ) {
				SetMibDescr(szName,szDescr);
				szName.Empty();
				szDescr.Empty();
			}
			nDescrState = 0;
		}
	}
	ar.Close();
	f.Close();
}


void CmSnmpApi::SetMibDescr(CString szNameIn,CString szDescr)
{
	char szName[1024];
    oid name[MAX_OID_LEN];
    size_t name_length;
	strcpy_s(szName,sizeof(szName),szNameIn);
	name_length = MAX_OID_LEN;
	if( get_node(szName,name,&name_length)==0 ) return;
	struct tree *tp  = get_tree(name,name_length,get_tree_head() );
	if( tp == NULL ) return;
	if( tp->description ) SNMP_FREE(tp->description);
	tp->description = _strdup(szDescr);
	return;

}

CString CmSnmpApi::GetGroupObject(CString szGroupName)
{
	int i = szGroupName.Find("[");
	if( i != -1 ) {
		szGroupName = szGroupName.Mid(i+1);
	}
	i = szGroupName.Find("]");
	if( i != -1 ) {
		szGroupName = szGroupName.Left(i);
	}
	char szName[1024];
    oid name[MAX_OID_LEN];
    size_t name_length;
	strcpy_s(szName,sizeof(szName),szGroupName);
	name_length = MAX_OID_LEN;
	if( get_node(szName,name,&name_length)==0 ) return("");
	struct tree *tp  = get_tree(name,name_length,get_tree_head() );
	if( tp == NULL ) return("");
	struct tree *tpp;
	tpp = tp->child_list;
	CMapWordToPtr omap;
	omap.RemoveAll();
	int nMaxSubID =0;
	while(tpp ) {
		if( tpp->type <= TYPE_SIMPLE_LAST && tpp->type != TYPE_OTHER
			&& (tpp->access == MIB_ACCESS_READONLY
			|| tpp->access == MIB_ACCESS_READWRITE )
			&& tpp->subid< 0x7fff) {
				omap[(WORD)tpp->subid] = tpp;
				if( nMaxSubID < (int) tpp->subid) nMaxSubID = tpp->subid;
		}
		tpp = tpp->next_peer;
	}
	CString szRet;
	szRet.Empty();
	for( i = 0;i < nMaxSubID;i++ ) {
		void *p;
		if( omap.Lookup(i,p) ) {
			tpp = (struct tree *)p;
			if( !szRet.IsEmpty() ) szRet +="\t";
			szRet += tpp->label;
		}
	}
	return(szRet);
}

// 漢字変換ルーチン
#include "../twsnmplib/kconvtbl.inc"


int IsUtf8(char *p)
{
	int i;
	int j;
	int nLen;
	int c;
	if( p == NULL ) return(0);
	for(i =0; p[i]; ) {
		c = (int) p[i++];
		c&=0x00ff;
		if( c < 0x007f ) continue;
		if( c >= 0x00c2 && c <= 0x00df ) {
			c = (int) p[i++];
			c &= 0x00ff;
			if( c  < 0x0080 || c > 0x00bf ) return(0);
			nLen  =0;
		} else if ( c  == 0x00e0 ) {
			c = (int) p[i++];
			c &= 0x00ff;
			if( c  < 0x00A0 || c > 0x00bf ) return(0);
			c = (int) p[i++];
			c &= 0x00ff;
			if( c  < 0x0080 || c > 0x00bf ) return(0);
			nLen = 0;
		} else if ( c >= 0x00e1 && c <= 0xef ) {
			nLen = 2;
		} else if ( c  == 0x00f0 ) {
			c = (int) p[i++];
			c &= 0x00ff;
			if( c  < 0x0090 || c > 0x00bf ) return(0);
			nLen = 2;
		} else if ( c >= 0x00f1 && c <= 0xf3 ) {
			nLen = 3;
		} else if ( c  == 0x00f4 ) {
			c = (int) p[i++];
			c &= 0x00ff;
			if( c  < 0x0080 || c > 0x008f ) return(0);
			nLen = 2;
		} else {
			//本当は、もっとあるが省略
			return(0);
		}
		for( j = 0; j < nLen ;j++ ) {
			c = (int) p[i++];
			c &= 0x00ff;
			if( c  < 0x0080 || c > 0x00bf ) return(0);
		}
	}
	return(1);
}

int IsEuc(char *p)
{
	int i;
	int c;
	for( i = 0; p[i]; ) {
		c = (int) p[i++];
		c &= 0x00ff;
		if( c < 0x007f ) continue;
		if( c < 0x00A1  || c > 0x00FE ) return(0);
		c = (int) p[i++];
		c &= 0x00ff;
		if( c < 0x00A1  || c > 0x00FE ) return(0);
	}
	return(1);
}


int IsSjis(char *p)
{
	int i;
	int c;
	for( i = 0; p[i]; ) {
		c = (int) p[i++];
		c &= 0x00ff;
		if( c < 0x007f ) continue;
		if( (c >= 0x0081 && c <= 0x9f ) ||
			(c >= 0x00e0  && c <= 0x00ef ) ) {
			c = (int) p[i++];
			c &= 0x00ff;
			if( c < 0x0040 || c > 0x00fc ) return(0);
		} else {
				return(0);
		}
	}
	return(1);
}


char *KConv(char *src,char *dst,int dstSize,unsigned char srctb[][4],unsigned  char dsttb[][4])
{
	int    find;
	int    ofst;
	unsigned char   *rp, *wp;
	unsigned char   *ep;
	rp  = (unsigned char*)src;
	wp  = (unsigned char*)dst;
	ep = wp;
	ep += (dstSize-1);
	memset(dst, 0x00, dstSize);
	while(*rp){
		if( wp > ep ) break; /* Buffer Over */
		if((0x00 < *rp)&&(*rp < ' ')){
			*wp = *rp;
			rp++;
			wp++;
		} else {
			find = 0;
			for(ofst=0 ; 0x00 != srctb[ofst][0] ; ofst++){
				if( *rp != srctb[ofst][0] ) continue; /* Speed up */
				if(! memcmp(rp, srctb[ofst], strlen((char*)srctb[ofst]))){
					find    = 1;
					break;
				}
			}
			if(find){
				strcpy_s((char*)wp, 4,(char*)dsttb[ofst]);
				rp += strlen((char*)srctb[ofst]);
				wp += strlen((char*)dsttb[ofst]);
			} else {
				*wp = *rp;
				rp++;
				wp++;
			}
		}
	}
	return(dst);
}


char *Utf8ToSjis(char *pIn,char *pOut,size_t nLen)
{
	return(KConv(pIn,pOut,nLen,UtfHex,SjisHex));
}


char *EucToSjis(char *pIn,char *pOut,size_t nLen)
{
	return(KConv(pIn,pOut,nLen,EucHex,SjisHex));
}



void  CmSnmpApi::ConvKanjiCode(struct variable_list *vars,char *s,size_t nLenIn)
{
	char *pIn;
	char *pOut;
	char *pHex;
	int i;
	size_t nLen = nLenIn;
	struct tree *tp;
	char szName[2048];
	char szTmp[2560];
	if( vars->type != ASN_OCTET_STR ) return;
// YMI  Check InetAddr Type IPv4 or IPv6
	if( vars->val_len == 4 || vars->val_len == 16  ) {
		strcpy_s(szName,sizeof(szName),s);
		pIn = strchr(szName,'.');
		if( pIn ) {
			*pIn ='\0';
			tp= get_tree_head();
			tp = find_node(szName,tp);
			pOut = strchr(s,'=');
			if( tp && pOut ) {
				pOut++;
				const char *pTC = get_tc_descriptor(tp->tc_index);
				if( pTC && strstr(pTC,"InetAddress") != NULL ){
					*pOut = '\0';
					if( vars->val_len == 4 ) {
						strcat_s(s,nLenIn," InetAddressIPv4: ");
						sprintf_s(szTmp,sizeof(szTmp),"%u.%u.%u.%u",
							(int)vars->val.string[0] & 0x00ff,
							(int)vars->val.string[1] & 0x00ff,
							(int)vars->val.string[2] & 0x00ff,
							(int)vars->val.string[3] & 0x00ff);
						strcat_s(s,nLenIn,szTmp);
						return;
					} else {
						int i;
						unsigned int nTmp;
						strcat_s(s,nLenIn," InetAddressIPv6: ");
						for( i =0; i < 8;i++ ) {
							nTmp = ((unsigned int)vars->val.string[i*2] &0x00ff);
							nTmp <<= 8;
							nTmp |=((unsigned int)vars->val.string[i*2+1]&0x00ff);

							sprintf_s(szTmp,sizeof(szTmp),"%04x",nTmp);
							if( i != 0 ) strcat_s(s,nLenIn,":");
							strcat_s(s,nLenIn,szTmp);
						}
						return;
					}
				}
			}
		}
	}
	pHex =  strstr(s,"Hex-STRING:");
	if( pHex == NULL ) return;
	strcpy_s(szName,sizeof(szName),s);
	pIn = strchr(szName,'.');
	if( pIn ) {
		*pIn ='\0';
		tp= get_tree_head();
		tp = find_node(szName,tp);
		if( tp ) {
			const char *pTC = get_tc_descriptor(tp->tc_index);
			if( pTC ) {
				if( strstr(pTC,"Display") == NULL ) return;
				// Display Stringの場合は、表示可能と考える。
				for( i = 0;i < (int)vars->val_len;i++ ) {
					if( vars->val.string[i] < 0x20  ) {
						vars->val.string[i]  = ' ';
					}
				}
			} else {
				// YMI Fix 2010.1.17
				// Display Stringでない場合は、チェックする。
				// 文字コードではない場合は、変換しない。
				for( i = 0;i < (int)vars->val_len;i++ ) {
					if( vars->val.string[i] == 0xff ) return;
					if( vars->val.string[i] & 0x80 ) continue;
					//最後の0x00はＯＫとする。
					if( vars->val.string[i] == 0 &&  (i == (int)vars->val_len-1)) continue;
					//TAB,CR,LFもＯＫとする。
					if ( vars->val.string[i] == '\n'  ||  vars->val.string[i] == '\t' || vars->val.string[i] == '\r') continue;
					if( vars->val.string[i] < 0x20  ) return;
				}
			}
		}
	}
	if( (((pHex -s) + vars->val_len+1) > nLen) ) return;
	pIn = ( char*) calloc(1,(size_t)(vars->val_len * 2));
	if( pIn == NULL ) return;
	pOut = (char*) calloc(1,(size_t)(vars->val_len * 2));
	nLen = nLen < vars->val_len * 2 ? nLen : vars->val_len * 2;
	if( pOut == NULL ) {
		free(pIn);
		return;
	}
	memcpy(pIn,vars->val.string,vars->val_len);
	pIn[vars->val_len] = '\0';
/*	if(  strlen(pIn) != vars->val_len) {
		free(pIn);
		free(pOut);
		return; // Not String
	}
*/
	for( i =0; i < (int)vars->val_len;i++ ) {
//		if(  pIn[i] < ' ' && pIn[i] >= 0 ) {
		//最後の００は文字列とする。2009.3.22 YMI
		if(  (pIn[i] < ' ' && pIn[i] > 0) || ( pIn[i] == 0 && i != (vars->val_len-1))) {
			free(pIn);
			free(pOut);
			return; // Not String
		}
	}
	if( IsUtf8(pIn) ) {
		Utf8ToSjis(pIn,pOut,nLen);
		*pHex = '\0';
		strcat_s(s,nLenIn,"STRING: ");
		strcat_s(s,nLenIn,pOut);
		free(pIn);
		free(pOut);
		return;
	} else if (IsSjis(pIn) ) {
		*pHex = '\0';
		strcat_s(s,nLenIn,"STRING: ");
		strcat_s(s,nLenIn,pIn);
		free(pIn);
		free(pOut);
		return;
	} else if ( IsEuc(pIn)) {
		EucToSjis(pIn,pOut,nLen);
		*pHex = '\0';
		strcat_s(s,nLenIn,"STRING: ");
		strcat_s(s,nLenIn,pOut);
		free(pIn);
		free(pOut);
		return;
	}
	free(pIn);
	free(pOut);
	return;
}

void CmSnmpApi::GetSnmpV3Info(struct snmp_session * session)
{
	if( session->version != SNMP_VERSION_3) return;
	m_szCEngID = FormatEngID(session->contextEngineID,session->contextEngineIDLen);
	m_szSEngID = FormatEngID(session->securityEngineID,session->securityEngineIDLen);
	m_nEngBoots = session->engineBoots;
	m_nEngTime = session->engineTime;
	return;
}

int CmSnmpApi::GetUsmUserList(CStringList &slUsmUserList)
{
	struct usmUser *pUser =	usm_get_userList();
	slUsmUserList.RemoveAll();
	while(pUser){
		CString s;
		s.Format("%s\t%s\t",pUser->name,
			FormatEngID(pUser->engineID,pUser->engineIDLen,TRUE));
		if( pUser->authProtocolLen > 0 && pUser->authProtocol) {
			char         *buf = NULL;
		    size_t          buf_len = 256, out_len = 0;
			buf = (char *) calloc(buf_len, 1);
			if( buf &&	snprint_objid(buf,buf_len,pUser->authProtocol,pUser->authProtocolLen) !=-1){
				s += buf;
			} else {
				s += "不明";
			}
			if( buf) free(buf);
		} else {
			s += "なし";
		}
		s +="\t";
		if( pUser->privProtocolLen > 0 && pUser->privProtocol) {
			char         *buf = NULL;
		    size_t          buf_len = 256, out_len = 0;
			buf = (char *) calloc(buf_len, 1);
			if( buf &&	snprint_objid(buf,buf_len,pUser->privProtocol,pUser->privProtocolLen) !=-1){
				s += buf;
			} else {
				s += "不明";
			}
			if( buf) free(buf);
		} else {
			s += "なし";
		}
		slUsmUserList.AddTail(s);
		pUser = pUser->next;
	}
	return((int)slUsmUserList.GetSize());
}

BOOL CmSnmpApi::AddUsmUser(CString szEngID,CString szUser,CString szAPass,CString szEPass)
{
	CString szLine;
	szLine.Empty();
	if( !szEngID.IsEmpty() ) {
		szLine+= "-e ";
		szLine += szEngID;
		szLine+= " ";
	}
	szLine += szUser;
	if( !szAPass.IsEmpty() ) {
		szLine +=" ";
		szLine +=szAPass;
	}
	if( !szEPass.IsEmpty() ) {
		szLine +=" ";
		szLine +=szEPass;
	}
	usm_parse_create_usmUser("CreateUser",szLine.GetBuffer());
	szLine.ReleaseBuffer();
	return(TRUE);
}

BOOL CmSnmpApi::DelUsmUser(CString szEngID,CString szUser)
{
	if( szUser.IsEmpty() ) return(TRUE);
	u_char *engineID = (u_char*)calloc(1,64);
	size_t engineIDLen=0;
	size_t nBufSize=64;
	if( engineID == NULL ) return(FALSE);
	if( szEngID.IsEmpty() ) {
		engineIDLen = snmpv3_get_engineID(engineID,nBufSize);
	} else {
		snmp_hex_to_binary((u_char**)(&engineID),&nBufSize,&engineIDLen, 0,szEngID.GetBuffer());
		szEngID.ReleaseBuffer();
	}
	struct usmUser *pUser  = usm_get_user(engineID,engineIDLen, szUser.GetBuffer(0));
	szUser.ReleaseBuffer();
	free(engineID);
	return(usm_remove_user(pUser)==NULL);
}

CString    CmSnmpApi::FormatEngID(u_char *pEngID,size_t nEngIDLen,BOOL bLong)
{
	CString szEngID;
	szEngID.Empty();
	int i;
	if( pEngID == NULL || nEngIDLen < 5 ) return("なし");
	szEngID ="0x";
	for(i=0; i< (int)nEngIDLen;i++ ) {
		CString s;
		s.Format("%02X",pEngID[i]);
		szEngID += s;
	}
	if( !bLong) return(szEngID);
	szEngID += " ";
	DWORD nENum=0;
	for( i = 0;i < 4;i++ ) {
		nENum <<=8;
		nENum |= (pEngID[i] &0x00ff);
	}
	if( nENum & 0x80000000){
		CString s;
		s.Format(" (EID:%u",nENum&0x7fffffff);
		szEngID += s;
		BYTE nEType = pEngID[i++];
		if( nEType == 1 && nEngIDLen > 8 ) {
			s.Format(" IPv4:%u.%u.%u.%u"
				,(int)pEngID[i]&0x00ff
				,(int)pEngID[i+1]&0x00ff
				,(int)pEngID[i+2]&0x00ff
				,(int)pEngID[i+3]&0x00ff);
			szEngID += s;
		} else if ( nEType == 3 ){
			s.Format(" MAC:");
			szEngID += s;
			s.Empty();
			for(; i< (int)nEngIDLen;i++ ) {
				s.Format("%02X",pEngID[i]);
				szEngID += s;
			}
		} else if ( nEType == 4 ){
			s.Format(" SRING:");
			szEngID += s;
			for(; i< (int)nEngIDLen;i++ ) {
				s.Format("%c",pEngID[i]);
				szEngID += s;
			}
		} else if ( nEType == 2 ){
			s.Format(" IPv6:");
			szEngID += s;
			for(; i< (int)nEngIDLen;i++ ) {
				s.Format("%02X",pEngID[i]);
				szEngID += s;
			}
		} else {
			s.Format(" Type(%d):",(int)nEType&0x00ff);
			szEngID += s;
			s.Empty();
			for(; i< (int)nEngIDLen;i++ ) {
				s.Format("%02X",pEngID[i]);
				szEngID += s;
			}
		}
	}else {
		CString s;
		s.Format(" (EID=%u Old:",nENum);
		szEngID += s;
		s.Empty();
		for(; i< (int)nEngIDLen;i++ ) {
			s.Format("%02X",pEngID[i]);
			szEngID += s;
		}
	}
	szEngID +=")";
	return(szEngID);
}

CString    CmSnmpApi::GetMySNMPv3Info(void)
{
	CString szRet;
	u_char szEngID[2560];
	size_t nEngIDLen = 2560;
	nEngIDLen = snmpv3_get_engineID(szEngID,nEngIDLen);
	szRet ="EngID=";
	if( nEngIDLen > 0 ){
		szRet += FormatEngID(szEngID,nEngIDLen);
	} else {
		szRet +="不明";
	}
	CString s;
	s.Format(" Boots=%u　Time=%u",snmpv3_local_snmpEngineBoots(),snmpv3_local_snmpEngineTime());
	szRet += s;
	return(szRet);
}
