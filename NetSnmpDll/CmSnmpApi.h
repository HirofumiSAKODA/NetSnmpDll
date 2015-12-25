#pragma once

// CmSnmpApi コマンド ターゲット

class CmSnmpApi : public CObject
{
public:
	CmSnmpApi();
	virtual ~CmSnmpApi();
	// CSnmpApi();
	// virtual ~CSnmpApi();

public:
	static void CALLBACK TimerCallBack(HWND hWnd,UINT uMsg,UINT_PTR idEvent,DWORD dwTime);
	static CString GetVBStr(char *p,BOOL bOid);
	static CString GetSubTree(struct tree *tree);
	static CString GetTrapDescr(int wTrap);
	static CString ConvShortNameVarBind(CString szIn);
	static CString  GetTypeName(int wType );
	static int GetIndexList(CString& szIn,CString szMib,CStringList& slIndex);
	static CString GetIPAddr(CString &szIPList, CString szIndex);
	static double GetDoubleMibVal(CString & szIn,CString szMib);
	static double GetDoubleMibVal(CString & szVal);
	static CString GetShortName( CString &sIn);
	static CString GetOid(char *pLabel);
	static int GetIntMibVal(CString &sIn,CString  szMib);
	static int GetIntMibVal(CString & szVal);
	static CString GetMibVal( CString &sIn,CString szMib);
	static void CloseSnmpApi(CString szType);
	static void InitSnmpApi(CString szType,CString szBaseDir,CString szLogFile ="");
	static BOOL CheckRcv(void);
	static char GetType(char *szName);
	static CString GetGroupObject(CString szGroupName);
	static int  GetSesCount(void);

	// YMI Added 2007.4.29 高速化
	int  GetSocket(void);

	void StopTrapRcv(void);
	BOOL SendTrap(CString szIP,CString szCom,CString szEID,CString szVarBindList,int wGen,int wSpe);
	CString GetTrap(void);
	BOOL StartTrapRcv(int wPort=162);
	CStringList m_TrapList;
    CSemaphore m_TrapSema;
	UINT	m_wTrapPort;
	static int TrapRcv(int op,struct snmp_session *session,int reqid,struct snmp_pdu *pdu,void *magic);
	CString GetRetStr(void);

	int m_wReqType;
	void SetVarList(CString& szVarList,CString szSep);
	void ClearReq(void);
	int  GetSessSock();


	static int  ReqCallback(int op,struct snmp_session *session,int reqid,struct snmp_pdu *pdu,void *magic);
	BOOL Walk(int nMode,CString szIP,CString szComOrUser,CString szPasswd,CString szVarList,BOOL bBulkMode,int wTimeOut,int wRetry);
	BOOL SetReq(int nMode,CString szIP,CString szComOrUser,CString szPasswd,CString szVarList,int wTimeOut = 50,int wRetry =2);
	BOOL GetReq(int nMode,CString szIP,CString szComOrUser,CString szPasswd,CString szVarList,int wTimeOut = 50,int wRetry =2);
	BOOL GetNextReq(int nMode,CString szIP,CString szComOrUser,CString szPasswd,CString szVarList,int wTimeOut = 50,int wRetry =2);
	BOOL SendSetReq(void);
	BOOL SendReq(void);
	struct snmp_session *m_pSnmpSession; 

	unsigned int m_wTimeOut;
	unsigned int m_wRetry;
	CString   m_szIP;
	unsigned int m_wTime;
	int		m_wStatus;
	int		m_wRetCode;
	// For SNMP Walk
	oid m_RootOID[MAX_OID_LEN];
	size_t m_nRootOIDLen;


	CStringList m_slVarList;
	CStringList  m_slRet;
	BOOL    m_bMIBOver;

	int m_nSnmpMode;

	CString m_szPasswd;
	CString m_szComOrUser;
	BOOL m_bBulkMode;
// YMI Added 2009.3.7
	CString m_szSEngID;
	CString m_szCEngID;
	DWORD   m_nEngBoots;
	DWORD   m_nEngTime;
	static  int GetUsmUserList(CStringList &slUsmUserList);
	static  BOOL        AddUsmUser(CString szEngID,CString szUser,CString szAPass,CString szEPass);
	static  BOOL        DelUsmUser(CString szEngID,CString szUser);
	static  CString     FormatEngID(u_char *pEngID,size_t nEngIDLen,BOOL bLong= TRUE);
// 
	static int CmpOidByName(CString szName1, CString szName2);
	static void FindMibDescr(CString szPath);
	static void LoadMibDescr(CString szFile);
	static void SetMibDescr(CString szName,CString szDescr);
	static oid *snmp_pars_oOid(char *argv,oid *root,size_t *rootlen);
	static void LoadMIB(CString szLogFile,CString szMibDescr);
	static void ConvKanjiCode(struct variable_list *vars,char *s,size_t nLen);
	void GetSnmpV3Info(struct snmp_session * session);
	static CString GetMySNMPv3Info(void);

};


