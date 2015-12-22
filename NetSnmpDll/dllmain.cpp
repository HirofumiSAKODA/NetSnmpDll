// dllmain.cpp : DllMain の実装

#include "stdafx.h"
#include "resource.h"
#include "NetSnmpDll_i.h"
#include "dllmain.h"
#include "compreg.h"
#include "xdlldata.h"

CNetSnmpDllModule _AtlModule;

class CNetSnmpDllApp : public CWinApp
{
public:

// オーバーライド
	virtual BOOL InitInstance();
	virtual int ExitInstance();

	DECLARE_MESSAGE_MAP()
};

BEGIN_MESSAGE_MAP(CNetSnmpDllApp, CWinApp)
END_MESSAGE_MAP()

CNetSnmpDllApp theApp;

BOOL CNetSnmpDllApp::InitInstance()
{
#ifdef _MERGE_PROXYSTUB
	if (!PrxDllMain(m_hInstance, DLL_PROCESS_ATTACH, NULL))
		return FALSE;
#endif
	return CWinApp::InitInstance();
}

int CNetSnmpDllApp::ExitInstance()
{
	return CWinApp::ExitInstance();
}
