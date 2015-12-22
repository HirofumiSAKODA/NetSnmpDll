// dllmain.h : モジュール クラスの宣言

class CNetSnmpDllModule : public ATL::CAtlDllModuleT< CNetSnmpDllModule >
{
public :
	DECLARE_LIBID(LIBID_NetSnmpDllLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_NETSNMPDLL, "{A3534659-CCCC-4262-A3B5-3378A08155F9}")
};

extern class CNetSnmpDllModule _AtlModule;
