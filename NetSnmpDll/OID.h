#include <vector>

#pragma once

// OID コマンド ターゲット

#if !defined(oid)
typedef u_long oid;
#endif

namespace msnmp {

    // OID型を用意
    // ついでにvalue も持つ。value は CStgring型とし、数値変換、binary 変換処理を合わせ持つ。
    class OID : public CObject
    {
    public:
	    OID();
        OID(std::vector<oid>);
        OID(CString);
        OID(oid[],size_t len);
        OID(const OID &a);
    
	    virtual ~OID();

        CString nameOrig; // createするときに指定された OID 文字列。保存。
        CString nameOid; // OID、先頭から全部数値、の文字列
	    CString nameOidShort; // 可能な限りMIB名に翻訳されて省略された文字列
        std::vector<oid> nameAry; // OIDの数値配列 （ 型 oid = u_long )

        CString value;
        CString type;
        int typeNum;
        INT64 valueInt;

        std::vector<oid> slices(int,int);
        oid slice(int);

        const OID & OID::operator=(const OID & p);

	    BOOL operator==(const OID);
	    BOOL operator!=(const OID);
	    BOOL operator==(const CString p);

        BOOL contains(const OID &) const;
        BOOL IsContained(const OID &) const;
	    BOOL contains(CString);
        BOOL contains(std::vector<oid>);

        BOOL clear();	

        BOOL set(CString);
        BOOL set(std::vector<oid>);
        BOOL set(oid[],size_t);
        BOOL OID::setFromLine(CString);
        size_t search(const std::vector<oid>, const std::vector<oid>) const;
        BOOL parseOid(CString &, std::vector<oid>);
        BOOL parseName(std::vector<oid> &, CString);
        CString getPartOfOid(INT64);
        CString getDescription();

    private:
        oid getPartOfOidRaw(INT64);
        BOOL convertAllNumberOid(CString & result, CString oidStr);
        BOOL convertMibNameToOidAry(std::vector<oid> & list,const CString oidStr);
        BOOL convertNamedOid(CString & result, const std::vector<oid> list);

    };
    class COidException : public CException
    {
    public:
        CString m_szError;
        COidException(CString line);
        void Delete();
        int ReportError();
    };
}

/*
 #create an object
 my $oid = SNMP::Class::OID->new('.1.3.6.1.2.1.1.5.0');
 #-or-
 my $oid = SNMP::Class::OID->new('sysName.0');
 
 #overloaded scalar representation
 print $oid; # evaluates to sysName.0

 #representations
 $oid->to_string; #string representation -- sysName.0
 $oid->numeric; #numeric representation -- .1.3.6.1.2.1.1.5.0
 $oid->to_array; #(1,3,6,1,2,1,1,5,0)
 $oid->[1]; #can be used as array reference -- returns 5
 $oid->length; #9

 #slicing
 my $oid2 = $oid->slice(3,6); #new object : .6.1.2.1
 my $oid2 = $oid->slice(3..6); #same

 #equality
 $oid1 == $oid2; # yields true if they are the same
 $oid1 == '.1.3.6.1.2.1.1.5.0' #also acceptable, second operand will be converted 

 #hierarchy
 $oid2 = SNMP::Class::OID->new('.1.3.6.1.2.1.1');
 $oid2->contains($oid); #true; Because .1.3.6.1.2.1.1.5.0 is under .1.3.6.1.2.1.1
 $oid2->contains('.1.3.6.1.2.1.1.5.0'); #also true, string autoconverted to SNMP::Class::OID

 #concatenation
 SNMP::Class::OID(".1.3.6") . SNMP::Class::OID("1.2.1"); #returns .1.3.6.1.2.1
 SNMP::Class::OID(".1.3.6") . '.1.2.1'; #also acceptable, returns the same



*/

