// OID.cpp : �����t�@�C��
//

#include "stdafx.h"
#include <regex>
#include <vector>
#include "SnmpApi.h"
#include "OID.h"

#include <sstream>

namespace msnmp {
// OID

    OID::OID(std::vector<oid> p)
    {
	    this->set(p);
	    return;
    }

    OID::OID()
    {

    }

    OID::OID(CString p)
    {
        if( p.IsEmpty() ){
            p = "0.0";
        }
        this->set(p);
    }

    OID::OID(oid oidAry[], size_t length)
    {
        this->set(oidAry,length);	
	    return;
    }

    OID::~OID()
    {

    }

    OID::OID(const OID & a){
        this->set(a.nameOid);
        this->nameOrig = a.nameOrig;
        this->value = a.value;
        this->type = a.type;
        this->valueInt = a.valueInt;
    }

    const OID & OID::operator=(const OID & p) {
        this->set(p.nameOid);
        this->nameOrig = p.nameOrig;
        this->value = p.value;
        this->type = p.type;
        this->valueInt = p.valueInt;
        return * this;
    }

    // MIB ��������A�u�S�����l�̕�����v�u�ł��ȗ����ꂽ������v�uoid �̔z��v�ɕϊ�
    BOOL OID::set (const CString p){
        this->nameOrig = p;
        this->convertAllNumberOid(this->nameOid, p);
        this->convertMibNameToOidAry(this->nameAry, this->nameOid);
        this->convertNamedOid(this->nameOidShort, this->nameAry);
	    return true;
    }

    // MIB oidAry ���u�S�����l�̕�����v�u�ł��ȗ����ꂽ������v�ɕϊ�
    BOOL OID::set (const std::vector<oid> p){
	    this->clear();
	    this->nameAry = std::vector<oid>(p);
	    return true;
    }

    BOOL OID::set (oid oidAry[], size_t length){
        std::vector<oid> p;
	    for(size_t len= 0; len < length; len++){
		    p.push_back(oidAry[len]);
	    }
        return this->set(p);
    }


    BOOL OID::setFromLine(CString line){
        // "<MIB��> = <�^��>:<�l>" �̃t�H�[�}�b�g�ŗ���A�͂��B
        // �܂��� "<MIB��>=<�^��>(<�l>)" �̃t�H�[�}�b�g�ŗ���B
        // "<MIB��> = <�l>" �̃t�H�[�}�b�g�����肦��B
        CString sep = _T("=");
        int oidpos = line.Find(sep);
        if( oidpos == -1) return FALSE;

        this->set(line.Left(oidpos).Trim());
        CString remain = line.Mid(oidpos + sep.GetLength()).Trim();
        if(this->nameOidShort.Find(_T("sysUpTimeInstance")) >= 0){
            this->value = remain;
            this->valueInt = _ttoi64(remain);
            this->type = "INTEGER";
            return TRUE;
        }
        if(this->nameOidShort.Find(_T("snmpTrapOID.0")) >= 0){
            this->value = remain;
            this->type = "OID";
            return TRUE;
        }

        CString value;
        int p = remain.Find(":");
        if( p == 0 ){
            // �擪�Ɂu:�v�� String �^�Ƃ��ē˂�����
            this->value = remain.Trim();
            this->type = _T("STRING");
            return TRUE;
        } else if (p < 0){
            // ������Ȃ��B�� sysUpTime.0 �� snmpTrapOID.0�A�܂��� "" �̂�
            if(remain == _T("\"\"")){
                this->type = _T("STRING");
                this->value = _T("");
                return TRUE;
            }
            return FALSE;
        }
        // �^: �l  �܂��� �^:desc(�l)
        this->type = remain.Left(p).Trim();
        remain = remain.Mid(p + 1).Trim();
        if( this->type == _T("STRING")){
            this->value = remain;
        } else {
            int p1 = remain.Find(_T("("));
            int p2 = remain.Find(_T(")"));
            if( p1 >= 0 && p2 >= 0 && p2 > p1){
                remain = remain.Mid(p1 + 1 , p2 - (p1 + 1)); // @@@
            } else if( remain.Left(1) == _T("\"") && remain.Mid(remain.GetLength()-1) == _T("\"")){
                remain = remain.Mid(1,remain.GetLength()-2);
            }
            this->value = remain;
            if(this->type == "INTEGER"){
                if( StrToInt64Ex(this->value , STIF_DEFAULT, & this->valueInt) != TRUE){
                    this->valueInt = 0;
                }
                // this->valueInt = StrToInt(this->value);
            }
        }
        return TRUE;
    }


    BOOL OID::convertAllNumberOid(CString & result, CString oidStr){
        BOOL ret = TRUE;
        char *p = new char[oidStr.GetLength()+1];
        lstrcpy( p, oidStr);
        result = CSnmpApi::GetOid(p);
        if( result == _T("UnknownOID")){
            throw new COidException(oidStr);
            ret = FALSE;
        }

        delete [] p;
        return ret;
    }

    // �S�����l��MIB������� vector<oid>�z��ɕϊ�����B
    BOOL OID::convertMibNameToOidAry(std::vector<oid> & list, const CString oidStr){
        list.clear();

        int pos = 0;
        CString p = oidStr.Tokenize(".",pos);
        while ( pos >=0 && p != "") {
            list.push_back(atoi(p));
            p = oidStr.Tokenize(".",pos);
        }
        return TRUE;
    }

    BOOL OID::convertNamedOid(CString & result, const std::vector<oid> list){
        char oidResult[SPRINT_MAX_LEN];
        snprint_objid(oidResult, sizeof(oidResult), list.data(), list.size());
        result = oidResult;
        return TRUE;
    }


    BOOL OID::clear(){
	    this->nameOidShort = "";
	    this->nameOid = "";
        this->nameAry.clear();	
        this->value = "";
        this->type = "";
        this->valueInt = 0;
	    return true;
    }

    BOOL OID::operator == ( const OID p){
         return (p.nameAry == this->nameAry);
    }

    BOOL OID::operator == ( const CString p){
         OID oid(p);
         return (oid == * this);
    }

    BOOL OID::operator != ( const OID p){
         return (p.nameAry != this->nameAry);
    }

    BOOL OID::parseOid(CString &nameOid, std::vector<oid> pOid){
	    char szName[1024];
	    oid name[MAX_OID_LEN]; // pOid.size()

	    size_t nameLen = pOid.size();	
	    for(size_t i=0; i<nameLen; i++){
		    name[i] = pOid[i];
	    }
	    if(snmp_parse_oid(szName,name,&nameLen) == NULL) {
		    return false;
	    }
        nameOid = szName;
	    return true;
    }

    BOOL OID::parseName(std::vector<oid> &p, CString name){

        return false;
    }

    BOOL OID::contains(const OID & p) const {
	    size_t len = this->search(this->nameAry, p.nameAry);
        if(len > 0) return TRUE;
        return FALSE;	
    }

    BOOL OID::IsContained(const OID & p) const {
	    size_t len = p.search(p.nameAry, this->nameAry);
        if(len > 0) return TRUE;
        return FALSE;	
    }

    // oid�z�� A �� B ���܂܂�Ă����ꍇ�A���̊܂܂�Ă�������Ԃ��B
    // B �����S�Ɋ܂܂�Ă��Ȃ��ꍇ�� 0 ��Ԃ��B
    size_t OID::search(const std::vector<oid> A, const std::vector<oid> B) const {
        size_t i;

        if(A.size() < B.size()){
            return 0;
        }

        for(i=0; i < B.size(); i++){
		    if(A[i] != B[i]){
			    break;
		    }
	    }
        if(B.size() == i ) {
            return i;
        }
	    return 0;
    }

    oid OID::getPartOfOidRaw(INT64 position){
        int p = this->nameAry.size() + (int)position;
        return nameAry[p];
    }

    CString OID::getPartOfOid(INT64 position){
        oid p = this->getPartOfOidRaw(position);
        CString result;
        result.Format("%d",p);
        return result;
    }

    CString OID::getDescription(){
        CString ret;
        ret.Empty();
        char buf[8192];
		if (snprint_description(buf,sizeof(buf),& nameAry.front(),nameAry.size(),100) > 0 ) {
            std::stringstream ss;
            ss << buf;
            char lines[256];
            CString line;
            BOOL fQuote = FALSE;
            while ( ss && ss.getline(lines,sizeof(lines))){
                line = lines;
                line.Replace(_T("\n"),_T(" ")); // �O�̂���
                line.Replace(_T("\t"),_T(" ")); // TAB �͕s�v�B
                line.Trim();
                if( ret.IsEmpty() ){
                    if (line.Find(_T("DESCRIPTION")) >= 0 ){ // ����
                        ret += line;
                        int start = ret.Find(_T("\""));
                        if( start >= 0 ){
                            fQuote = TRUE;
                            int end = ret.Find(_T("\""),start);
                            if( end > start ){
                                return ret; // DESCRIPTION �܂߂�1�s�����Ȃ��Ƃ�
                            }
                        }
                    }
                    continue;
                }
                if( line.IsEmpty() ) continue;

                ret += _T(" ") ;
                ret += line;
                if( fQuote ) {
                    if( line.Find(_T("\"")) >= 0 ){
                        return ret;
                    }
                } else {
                    if( line.Find(_T("\"")) >= 0 ){
                        fQuote = TRUE;
                    }
                }
            }
        }
        return ret;
    }


// OID �����o�[�֐�

    COidException::COidException(CString line)
    {
#ifdef _DEBUG
        m_bReadyForDelete = TRUE;
#endif
        m_szError = line;
    }
    void COidException::Delete()
    {
        delete this;
    }
    int COidException::ReportError()
    {
        CString strText;
        strText.Format(_T("�o�^���ꂽ MIB �t�@�C���Ɂu%s�v�͒�`����Ă��܂���B"), m_szError);
        AfxMessageBox(strText, MB_OK);
        return 0;
    }
}