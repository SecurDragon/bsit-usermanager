#include "UserInfo.h"

#include "dlls.h"

void User::updateInfo() {
	DWORD SIDlen = SECURITY_MAX_SID_SIZE;
	SID_NAME_USE tmp;

	TCHAR domain[MAX_PATH];
	DWORD szDomain = MAX_PATH;

	advapi32dll.LookupAccountNameW(NULL, _name.c_str(), &_SID, &SIDlen, domain, &szDomain, &tmp);
	
	LPWSTR sid = NULL;
	advapi32dll.ConvertSidToStringSidW(&_SID, &sid);
	_strSID = sid;
	LocalFree(sid);

	LPLOCALGROUP_INFO_0 groups = NULL;
	DWORD entriesRead = 0;
	DWORD totalEntries = 0;
	netapi32dll.NetUserGetLocalGroups(NULL, _name.c_str(), 0, 0, (LPBYTE*)&groups, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries);

	for (int i = 0; i < entriesRead; ++i) {
		_groups.emplace_back(std::wstring(groups[i].lgrpi0_name));
	}

	PLSA_UNICODE_STRING rights = NULL;
	ULONG rights_count = 0;
	advapi32dll.LsaEnumerateAccountRights(policy, _SID, &rights, &rights_count);

	for (int i = 0; i < rights_count; ++i) {
		_privileges.emplace_back(std::wstring(rights[i].Buffer, rights[i].Length));
	}

	netapi32dll.NetApiBufferFree(groups);
	advapi32dll.LsaFreeMemory(rights);
}

NTSTATUS User::addPrivilege(std::wstring & privilegeName){
	LSA_UNICODE_STRING privilege;

	if (!InitLsaString(&privilege, privilegeName.c_str()))
		return false;

	PSID s;
	ConvertStringSidToSid(_strSID.c_str(), &s);
	return advapi32dll.LsaAddAccountRights(policy, s, &privilege, 1);
}

NTSTATUS User::removePrivilege(std::wstring & privilegeName) {
	LSA_UNICODE_STRING privilege;

	if (!InitLsaString(&privilege, privilegeName.c_str()))
		return false;

	return advapi32dll.LsaRemoveAccountRights(policy, &_SID, FALSE, &privilege, 1);
}


DWORD addUser(std::wstring& name, std::wstring& pwd) {
	USER_INFO_1 userInfo;
	userInfo.usri1_comment = NULL;
	userInfo.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
	userInfo.usri1_home_dir = NULL;
	userInfo.usri1_name = const_cast<LPWSTR>(name.c_str());
	userInfo.usri1_password = const_cast<LPWSTR>(pwd.c_str());
	userInfo.usri1_priv = USER_PRIV_USER;
	userInfo.usri1_script_path = NULL;

	DWORD err = 0;
	return netapi32dll.NetUserAdd(NULL, 1, (LPBYTE)&userInfo, &err);
}

DWORD deleteUser(std::wstring& name) {
	return netapi32dll.NetUserDel(NULL, name.c_str());
}
