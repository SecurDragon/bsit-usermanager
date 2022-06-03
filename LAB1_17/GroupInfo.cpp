#include "GroupInfo.h"

#include "dlls.h"

void Group::updateInfo() {
	DWORD SIDlen = SECURITY_MAX_SID_SIZE;
	SID_NAME_USE tmp;

	TCHAR domain[MAX_PATH];
	DWORD szDomain = MAX_PATH;

	advapi32dll.LookupAccountNameW(NULL, _name.c_str(), &_SID, &SIDlen, domain, &szDomain, &tmp);

	PLSA_UNICODE_STRING rights = NULL;
	ULONG rights_count = 0;
	DWORD stat = advapi32dll.LsaEnumerateAccountRights(policy, &_SID, &rights, &rights_count);
	if (stat && stat != 0xc0000034)
	{
		std::wstringstream err;
		err << L"[LSAERROR " << std::hex << stat << "]" << std::endl;
		_privileges.emplace_back(err.str());
	}
	else {
		for (int i = 0; i < rights_count; ++i) {
			_privileges.emplace_back(std::wstring(rights[i].Buffer, rights[i].Length));
		}
	}

	advapi32dll.LsaFreeMemory(rights);

	LPWSTR sid = NULL;
	advapi32dll.ConvertSidToStringSidW(&_SID, &sid);
	_strSID = sid;
	LocalFree(sid);

	LPLOCALGROUP_MEMBERS_INFO_1 users;
	DWORD entriesRead = 0;
	DWORD totalEntries = 0;

	stat = netapi32dll.NetLocalGroupGetMembers(NULL, _name.c_str(), 1, (LPBYTE*)&users, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, NULL);

	if (stat) {
		std::wstringstream err;
		err << "[NETERROR " << std::hex << stat << "]" << std::endl;
		_users.emplace_back(err.str());
	}
	else {
		for (int i = 0; i < entriesRead; ++i) {
			_users.emplace_back(std::wstring(users[i].lgrmi1_name));
		}
	}
	netapi32dll.NetApiBufferFree(users);
}

NTSTATUS Group::addPrivilege(std::wstring & privilegeName) {
	LSA_UNICODE_STRING privilege;

	if (!InitLsaString(&privilege, privilegeName.c_str()))
		return false;

	return advapi32dll.LsaAddAccountRights(policy, &_SID, &privilege, 1);
}

NTSTATUS Group::removePrivilege(std::wstring & privilegeName) {
	LSA_UNICODE_STRING privilege;

	if (!InitLsaString(&privilege, privilegeName.c_str()))
		return false;

	return advapi32dll.LsaRemoveAccountRights(policy, &_SID, FALSE, &privilege, 1);
}

DWORD Group::addUser(PSID sid)
{
	return netapi32dll.NetLocalGroupAddMember(NULL, _name.c_str(), sid);
}

DWORD Group::removeUser(PSID sid)
{
	return netapi32dll.NetLocalGroupDelMember(NULL, _name.c_str(), sid);
}



DWORD addGroup(std::wstring& name) {
	LOCALGROUP_INFO_0 info;
	info.lgrpi0_name = const_cast<LPWSTR>(name.c_str());
	DWORD err = 0;

	return netapi32dll.NetLocalGroupAdd(NULL, 0, (LPBYTE)&info, &err);
}

DWORD deleteGroup(std::wstring& name) {
	return netapi32dll.NetLocalGroupDel(NULL, name.c_str());
}