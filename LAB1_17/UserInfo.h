#ifndef _USER_INFO_H_
#define _USER_INFO_H_

#include "includes.h"
#include <string>
#include <vector>

#include <sddl.h>

#include "dlls.h"

class User
{
private:
	std::wstring _name;
	BYTE _SID[SECURITY_MAX_SID_SIZE];
	std::vector<std::wstring> _groups;
	std::vector<std::wstring> _privileges;
	std::wstring _strSID;

	void updateInfo();
public:
	User(std::wstring&& name): _name(name) {
		updateInfo();
	}

	NTSTATUS addPrivilege(std::wstring& privilegeName);

	NTSTATUS removePrivilege(std::wstring& privilegeName);

	std::wstring getName() const
	{
		return _name;
	}

	std::vector<std::wstring> getPrivileges() const
	{
		return _privileges;
	}

	std::vector<std::wstring> getGroups() const
	{
		return _groups;
	}

	std::wstring getSID() const
	{
		return _strSID;
	}

	PSID getPSID() const {
		return (PSID)_SID;
	}
};

DWORD addUser(std::wstring& name, std::wstring& pwd);

DWORD deleteUser(std::wstring& name);

#endif //_USER_INFO_H_

