#ifndef _GROUP_INFO_H_
#define _GROUP_INFO_H_

#include "includes.h"
#include <string>
#include <vector>
#include <sstream>

#include <sddl.h>

#include "dlls.h"

class Group
{
private:
	std::wstring _name;
	BYTE _SID[SECURITY_MAX_SID_SIZE];
	std::vector<std::wstring> _privileges;
	std::vector<std::wstring> _users;
	std::wstring _strSID;

	void updateInfo();
public:
	Group(std::wstring name) : _name(name) {
		updateInfo();
	}

	NTSTATUS addPrivilege(std::wstring& privilegeName);

	NTSTATUS removePrivilege(std::wstring& privilegeName);

	DWORD addUser(PSID sid);

	DWORD removeUser(PSID sid);

	std::vector<std::wstring> getUsers() const {
		return _users;
	}

	std::wstring getName() const
	{
		return _name;
	}

	std::vector<std::wstring> getPrivileges() const
	{
		return _privileges;
	}

	std::wstring getSID() const
	{
		return _strSID;
	}
};


DWORD addGroup(std::wstring& name);

DWORD deleteGroup(std::wstring& name);

#endif