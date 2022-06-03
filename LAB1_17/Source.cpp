#include <iomanip>

#include "GroupInfo.h"
#include "UserInfo.h"

#include <algorithm>
#include <locale.h>


#include "dlls.h"
#undef max

LSA_HANDLE policy = NULL;

LSA_HANDLE GetPolicyHandle()
{
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS ntsResult;
    LSA_HANDLE lsahPolicyHandle;

    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    ntsResult = advapi32dll.LsaOpenPolicy(
        NULL,
        &ObjectAttributes,
        POLICY_ALL_ACCESS,
        &lsahPolicyHandle
    );

    if (ntsResult != 0)
    {
		std::cerr << "Can't acquire policy: " << advapi32dll.LsaNtStatusToWinError(ntsResult) << std::endl;
        return NULL;
    }
    return lsahPolicyHandle;
}

bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
    DWORD dwLen = 0;

    if (NULL == pLsaString)
        return FALSE;

    if (NULL != pwszString)
    {
        dwLen = wcslen(pwszString);
        if (dwLen > 0x7ffe)
            return FALSE;
    }

    pLsaString->Buffer = (WCHAR*)pwszString;
    pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
    pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

    return TRUE;
}

void getUsers(std::vector<User>& users)
{
	users.clear();
	
    LPUSER_INFO_0 inf = NULL;
    DWORD read, total;
    netapi32dll.NetUserEnum(NULL, 0, 0, (LPBYTE*)&inf, MAX_PREFERRED_LENGTH, &read, &total, NULL);
    for (int i = 0; i < read; ++i)
        users.emplace_back(User(inf[i].usri0_name));
    netapi32dll.NetApiBufferFree(inf);
}

void getGroups(std::vector<Group>& groups)
{
	groups.clear();
    DWORD read, total;
	
    LPLOCALGROUP_INFO_0 grInfo = NULL;
    netapi32dll.NetLocalGroupEnum(NULL, 0, (LPBYTE*)&grInfo, MAX_PREFERRED_LENGTH, &read, &total, NULL);
    for (int i = 0; i < read; ++i)
        groups.emplace_back(Group(grInfo[i].lgrpi0_name));
    netapi32dll.NetApiBufferFree(grInfo);
}

char get_input(const char* mask) {
    char res = 0;
    while (1) {
		std::cin.get(res);

		std::cin.clear();
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        if (strchr(mask, res)) return res;
        std::cout << "No such command\nYour choice: ";
    }
}

void printOptions()
{
    std::wcout << 
		"Choose option:" << std::endl <<
        "[u] - users menu" << std::endl <<
		"[g] - groups menu" << std::endl <<
        "[p] - manage privileges" << std::endl <<
        "[q] - quit" << std::endl;
}

std::vector<std::wstring> privilegesList{
	SE_ASSIGNPRIMARYTOKEN_NAME,
	SE_AUDIT_NAME,
	SE_BACKUP_NAME,
	SE_CHANGE_NOTIFY_NAME,
	SE_CREATE_GLOBAL_NAME,
	SE_CREATE_PAGEFILE_NAME,
	SE_CREATE_PERMANENT_NAME,
	SE_CREATE_SYMBOLIC_LINK_NAME,
	SE_CREATE_TOKEN_NAME,
	SE_DEBUG_NAME,
	SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
	SE_ENABLE_DELEGATION_NAME,
	SE_IMPERSONATE_NAME,
	SE_INC_BASE_PRIORITY_NAME,
	SE_INCREASE_QUOTA_NAME,
	SE_INC_WORKING_SET_NAME,
	SE_LOAD_DRIVER_NAME,
	SE_LOCK_MEMORY_NAME,
	SE_MACHINE_ACCOUNT_NAME,
	SE_MANAGE_VOLUME_NAME,
	SE_PROF_SINGLE_PROCESS_NAME,
	SE_RELABEL_NAME,
	SE_REMOTE_SHUTDOWN_NAME,
	SE_RESTORE_NAME,
	SE_SECURITY_NAME,
	SE_SHUTDOWN_NAME,
	SE_SYNC_AGENT_NAME,
	SE_SYSTEM_ENVIRONMENT_NAME,
	SE_SYSTEM_PROFILE_NAME,
	SE_SYSTEMTIME_NAME,
	SE_TAKE_OWNERSHIP_NAME,
	SE_TCB_NAME,
	SE_TIME_ZONE_NAME,
	SE_TRUSTED_CREDMAN_ACCESS_NAME,
	SE_UNDOCK_NAME,
	SE_UNSOLICITED_INPUT_NAME,
	SE_BATCH_LOGON_NAME,
	SE_DENY_BATCH_LOGON_NAME,
	SE_DENY_INTERACTIVE_LOGON_NAME,
	SE_DENY_NETWORK_LOGON_NAME,
	SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME,
	SE_DENY_SERVICE_LOGON_NAME,
	SE_INTERACTIVE_LOGON_NAME,
	SE_NETWORK_LOGON_NAME,
	SE_REMOTE_INTERACTIVE_LOGON_NAME,
	SE_SERVICE_LOGON_NAME
};



std::vector<User> users;
std::vector<Group> groups;

void user_menu() {
	std::wcout <<
		"[===USER=MENU===]" << std::endl <<
		"[l] - show list of users" << std::endl <<
		"[+] - add new user\t[-] - delete user" << std::endl <<
		"[q] - main menu" << std::endl;
	std::wcout << std::endl;
	std::wcout << "Choose option: ";
	int choice = get_input("+-lq");
	std::wcout << std::endl;
	
	switch(choice) {
	case '+':
	{
		std::wcout << "[ADD USER]" << std::endl;
		std::wstring username, userpwd;
		std::wcout << "Enter new user name: ";
		std::getline(std::wcin, username);

		std::wcout << "Enter new user password: ";
		std::getline(std::wcin, userpwd);

		DWORD res = addUser(username, userpwd);
		if (!res)
			std::wcout << "[SUCCESS] User '" << username << "' was successfully created!" << std::endl;
		else
			std::wcout << "[FAIL] User '" << username << "' can't be created due to error " << std::hex << res << std::endl;
		
		break;
	}
	case '-':
	{
		std::wcout << "[DELETE USER]" << std::endl;
		std::wstring username;
		std::wcout << "Enter user name: ";
		std::getline(std::wcin, username);

		DWORD res = deleteUser(username);
		if(!res)
			std::wcout << "[SUCCESS] User '" << username << "' was successfully deleted!" << std::endl;
		else
			std::wcout << "[FAIL] User '" << username << "' can't be deleted due to error " << std::hex << res << std::endl;

		break;
	}
	case 'l':
	{
		std::wcout << "[USERS LIST]" << std::endl;
		for (User& usr : users)
		{
			std::wcout << std::setw(15) << L"User: " << usr.getName() << std::endl <<
				std::setw(15) << L"SID: " << usr.getSID() << std::endl <<
				std::setw(15) << L"Groups: " << std::endl;
			for (auto& grp : usr.getGroups())
				std::wcout << std::setw(15) << " " << grp << std::endl;

			std::wcout << std::setw(15) << L"Privileges: " << std::endl;
			for (auto& priv : usr.getPrivileges())
				std::wcout << std::setw(15) << " " << priv.c_str() << std::endl;
			std::wcout << L"=========" << std::endl;
		}
		break;
	}
	}
}

void group_menu() {
	std::wcout <<
		"[===GROUP=MENU===]" << std::endl <<
		"[l] - show list of groups" << std::endl <<
		"[+] - create new group\t[-] - delete group" << std::endl <<
		"[a] - add user to group\t[r] - remove user from group" << std::endl << 
		"[q] - main menu" << std::endl;
	std::wcout << std::endl;
	std::wcout << "Choose option: ";
	int choice = get_input("+-arlq");
	std::wcout << std::endl;
	
	switch(choice) {
	case '+':
	{
		std::wcout << "[CREATE GROUP]" << std::endl;
		std::wstring groupname;
		std::wcout << "Enter new group name: ";
		std::getline(std::wcin, groupname);

		DWORD res = addGroup(groupname);
		if(!res)
			std::wcout << "[SUCCESS] Group '" << groupname << "' was successfully created!" << std::endl;
		else
			std::wcout << "[FAIL] Group '" << groupname << "' can't be created due to error " << std::hex << res << std::endl;

		break;
	}
	case '-':
	{
		std::wcout << "[DELETE GROUP]" << std::endl;
		std::wstring groupname;
		std::wcout << "Enter group name: ";
		std::getline(std::wcin, groupname);

		DWORD res = deleteGroup(groupname);
		if (!res)
			std::wcout << "[SUCCESS] Group '" << groupname << "' was successfully deleted!" << std::endl;
		else
			std::wcout << "[FAIL] Group '" << groupname << "' can't be deleted due to error " << std::hex << res << std::endl;

		break;
	}
	case 'a':
	{
		std::wcout << "[ADD TO GROUP]" << std::endl;
		std::wstring username, groupname;
		std::wcout << "Enter username: ";
		std::getline(std::wcin, username);
		auto userIt = std::find_if(users.begin(), users.end(), [&](const User& usr) {return usr.getName() == username; });
		if (userIt == std::end(users))
		{
			std::wcout << "[FAIL] There is no user with name '" << username << "'" << std::endl;
			break;
		}
		std::wcout << "Enter groupname: ";
		std::getline(std::wcin, groupname);
		auto groupIt = std::find_if(groups.begin(), groups.end(), [&](const Group& group) {return group.getName() == groupname; });
		if (groupIt == std::end(groups)) {
			std::wcout << "[FAIL] There is no group with name '" << groupname << "'" << std::endl;
			break;
		}

		User& usr = *userIt;
		Group& grp = *groupIt;
		auto res = grp.addUser(usr.getPSID());
		if (!res)
			std::wcout << "[SUCCESS] User '" << username << "' was successfully added to group '" << groupname << "'" << std::endl;
		else
			std::wcout << "[FAIL] Can't add user '" << username << "' to group '" << groupname << "' due to error: " << std::hex << res << std::endl;

		break;
	}
	case 'r':
	{
		std::wcout << "[REMOVE FROM GROUP]" << std::endl;
		std::wstring username, groupname;
		std::wcout << "Enter username: ";
		std::getline(std::wcin, username);
		auto userIt = std::find_if(users.begin(), users.end(), [&](const User& usr) {return usr.getName() == username; });
		if (userIt == std::end(users))
		{
			std::wcout << "[FAIL] There is no user with name '" << username << "'" << std::endl;
			break;
		}
		std::wcout << "Enter groupname: ";
		std::getline(std::wcin, groupname);
		auto groupIt = std::find_if(groups.begin(), groups.end(), [&](const Group& group) {return group.getName() == groupname; });
		if (groupIt == std::end(groups)) {
			std::wcout << "[FAIL] There is no group with name '" << groupname << "'" << std::endl;
			break;
		}

		User& usr = *userIt;
		Group& grp = *groupIt;
		auto res = grp.removeUser(usr.getPSID());
		if (!res)
			std::wcout << "[SUCCESS] User '" << username << "' was successfully removed from group '" << groupname << "'" << std::endl;
		else
			std::wcout << "[FAIL] Can't remove '" << username << "' from group '" << groupname << "' due to error: " << std::hex << res << std::endl;

		break;
	}
	case 'l':
	{
		std::wcout << "[GROUPS LIST]" << std::endl;
		for (Group& grp : groups)
		{
			std::wcout << std::setw(15) << L"Group: " << grp.getName() << std::endl <<
				std::setw(15) << L"SID: " << grp.getSID() << std::endl;

			std::wcout << std::setw(15) << L"Users: " << std::endl;
			for (auto& user : grp.getUsers())
				std::wcout << std::setw(15) << " " << user.c_str() << std::endl;

			std::wcout << std::setw(15) << L"Privileges: " << std::endl;
			for (auto& priv : grp.getPrivileges())
				std::wcout << std::setw(15) << " " << priv.c_str() << std::endl;
			std::wcout << L"=========" << std::endl;
		}

		break;
	}
	}
}

void privileges_menu() {
	std::wcout <<
		"[===PRIVILEGES===]" << std::endl <<
		"[l] - show list of available privileges" << std::endl <<
		"[a] - add privilege to user/group" << std::endl <<
		"[r] - remove privilege from user/group" << std::endl <<
		"[q] - main menu" << std::endl;
	std::wcout << std::endl;
	std::wcout << "Choose option: ";
	int choice = get_input("larq");
	std::wcout << std::endl;
	
	switch(choice) {
	case 'l':
	{
		std::wcout << "[PRIVILEGE LIST]" << std::endl;
		for (auto& priv : privilegesList)
			std::wcout << priv << std::endl;

		break;
	}
	case 'a':
	{
		std::wcout << "[ADD PRIVILEGE]" << std::endl;
		std::wstring name, privilege;
		std::wcout << "Enter user or group name: ";
		std::getline(std::wcin, name);
		auto userIt = std::find_if(users.begin(), users.end(), [&](const User& usr) {return usr.getName() == name; });
		auto groupIt = std::find_if(groups.begin(), groups.end(), [&](const Group& group) {return group.getName() == name; });
		if (userIt == std::end(users) && groupIt == std::end(groups)) {
			std::wcout << "[FAIL] There are neither user nor group named '" << name << "'" << std::endl;
			break;
		}

		std::wcout << "Enter privilege name: ";
		std::wcin >> privilege;
		if (std::find(privilegesList.begin(), privilegesList.end(), privilege) == std::end(privilegesList)) {
			std::wcout << "[FAIL] There is no privilege named '" << privilege << "'" << std::endl;
			break;
		}

		bool isUser = false;
		NTSTATUS res;

		if (userIt != std::end(users)) {
			isUser = true;
			auto& user = *userIt;
			res = user.addPrivilege(privilege);
		}
		else {
			auto& group = *groupIt;
			res = group.addPrivilege(privilege);
		}

		if (!res)
			std::wcout << "[SUCCESS] Privilege '" << privilege << "' was successfully given to " << (isUser ? "user" : "group") << " '" << name << "'" << std::endl;
		else
			std::wcout << "[FAIL] Can't give privilege '" << privilege << "' to " << (isUser ? "user" : "group") << " '" << name << "' due to error: " << std::hex << res << std::endl;
		break;
	}
	case 'r':
	{
		std::wcout << "[REMOVE PRIVILEGE]" << std::endl;
		std::wstring name, privilege;
		std::wcout << "Enter user or group name: ";
		std::getline(std::wcin, name);
		auto userIt = std::find_if(users.begin(), users.end(), [&](const User& usr) {return usr.getName() == name; });
		auto groupIt = std::find_if(groups.begin(), groups.end(), [&](const Group& group) {return group.getName() == name; });
		if (userIt == std::end(users) && groupIt == std::end(groups)) {
			std::wcout << "[FAIL] There are neither user nor group named '" << name << "'" << std::endl;
			break;
		}

		std::wcout << "Enter privilege name: ";
		std::wcin >> privilege;
		if (std::find(privilegesList.begin(), privilegesList.end(), privilege) == std::end(privilegesList)) {
			std::wcout << "[FAIL] There is no privilege named '" << privilege << "'" << std::endl;
			break;
		}

		bool isUser = false;
		NTSTATUS res;

		if (userIt != std::end(users)) {
			isUser = true;
			auto& user = *userIt;
			res = user.removePrivilege(privilege);
		}
		else {
			auto& group = *groupIt;
			res = group.removePrivilege(privilege);
		}

		if (!res)
			std::wcout << "[SUCCESS] Privilege '" << privilege << "' was successfully removed from " << (isUser ? "user" : "group") << " '" << name << "'" << std::endl;
		else
			std::wcout << "[FAIL] Can't remove privilege '" << privilege << "' from " << (isUser ? "user" : "group") << " '" << name << "' due to error: " << std::hex << res << std::endl;
		break;
	}
	}
}

void main_menu() {
	while (1) {
		printOptions();
		std::wcout << std::endl;
		std::wcout << "Choose option: ";
		int choice = get_input("ugpq");
		std::wcout << std::endl;

		getUsers(users);
		getGroups(groups);
		switch (choice) {
		case 'u':
			user_menu();
			break;
		case 'g':
			group_menu();
			break;
		case 'p':
			privileges_menu();
			break;
		case 'q':
			return;
		}
		std::wcout << std::endl;
	}
}

int main() {
    setlocale(LC_ALL, "ru-RU");
	system("chcp 1251");
	system("cls");
	policy = GetPolicyHandle();

	main_menu();
	
	return 0;
}