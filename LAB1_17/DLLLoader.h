#ifndef _DLL_LOADER_H_
#define _DLL_LOADER_H_

#include "includes.h"

class DLLLoader {
protected:
	HMODULE dllHandle;
	std::wstring _libName;
	void handleError(const char* func, DWORD error) {
		std::wcerr << "\x1b[31m[DLLERROR][" << _libName.c_str() << "] Error " << std::hex << error << std::dec << " in function " << func << "\x1b[0m" << std::endl;
	}
public:
	DLLLoader(LPCTSTR dllname) : _libName(dllname) {
		dllHandle = LoadLibrary(dllname);
	}
	~DLLLoader() {
		FreeLibrary(dllHandle);
	}
};


#define DECLARE_CLASS(ClassName) \
	public:\
	ClassName (const LPCTSTR name): DLLLoader(name){}\
	~ClassName () = default;


#define DECLARE_FUNCTION1(retType, funcName, p1Type) \
	typedef retType (CALLBACK* TYPE_##funcName)(p1Type);\
	TYPE_##funcName m_##funcName = NULL; \
	bool m_ld##funcName = false; \
	retType funcName(p1Type p1) {\
		if(dllHandle) {\
			if(!m_ld##funcName){ \
				m_##funcName = NULL; \
				m_##funcName = (TYPE_##funcName)GetProcAddress(dllHandle, #funcName);\
				m_ld##funcName = true;\
			}\
			if(NULL != m_##funcName)\
				return m_##funcName(p1);\
			else{ \
				handleError(#funcName, GetLastError()); \
				return (retType) -1;\
			}\
		}\
		else{ \
			handleError(#funcName, GetLastError()); \
			return (retType) -1;\
		}\
	}


#define DECLARE_FUNCTION2(retType, funcName, p1Type, p2Type) \
	typedef retType (CALLBACK* TYPE_##funcName)(p1Type, p2Type);\
	TYPE_##funcName m_##funcName = NULL; \
	bool m_ld##funcName = false; \
	retType funcName(p1Type p1, p2Type p2) {\
		if(dllHandle) {\
			if(!m_ld##funcName){ \
				m_##funcName = NULL; \
				m_##funcName = (TYPE_##funcName)GetProcAddress(dllHandle, #funcName);\
				m_ld##funcName = true;\
			}\
			if(NULL != m_##funcName)\
				return m_##funcName(p1, p2);\
			else{ \
				handleError(#funcName, GetLastError()); \
				return (retType) -1;\
			}\
		}\
		else{ \
			handleError(#funcName, GetLastError()); \
			return (retType) -1;\
		}\
	}


#define DECLARE_FUNCTION3(retType, funcName, p1Type, p2Type, p3Type) \
	typedef retType (CALLBACK* TYPE_##funcName)(p1Type, p2Type, p3Type);\
	TYPE_##funcName m_##funcName = NULL; \
	bool m_ld##funcName = false; \
	retType funcName(p1Type p1, p2Type p2, p3Type p3) {\
		if(dllHandle) {\
			if(!m_ld##funcName){ \
				m_##funcName = NULL; \
				m_##funcName = (TYPE_##funcName)GetProcAddress(dllHandle, #funcName);\
				m_ld##funcName = true;\
			}\
			if(NULL != m_##funcName)\
				return m_##funcName(p1, p2, p3);\
			else{ \
				handleError(#funcName, GetLastError()); \
				return (retType) -1;\
			}\
		}\
		else{ \
			handleError(#funcName, GetLastError()); \
			return (retType) -1;\
		}\
	}


#define DECLARE_FUNCTION4(retType, funcName, p1Type, p2Type, p3Type, p4Type) \
	typedef retType (CALLBACK* TYPE_##funcName)(p1Type, p2Type, p3Type, p4Type);\
	TYPE_##funcName m_##funcName = NULL; \
	bool m_ld##funcName = false; \
	retType funcName(p1Type p1, p2Type p2, p3Type p3, p4Type p4) {\
		if(dllHandle) {\
			if(!m_ld##funcName){ \
				m_##funcName = NULL; \
				m_##funcName = (TYPE_##funcName)GetProcAddress(dllHandle, #funcName);\
				m_ld##funcName = true;\
			}\
			if(NULL != m_##funcName)\
				return m_##funcName(p1, p2, p3, p4);\
			else{ \
				handleError(#funcName, GetLastError()); \
				return (retType) -1;\
			}\
		}\
		else{ \
			handleError(#funcName, GetLastError()); \
			return (retType) -1;\
		}\
	}


#define DECLARE_FUNCTION5(retType, funcName, p1Type, p2Type, p3Type, p4Type, p5Type) \
	typedef retType (CALLBACK* TYPE_##funcName)(p1Type, p2Type, p3Type, p4Type, p5Type);\
	TYPE_##funcName m_##funcName = NULL; \
	bool m_ld##funcName = false; \
	retType funcName(p1Type p1, p2Type p2, p3Type p3, p4Type p4, p5Type p5) {\
		if(dllHandle) {\
			if(!m_ld##funcName){ \
				m_##funcName = NULL; \
				m_##funcName = (TYPE_##funcName)GetProcAddress(dllHandle, #funcName);\
				m_ld##funcName = true;\
			}\
			if(NULL != m_##funcName)\
				return m_##funcName(p1, p2, p3, p4, p5);\
			else{ \
				handleError(#funcName, GetLastError()); \
				return (retType) -1;\
			}\
		}\
		else{ \
			handleError(#funcName, GetLastError()); \
			return (retType) -1;\
		}\
	}

#define DECLARE_FUNCTION6(retType, funcName, p1Type, p2Type, p3Type, p4Type, p5Type, p6Type) \
	typedef retType (CALLBACK* TYPE_##funcName)(p1Type, p2Type, p3Type, p4Type, p5Type, p6Type);\
	TYPE_##funcName m_##funcName = NULL; \
	bool m_ld##funcName = false; \
	retType funcName(p1Type p1, p2Type p2, p3Type p3, p4Type p4, p5Type p5, p6Type p6) {\
		if(dllHandle) {\
			if(!m_ld##funcName){ \
				m_##funcName = NULL; \
				m_##funcName = (TYPE_##funcName)GetProcAddress(dllHandle, #funcName);\
				m_ld##funcName = true;\
			}\
			if(NULL != m_##funcName)\
				return m_##funcName(p1, p2, p3, p4, p5, p6);\
			else{ \
				handleError(#funcName, GetLastError()); \
				return (retType) -1;\
			}\
		}\
		else{ \
			handleError(#funcName, GetLastError()); \
			return (retType) -1;\
		}\
	}


#define DECLARE_FUNCTION7(retType, funcName, p1Type, p2Type, p3Type, p4Type, p5Type, p6Type, p7Type) \
	typedef retType (CALLBACK* TYPE_##funcName)(p1Type, p2Type, p3Type, p4Type, p5Type, p6Type, p7Type);\
	TYPE_##funcName m_##funcName = NULL; \
	bool m_ld##funcName = false; \
	retType funcName(p1Type p1, p2Type p2, p3Type p3, p4Type p4, p5Type p5, p6Type p6, p7Type p7) {\
		if(dllHandle) {\
			if(!m_ld##funcName){ \
				m_##funcName = NULL; \
				m_##funcName = (TYPE_##funcName)GetProcAddress(dllHandle, #funcName);\
				m_ld##funcName = true;\
			}\
			if(NULL != m_##funcName)\
				return m_##funcName(p1, p2, p3, p4, p5, p6, p7);\
			else{ \
				handleError(#funcName, GetLastError()); \
				return (retType) -1;\
			}\
		}\
		else{ \
			handleError(#funcName, GetLastError()); \
			return (retType) -1;\
		}\
	}


#define DECLARE_FUNCTION8(retType, funcName, p1Type, p2Type, p3Type, p4Type, p5Type, p6Type, p7Type, p8Type) \
	typedef retType (CALLBACK* TYPE_##funcName)(p1Type, p2Type, p3Type, p4Type, p5Type, p6Type, p7Type, p8Type);\
	TYPE_##funcName m_##funcName = NULL; \
	bool m_ld##funcName = false; \
	retType funcName(p1Type p1, p2Type p2, p3Type p3, p4Type p4, p5Type p5, p6Type p6, p7Type p7, p8Type p8) {\
		if(dllHandle) {\
			if(!m_ld##funcName){ \
				m_##funcName = NULL; \
				m_##funcName = (TYPE_##funcName)GetProcAddress(dllHandle, #funcName);\
				m_ld##funcName = true;\
			}\
			if(NULL != m_##funcName)\
				return m_##funcName(p1, p2, p3, p4, p5, p6, p7, p8);\
			else{ \
				handleError(#funcName, GetLastError()); \
				return (retType) -1;\
			}\
		}\
		else{ \
			handleError(#funcName, GetLastError()); \
			return (retType) -1;\
		}\
	}


#endif //_DLL_LOADER_H_