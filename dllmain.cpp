#include "HookFucker.h"

using func_t = BOOL(*)(LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect);

void init() {
	void* function = (void*)hook_fucker::copy_function("kernel32.dll", "VirtualProtect");
	func_t virtual_protect = (func_t)(function);
}



