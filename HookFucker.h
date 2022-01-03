#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>

namespace hook_fucker {
	namespace utility {

		auto str(const char* str1, const char* str2) {
			while (*str1 && *str2) {
				if (*str1 < *str2)
					return -1;
				if (*str1 > *str2)
					return 1;
				++str1; ++str2;
			}
			return *str1 ? -1 : *str2 ? 1 : 0;
		}

		void* get_func(std::string module, LPCSTR api)
		{
			DWORD base = (DWORD)GetModuleHandleA(module.c_str());
			if (!base)
				return 0;
			PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)base;
			if (pDOS->e_magic != IMAGE_DOS_SIGNATURE)
				return 0;
			PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(base + (DWORD)pDOS->e_lfanew);
			if (pNT->Signature != IMAGE_NT_SIGNATURE)
				return 0;
			PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(base + pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (!pExport)
				return 0;
			auto names = (PDWORD)(base + pExport->AddressOfNames);
			auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
			auto functions = (PDWORD)(base + pExport->AddressOfFunctions);
			for (auto i = 0; i < pExport->NumberOfFunctions; ++i) {
				LPCSTR name = (LPCSTR)(base + names[i]);
				if (!str(name, api))
					return (void*)(base + functions[ordinals[i]]);
			}
		}

	}

	namespace globals {
		std::vector<BYTE> g_bytes;
		std::vector<uint8_t> g_abytes{ 0xCC, 0x90 };
	}

#define PushBack(arg) globals::g_bytes.push_back(arg);

	//THIS FUNCTION IS FULLY CREDITED TO https://github.com/Zpes/copy-calling/blob/master/copy-calling/copy_calling.cpp
	void* allocate_memory_close_to_address(void* address, const std::size_t size)
	{
		SYSTEM_INFO system_info{};
		GetSystemInfo(&system_info);

		const auto page_size = static_cast<std::uintptr_t>(system_info.dwPageSize);

		const auto start_adress = (reinterpret_cast<std::uintptr_t>(address) & ~(page_size - 1));
		const auto min = min(start_adress - 0x7FFFFF00, reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress));
		const auto max = max(start_adress + 0x7FFFFF00, reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress));

		const auto start_page = (start_adress - (start_adress % page_size));

		std::size_t page = 1;
		while (true)
		{
			const auto byte_offset = page * page_size;
			const auto high = start_page + byte_offset;
			const auto low = (start_page > byte_offset) ? start_page - byte_offset : 0;

			const auto stop_point = high > max && low < min;

			if (!low)
				continue;

			if (high < max)
			{
				auto const out_addr = VirtualAlloc(reinterpret_cast<void*>(high), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (out_addr)
					return out_addr;
			}

			if (low > min)
			{
				auto const out_addr = VirtualAlloc(reinterpret_cast<void*>(low), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (out_addr)
					return out_addr;
			}

			page++;

			if (stop_point)
				break;
		}

		return nullptr;
	}

	void* copy_function(std::string modName, std::string Func)
	{
		void* function_addr = (void*)utility::get_func(modName, Func.c_str()); //literally just GetProcAddress but remade to avoid triggering hooks that sometimes are placed on this winapi func
		if (function_addr)
			return NULL;

		for (auto i = 0u;; i++)
		{
			BYTE* b_address = (BYTE*)((uintptr_t)(function_addr)+(i * sizeof(BYTE)));
			auto kill = false;

			PushBack(*b_address);

			uint8_t op = 0xC3;
			uint8_t sz = 0xC2;

			if (*(b_address - sz) == op)
			{
				for (auto indx : globals::g_abytes)
					if (*(b_address + 1) == indx)
					{
						kill = true;
						break;
					}

				if (kill)
					break;
			}

			if (kill)
				break;
		}

		////https://github.com/Zpes/copy-calling/blob/master/copy-calling/copy_calling.cpp
		void* allocated_mem = (void*)allocate_memory_close_to_address(function_addr, globals::g_bytes.size());

		auto memcopy = memcpy(allocated_mem, globals::g_bytes.data(), globals::g_bytes.size());
		if (memcopy)
			return memcopy;

		return NULL;
	}

}