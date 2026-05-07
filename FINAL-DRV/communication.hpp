#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include "shared_memory_ipc.h"

inline uintptr_t virtualaddy;
inline uintptr_t cr3;
inline uintptr_t Base;

namespace mem {
	inline INT32 process_id;
	
	__declspec(align(4096)) __declspec(selectany) char g_ipc_buffer_storage[IPC_TOTAL_SIZE];
	inline PIPC_MEMORY const ipc_mem = reinterpret_cast<PIPC_MEMORY>(g_ipc_buffer_storage);

	inline IPC_SLOT* get_slot(int idx)        { return &ipc_mem->slots[idx]; }
	inline void*     get_cmd_data(int idx)    { return &ipc_mem->slots[idx].cmd_data; }
	inline void*     get_data_buffer(int idx) { return  ipc_mem->slots[idx].data_buffer; }

	#define IPC_DATA_SIZE ((int)IPC_SLOT_DATA_SIZE)

	inline bool send_command(int slot_idx, UINT32 command, UINT32 target_pid, int timeout_ms = 5000)
	{
		IPC_SLOT* hdr = get_slot(slot_idx);

		hdr->command = CMD_IDLE;
		MemoryBarrier();
		hdr->process_id = target_pid;
		hdr->status = STATUS_IPC_IDLE;
		MemoryBarrier();
		hdr->command = command;

		int elapsed = 0;
		while (elapsed < timeout_ms)
		{
			if (hdr->status == STATUS_IPC_SUCCESS || hdr->status == STATUS_IPC_ERROR)
				break;

			Sleep(1);
			elapsed++;
		}

		return hdr->status == STATUS_IPC_SUCCESS;
	}

	inline bool find_driver() {
		memset(ipc_mem, 0, IPC_TOTAL_SIZE);
		ipc_mem->magic        = IPC_MAGIC;
		ipc_mem->version      = IPC_VERSION;
		ipc_mem->active_slots = IPC_MAX_SLOTS;

		for (int i = 0; i < IPC_MAX_SLOTS; i++) {
			ipc_mem->slots[i].slot_state = SLOT_STATE_FREE;
			ipc_mem->slots[i].status     = STATUS_IPC_IDLE;
			ipc_mem->slots[i].command    = CMD_IDLE;
		}

		int attempts = 0;
		while (!send_command(0, CMD_PING, 0, 1000))
		{
			attempts++;
			Sleep(500);
			if (attempts >= 60) return false;
		}
		return true;
	}

	inline void read_physical(PVOID address, PVOID buffer, DWORD size) {
		unsigned char* p = (unsigned char*)buffer;
		size_t remaining = size;
		uint64_t curr_addr = (uint64_t)address;

		while (remaining > 0)
		{
			size_t chunk = (remaining > IPC_DATA_SIZE) ? IPC_DATA_SIZE : remaining;
			
			IPC_RW_DATA* rw = (IPC_RW_DATA*)get_cmd_data(0);
			rw->target_address = curr_addr;
			rw->buffer_size = chunk;
			rw->is_write = 0;
			rw->use_cr3 = 1; // Use CR3 to bypass EAC
			
			if (!send_command(0, CMD_READ_MEMORY, process_id, 10000))
				break;
				
			memcpy(p, get_data_buffer(0), chunk);
			
			remaining -= chunk;
			curr_addr += chunk;
			p += chunk;
		}
	}

	inline void write_physical(PVOID address, PVOID buffer, DWORD size) {
		const unsigned char* p = (const unsigned char*)buffer;
		size_t remaining = size;
		uint64_t curr_addr = (uint64_t)address;

		while (remaining > 0)
		{
			size_t chunk = (remaining > IPC_DATA_SIZE) ? IPC_DATA_SIZE : remaining;
			
			IPC_RW_DATA* rw = (IPC_RW_DATA*)get_cmd_data(0);
			rw->target_address = curr_addr;
			rw->buffer_size = chunk;
			rw->is_write = 1;
			rw->use_cr3 = 1; // Use CR3 to bypass EAC
			
			memcpy(get_data_buffer(0), p, chunk);
			
			if (!send_command(0, CMD_WRITE_MEMORY, process_id, 10000))
				break;
				
			remaining -= chunk;
			curr_addr += chunk;
			p += chunk;
		}
	}

	inline uintptr_t fetch_cr3() {
		if (send_command(0, CMD_RESOLVE_DTB, process_id)) {
			IPC_RESULT_DATA* result = (IPC_RESULT_DATA*)get_cmd_data(0);
			return result->result;
		}
		return 0;
	}

	inline uintptr_t find_image() {
		if (send_command(0, CMD_GET_BASE_ADDRESS, process_id)) {
			IPC_RESULT_DATA* result = (IPC_RESULT_DATA*)get_cmd_data(0);
			return result->result;
		}
		return 0;
	}

	inline uintptr_t get_guarded_region() {
		if (send_command(0, CMD_GET_GUARDED_REGION, process_id)) {
			IPC_RESULT_DATA* result = (IPC_RESULT_DATA*)get_cmd_data(0);
			return result->result;
		}
		return 0;
	}

	inline INT32 find_process(LPCTSTR process_name) {
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name)) {
					CloseHandle(hsnap);
					process_id = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);
		return 0;
	}
}

template <typename T>
inline T read(uint64_t address) {
	T buffer{ };
	mem::read_physical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

template <typename T>
inline T write(uint64_t address, T buffer) {
	mem::write_physical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}