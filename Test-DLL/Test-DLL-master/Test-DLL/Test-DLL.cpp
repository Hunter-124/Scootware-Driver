#include <Windows.h>

extern "C" __declspec(dllexport)
DWORD WINAPI DisplayMessageBox(LPVOID parameter)
{
	MessageBoxA(nullptr, "DLL Successfully Loaded", "Test DLL", 0);
	return 0;
}

extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
		{
			CreateThread(nullptr, 0, DisplayMessageBox, nullptr, 0, nullptr);
			break;
		}

		case DLL_THREAD_ATTACH:
		{
			break;
		}

		case DLL_PROCESS_DETACH:
		{
			break;
		}

		case DLL_THREAD_DETACH:
		{
			break;
		}
	}

	return true;
}