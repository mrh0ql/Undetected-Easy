#pragma once
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <vector>
#include <iostream>
#include <conio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <winternl.h>
#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_
#include <cstdint>
#include <DbgHelp.h>
#include <thread>
#include <functional>
#include <map>
#include <atlbase.h>
#include <string>
#include <memory>
#include <random>
#include <ntstatus.h>
#include <psapi.h>
#include <dia2.h>
#include <diacreate.h>
#include <array>
#include <unordered_map>
#include <atomic>
#include <numbers>
#include <unordered_set>
#include <aclapi.h>
#include <winevt.h>
#include <shared_mutex>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wevtapi.lib")

#include <ext/obfuscation/obfuscation.h>
#include <ext/ia32/ia32.h>

#include <core/utility/utility.hxx>
#include <core/blocklist/blocklist.hxx>
#include <core/driver/driver.hxx>

#include <ext/service/bytes.h>
#include <ext/service/service.hxx>

#include <deps/pdb/pdb.hxx>
auto g_pdb = std::make_shared<pdb::c_pdb>( obf( "ntoskrnl.exe" ) );

#include <ext/service/driver.hxx>
auto g_service = std::make_shared<service::c_service>( );
auto g_driver = std::make_shared<driver::c_driver>( );

#include <deps/gui/render/types.hxx>
#include <deps/gui/render/window.hxx>
#include <deps/gui/render/device.hxx>
#include <deps/gui/render/renderer.hxx>
#include <deps/gui/render/overlay.hxx>
auto g_overlay = std::make_shared<render::c_overlay>( );

#include <deps/gui/widgets/stages/stage.hxx>
#include <deps/gui/widgets/stages/welcome/welcome.hxx>
#include <deps/gui/widgets/stages/dashboard/dashboard.hxx>

#include <deps/gui/widgets/widgets.hxx>
