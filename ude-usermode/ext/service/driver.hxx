#pragma once

namespace service {
	struct driver_config_t {
		struct symbols_t {
			std::uint64_t m_mm_allocate_independent_pages;
			std::uint64_t m_mm_free_independent_pages;
			std::uint64_t m_mm_set_page_protection;
			std::uint64_t m_mi_lock_page_table_page;
			std::uint64_t m_mi_is_page_on_bad_list;
			std::uint64_t m_mi_make_page_bad;
			std::uint64_t m_ps_loaded_module_list;
			std::uint64_t m_pi_ddb_cache_table;
			std::uint64_t m_pi_ddb_lock;
			std::uint64_t m_mm_unloaded_drivers;
			std::uint64_t m_mm_last_unloaded_driver;
			std::uint64_t m_hal_dispatch_table;
			std::uint64_t m_hal_private_dispatch_table;
			std::uint64_t m_ki_wait_never;
			std::uint64_t m_ki_wait_always;
			std::uint64_t m_kd_debugger_not_present;
			std::uint64_t m_kd_pitch_debugger;
			std::uint64_t m_psp_create_process_notify_routine;
			std::uint64_t m_psp_create_thread_notify_routine;
			std::uint64_t m_psp_load_image_notify_routine;
			std::uint64_t m_cm_callback_list_head;
			std::uint64_t m_ke_service_descriptor_table;
			std::uint64_t m_ke_service_descriptor_table_shadow;
			std::uint64_t m_mm_pfn_database;
			std::uint64_t m_etw_threat_int_prov_reg_handle;
			std::uint64_t m_hal_send_nmi;
			std::uint64_t m_ci_kernel_hash_bucket_list;
			std::uint64_t m_ci_hash_cache_lock;
			std::uint64_t m_flt_globals;
			std::uint64_t m_ndis_global_filter_list;
			std::uint64_t m_ci_g_ci_options;
			std::uint64_t m_ki_nmi_callback_list_head;
			std::uint64_t m_ke_bugcheck_callback_list_head;
			std::uint64_t m_ke_bugcheck_reason_callback_list_head;
			std::uint64_t m_wmip_logger_context;
			std::uint64_t m_kd_enumerate_debugging_devices;
			std::uint64_t m_se_validate_image_header;
			std::uint64_t m_se_validate_image_data;
			std::uint64_t m_ob_type_index_table;
		} m_pdb;

		struct offsets_t {
			std::uint64_t m_kprcb_timer_table;
			std::uint64_t m_kprcb_dpc_data;
			std::uint64_t m_kthread_previous_mode;
			std::uint64_t m_kthread_misc_flags;
			std::uint64_t m_kthread_apc_state;
			std::uint64_t m_kthread_start_address;
			std::uint64_t m_kthread_win32_start_address;
			std::uint64_t m_object_type_callback_list;
			std::uint64_t m_mmpfn_size;
			std::uint64_t m_mmpfn_pte_address;
			std::uint64_t m_mmpfn_u4;
			std::uint64_t m_wmi_logger_get_cpu_clock;
			std::uint64_t m_object_type_name;
			std::uint64_t m_object_type_type_info;
			std::uint64_t m_object_type_init_dump_proc;
			std::uint64_t m_flt_globals_frame_list;
			std::uint64_t m_fltp_frame_links;
			std::uint64_t m_fltp_frame_registered_filters;
			std::uint64_t m_flt_object_primary_link;
			std::uint64_t m_flt_filter_driver_object;
			std::uint64_t m_flt_filter_operations;
		} m_offsets;

		std::uint64_t m_image_base;
		std::uint64_t m_image_size;
		std::uint64_t m_ntoskrnl_base;
		std::uint64_t m_directory_table_base;
	};
	static_assert( sizeof( driver_config_t ) == 512, "driver_config_t layout must match entry_t" );

	class c_service {
	public:
		bool test_signing_enabled( ) {
			return is_test_signing_enabled( );
		}

		bool request_test_signing( ) {
			return enable_test_signing( );
		}

		bool request_restart( ) {
			return restart_pc( );
		}

		bool create( const wchar_t* driver_path ) {
			if ( !driver_path || !driver_path[ 0 ] ) {
				utility::print( obf( "[ - ]" ), obf( "invalid driver path." ) );
				return false;
			}

			if ( !is_test_signing_enabled( ) ) {
				utility::print( obf( "[ - ]" ), obf( "test signing is not enabled." ) );

				if ( enable_test_signing( ) ) {
					utility::print_line( obf( "[ * ]" ), obf( "enabled test signing. restart now? " ) );

					char command[ 16 ]{ };
					std::cin.getline( command, sizeof( command ) );
					if ( std::strlen( command ) > 0 ) {
						if ( _stricmp( command, obf( "yes" ) ) == 0 || _stricmp( command, obf( "y" ) ) == 0 ) {
							restart_pc( );
							Sleep( 5000 );
						}
					}

					utility::print( obf( "[ * ]" ), obf( "restart your pc and try again." ) );
					return false;
				}

				utility::print( obf( "[ - ]" ), obf( "failed to enable test signing. run as admin or disable secure boot.\n" ) );
				return false;
			}

			if ( !load_driver_privilage( true ) ) {
				utility::print( obf( "[ - ]" ), obf( "failed to enable driver loading privilege." ) );
				return false;
			}

			std::memset( m_driver_path, 0, sizeof( m_driver_path ) );
			std::memset( m_driver_name, 0, sizeof( m_driver_name ) );

			const wchar_t* prefix = obf( L"\\??\\" );
			if ( std::wcsncmp( driver_path, prefix, std::wcslen( prefix ) ) != 0 )
				std::wcscat( m_driver_path, prefix );
			std::wcscat( m_driver_path, driver_path );

			const wchar_t* file_name = std::wcsrchr( driver_path, L'\\' );
			if ( !file_name )
				file_name = std::wcsrchr( driver_path, L'/' );
			file_name = file_name ? file_name + 1 : driver_path;

			std::wcscat( m_driver_name, file_name );
			wchar_t* extension = std::wcsrchr( m_driver_name, L'.' );
			if ( extension )
				*extension = L'\0';

			uninstall_service( m_driver_name );

			if ( !create_service( m_driver_name, m_driver_path ) ) {
				load_driver_privilage( false );
				return false;
			}

			if ( !create_config( m_driver_name ) ) {
				uninstall_service( m_driver_name );
				load_driver_privilage( false );
				return false;
			}

			if ( !load_service( m_driver_name ) ) {
				uninstall_service( m_driver_name );
				load_driver_privilage( false );
				return false;
			}

			return true;
		}

		bool unload( ) {
			uninstall_service( m_driver_name );
			load_driver_privilage( false );
			return true;
		}

	private:
		wchar_t m_driver_name[ MAX_PATH ]{ };
		wchar_t m_driver_path[ MAX_PATH ]{ };

		std::uint32_t get_timestamp( ) {
			auto dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( driver_bytes );
			if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
				return 0;

			auto nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS64 >( reinterpret_cast< std::uint64_t >( driver_bytes ) + dos_header->e_lfanew );
			if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
				return 0;

			return nt_headers->FileHeader.TimeDateStamp;
		}

		bool load_driver_privilage( bool enabled ) {
			TOKEN_PRIVILEGES privilege{};
			privilege.PrivilegeCount = 1;

			if ( !LookupPrivilegeValueA(
				nullptr,
				obf( "SeLoadDriverPrivilege" ),
				&privilege.Privileges[ 0 ].Luid ) ) {
				utility::print( obf( "[ - ]" ), obf( "LookupPrivilegeValue failed: 0x%x" ), GetLastError( ) );
				return false;
			}

			HANDLE token = nullptr;
			if ( !OpenProcessToken(
				GetCurrentProcess( ),
				TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
				&token ) ) {
				utility::print( obf( "[ - ]" ), obf( "OpenProcessToken failed: 0x%x" ), GetLastError( ) );
				return false;
			}

			privilege.Privileges[ 0 ].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;

			auto result = AdjustTokenPrivileges(
				token,
				FALSE,
				&privilege,
				sizeof( privilege ),
				nullptr,
				nullptr
			);

			auto last_error = GetLastError( );
			if ( !result || last_error == ERROR_NOT_ALL_ASSIGNED ) {
				result = AdjustTokenPrivileges(
					token,
					TRUE,
					&privilege,
					sizeof( privilege ),
					nullptr,
					nullptr
				);
				last_error = GetLastError( );
			}

			if ( !result || last_error == ERROR_NOT_ALL_ASSIGNED ) {
				NtClose( token );
				utility::print( obf( "[ - ]" ), obf( "AdjustTokenPrivileges failed: 0x%x" ), last_error );
				return false;
			}

			TOKEN_PRIVILEGES verify_privilege{ };
			DWORD length = 0;
			if ( GetTokenInformation( token, TokenPrivileges, &verify_privilege, sizeof( verify_privilege ), &length ) ) {
				utility::print( obf( "[ + ]" ), obf( "privilege state after adjustment: 0x%x" ),
					verify_privilege.Privileges[ 0 ].Attributes );
			}

			NtClose( token );
			return true;
		}

		bool is_test_signing_enabled( ) {
			auto ntdll = GetModuleHandleW ( obf( L"ntdll.dll" ) );
			if ( !ntdll )
				return false;

			using nt_query_system_information_t = NTSTATUS( NTAPI* )(
				SYSTEM_INFORMATION_CLASS system_information_class,
				PVOID system_information,
				ULONG system_information_length,
				PULONG return_length
				);

			auto nt_query_system_information =
				reinterpret_cast< nt_query_system_information_t >(
					GetProcAddress( ntdll, "NtQuerySystemInformation" )
					);

			if ( !nt_query_system_information )
				return false;

			system_codeintegrity_information_t info = {};
			info.Length = sizeof( info );

			NTSTATUS status = nt_query_system_information(
				SystemCodeIntegrityInformation,
				&info,
				sizeof( info ),
				nullptr
			);

			if ( status < 0 )
				return false;

			return ( info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN ) != 0;
		}

		bool enable_test_signing( ) {
			SHELLEXECUTEINFOA info = { };
			info.cbSize = sizeof( info );
			info.fMask = SEE_MASK_NOCLOSEPROCESS;
			info.lpVerb = "runas";
			info.lpFile = "bcdedit.exe";
			info.lpParameters = "/set testsigning on";
			info.nShow = SW_HIDE;

			if ( !ShellExecuteExA( &info ) )
				return false;

			WaitForSingleObject( info.hProcess, INFINITE );

			DWORD exit_code = 1;
			GetExitCodeProcess( info.hProcess, &exit_code );
			CloseHandle( info.hProcess );

			return exit_code == 0;
		}

		bool restart_pc( ) {
			SHELLEXECUTEINFOA info = { };
			info.cbSize = sizeof( info );
			info.fMask = SEE_MASK_NOCLOSEPROCESS;
			info.lpVerb = "runas";
			info.lpFile = "shutdown.exe";
			info.lpParameters = "/r /t 0";
			info.nShow = SW_HIDE;

			if ( !ShellExecuteExA( &info ) )
				return false;

			if ( info.hProcess ) {
				CloseHandle( info.hProcess );
			}

			return true;
		}

		bool create_config( const wchar_t* service_name ) {
			if ( !service_name || service_name[ 0 ] == L'\0' )
				return false;

			driver_config_t config{ };
			config.m_ntoskrnl_base = g_pdb->m_module_base;
			config.m_pdb.m_mm_allocate_independent_pages = g_pdb->get_symbol_address( obf( "MmAllocateIndependentPages" ) );
			config.m_pdb.m_mm_free_independent_pages = g_pdb->get_symbol_address( obf( "MmFreeIndependentPages" ) );
			config.m_pdb.m_mm_set_page_protection = g_pdb->get_symbol_address( obf( "MmSetPageProtection" ) );
			config.m_pdb.m_mi_lock_page_table_page = g_pdb->get_symbol_address( obf( "MiLockPageTablePage" ) );
			config.m_pdb.m_mi_is_page_on_bad_list = g_pdb->get_symbol_address( obf( "MiIsPageOnBadList" ) );
			config.m_pdb.m_mi_make_page_bad = g_pdb->get_symbol_address( obf( "MiMakePageBad" ) );
			config.m_pdb.m_ps_loaded_module_list = g_pdb->get_symbol_address( obf( "PsLoadedModuleList" ) );
			config.m_pdb.m_pi_ddb_cache_table = g_pdb->get_symbol_address( obf( "PiDDBCacheTable" ) );
			config.m_pdb.m_pi_ddb_lock = g_pdb->get_symbol_address( obf( "PiDDBLock" ) );
			config.m_pdb.m_mm_unloaded_drivers = g_pdb->get_symbol_address( obf( "MmUnloadedDrivers" ) );
			config.m_pdb.m_mm_last_unloaded_driver = g_pdb->get_symbol_address( obf( "MmLastUnloadedDriver" ) );
			config.m_pdb.m_hal_dispatch_table = g_pdb->get_symbol_address( obf( "HalDispatchTable" ) );
			config.m_pdb.m_hal_private_dispatch_table = g_pdb->get_symbol_address( obf( "HalPrivateDispatchTable" ) );
			config.m_pdb.m_ki_wait_never = g_pdb->get_symbol_address( obf( "KiWaitNever" ) );
			config.m_pdb.m_ki_wait_always = g_pdb->get_symbol_address( obf( "KiWaitAlways" ) );
			config.m_pdb.m_kd_debugger_not_present = g_pdb->get_symbol_address( obf( "KdDebuggerNotPresent" ) );
			config.m_pdb.m_kd_pitch_debugger = g_pdb->get_symbol_address( obf( "KdPitchDebugger" ) );
			config.m_pdb.m_psp_create_process_notify_routine = g_pdb->get_symbol_address( obf( "PspCreateProcessNotifyRoutine" ) );
			config.m_pdb.m_psp_create_thread_notify_routine = g_pdb->get_symbol_address( obf( "PspCreateThreadNotifyRoutine" ) );
			config.m_pdb.m_psp_load_image_notify_routine = g_pdb->get_symbol_address( obf( "PspLoadImageNotifyRoutine" ) );
			config.m_pdb.m_cm_callback_list_head = g_pdb->get_symbol_address( obf( "CmCallbackListHead" ) );
			config.m_pdb.m_ke_service_descriptor_table = g_pdb->get_symbol_address( obf( "KeServiceDescriptorTable" ) );
			config.m_pdb.m_ke_service_descriptor_table_shadow = g_pdb->get_symbol_address( obf( "KeServiceDescriptorTableShadow" ) );
			config.m_pdb.m_mm_pfn_database = g_pdb->get_symbol_address( obf( "MmPfnDatabase" ) );
			config.m_pdb.m_etw_threat_int_prov_reg_handle = g_pdb->get_symbol_address( obf( "EtwThreatIntProvRegHandle" ) );
			config.m_pdb.m_hal_send_nmi = g_pdb->get_symbol_address( obf( "HalSendNMI" ) );
			config.m_pdb.m_ki_nmi_callback_list_head = g_pdb->get_symbol_address( obf( "KiNmiCallbackListHead" ) );
			config.m_pdb.m_ke_bugcheck_callback_list_head = g_pdb->get_symbol_address( obf( "KeBugCheckCallbackListHead" ) );
			config.m_pdb.m_ke_bugcheck_reason_callback_list_head = g_pdb->get_symbol_address( obf( "KeBugCheckReasonCallbackListHead" ) );
			config.m_pdb.m_wmip_logger_context = g_pdb->get_symbol_address( obf( "WmipLoggerContext" ) );
			config.m_pdb.m_kd_enumerate_debugging_devices = g_pdb->get_symbol_address( obf( "KdEnumerateDebuggingDevices" ) );
			config.m_pdb.m_se_validate_image_header = g_pdb->get_symbol_address( obf( "SeValidateImageHeader" ) );
			config.m_pdb.m_se_validate_image_data = g_pdb->get_symbol_address( obf( "SeValidateImageData" ) );
			config.m_pdb.m_ob_type_index_table = g_pdb->get_symbol_address( obf( "ObTypeIndexTable" ) );

			config.m_offsets.m_kprcb_timer_table = g_pdb->get_struct_member( obf( "_KPRCB" ), obf( "TimerTable" ) );
			config.m_offsets.m_kprcb_dpc_data = g_pdb->get_struct_member( obf( "_KPRCB" ), obf( "DpcData" ) );
			config.m_offsets.m_kthread_previous_mode = g_pdb->get_struct_member( obf( "_KTHREAD" ), obf( "PreviousMode" ) );
			config.m_offsets.m_kthread_misc_flags = g_pdb->get_struct_member( obf( "_KTHREAD" ), obf( "MiscFlags" ) );
			config.m_offsets.m_kthread_apc_state = g_pdb->get_struct_member( obf( "_KTHREAD" ), obf( "ApcState" ) );
			config.m_offsets.m_kthread_start_address = g_pdb->get_struct_member( obf( "_ETHREAD" ), obf( "StartAddress" ) );
			if ( !config.m_offsets.m_kthread_start_address )
				config.m_offsets.m_kthread_start_address = g_pdb->get_struct_member( obf( "_KTHREAD" ), obf( "StartAddress" ) );
			config.m_offsets.m_kthread_win32_start_address = g_pdb->get_struct_member( obf( "_ETHREAD" ), obf( "Win32StartAddress" ) );
			config.m_offsets.m_object_type_callback_list = g_pdb->get_struct_member( obf( "_OBJECT_TYPE" ), obf( "CallbackList" ) );
			config.m_offsets.m_mmpfn_size = g_pdb->get_struct_size( obf( "_MMPFN" ) );
			config.m_offsets.m_mmpfn_pte_address = g_pdb->get_struct_member( obf( "_MMPFN" ), obf( "PteAddress" ) );
			config.m_offsets.m_mmpfn_u4 = g_pdb->get_struct_member( obf( "_MMPFN" ), obf( "u4" ) );
			config.m_offsets.m_wmi_logger_get_cpu_clock = g_pdb->get_struct_member( obf( "_WMI_LOGGER_CONTEXT" ), obf( "GetCpuClock" ) );
			config.m_offsets.m_object_type_name = g_pdb->get_struct_member( obf( "_OBJECT_TYPE" ), obf( "Name" ) );
			config.m_offsets.m_object_type_type_info = g_pdb->get_struct_member( obf( "_OBJECT_TYPE" ), obf( "TypeInfo" ) );
			config.m_offsets.m_object_type_init_dump_proc = g_pdb->get_struct_member( obf( "_OBJECT_TYPE_INITIALIZER" ), obf( "DumpProcedure" ) );

			{
				pdb::c_pdb ci_pdb( obf( "CI.dll" ) );
				if ( ci_pdb.load( ) ) {
					config.m_pdb.m_ci_kernel_hash_bucket_list = ci_pdb.get_symbol_address( obf( "g_KernelHashBucketList" ) );
					config.m_pdb.m_ci_hash_cache_lock = ci_pdb.get_symbol_address( obf( "g_HashCacheLock" ) );
					config.m_pdb.m_ci_g_ci_options = ci_pdb.get_symbol_address( obf( "g_CiOptions" ) );
				}
			}
			{
				pdb::c_pdb flt_pdb( obf( "drivers\\FLTMGR.SYS" ) );
				if ( flt_pdb.load( ) ) {
					config.m_pdb.m_flt_globals = flt_pdb.get_symbol_address( obf( "FltGlobals" ) );
					auto rlist_off = flt_pdb.get_struct_member( obf( "_FLT_RESOURCE_LIST_HEAD" ), obf( "rList" ) );
					if ( !rlist_off )
						rlist_off = 0x68;
					auto frame_list = flt_pdb.get_struct_member( obf( "_GLOBALS" ), obf( "FrameList" ) );
					if ( frame_list || flt_pdb.get_struct_size( obf( "_GLOBALS" ) ) )
						config.m_offsets.m_flt_globals_frame_list = frame_list + rlist_off;
					config.m_offsets.m_fltp_frame_links = flt_pdb.get_struct_member( obf( "_FLTP_FRAME" ), obf( "Links" ) );
					auto reg_filters = flt_pdb.get_struct_member( obf( "_FLTP_FRAME" ), obf( "RegisteredFilters" ) );
					if ( reg_filters )
						config.m_offsets.m_fltp_frame_registered_filters = reg_filters + rlist_off;
					auto flt_base = flt_pdb.get_struct_member( obf( "_FLT_FILTER" ), obf( "Base" ) );
					auto prim_link = flt_pdb.get_struct_member( obf( "_FLT_OBJECT" ), obf( "PrimaryLink" ) );
					if ( prim_link )
						config.m_offsets.m_flt_object_primary_link = flt_base + prim_link;
					config.m_offsets.m_flt_filter_driver_object = flt_pdb.get_struct_member( obf( "_FLT_FILTER" ), obf( "DriverObject" ) );
					config.m_offsets.m_flt_filter_operations = flt_pdb.get_struct_member( obf( "_FLT_FILTER" ), obf( "Operations" ) );
				}
			}
			{
				pdb::c_pdb ndis_pdb( obf( "drivers\\ndis.sys" ) );
				if ( ndis_pdb.load( ) )
					config.m_pdb.m_ndis_global_filter_list = ndis_pdb.get_symbol_address( obf( "ndisGlobalFilterList" ) );
			}

			HKEY service_key = nullptr;
			auto key_path = std::wstring( obf( L"SYSTEM\\CurrentControlSet\\Services\\" ) ) + service_name;
			auto result = RegOpenKeyExW( HKEY_LOCAL_MACHINE, key_path.c_str( ), 0, KEY_WRITE, &service_key );
			if ( result != ERROR_SUCCESS ) {
				utility::print( obf( "[ - ]" ), obf( "failed to open service key for config: %d" ), result );
				return false;
			}

			HKEY parameters_key = nullptr;
			result = RegCreateKeyExW(
				service_key,
				obf( L"Parameters" ),
				0,
				nullptr,
				REG_OPTION_NON_VOLATILE,
				KEY_WRITE,
				nullptr,
				&parameters_key,
				nullptr
			);

			RegCloseKey( service_key );

			if ( result != ERROR_SUCCESS ) {
				utility::print( obf( "[ - ]" ), obf( "failed to create Parameters key: %d" ), result );
				return false;
			}

			result = RegSetValueExW(
				parameters_key,
				obf( L"Config" ),
				0,
				REG_BINARY,
				reinterpret_cast< const BYTE* >( &config ),
				sizeof( config )
			);

			RegCloseKey( parameters_key );

			if ( result != ERROR_SUCCESS ) {
				utility::print( obf( "[ - ]" ), obf( "failed to write config: %d" ), result );
				return false;
			}

			utility::print( obf( "[ + ]" ), obf( "configurated service" ) );
			return true;
		}
	};
}
