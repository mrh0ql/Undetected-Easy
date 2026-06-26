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
		} m_pdb;

		struct offsets_t {
		} m_offsets;

		std::uint64_t m_image_base;
		std::uint64_t m_image_size;
		std::uint64_t m_ntoskrnl_base;
		std::uint64_t m_directory_table_base;
	};

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

			HANDLE token;
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

			if ( !result || GetLastError( ) == ERROR_NOT_ALL_ASSIGNED ) {
				result = AdjustTokenPrivileges(
					token,
					TRUE,
					&privilege,
					sizeof( privilege ),
					nullptr,
					nullptr
				);
			}

			NtClose( token );

			if ( !result || GetLastError( ) == ERROR_NOT_ALL_ASSIGNED ) {
				utility::print( obf( "[ - ]" ), obf( "AdjustTokenPrivileges failed: 0x%x" ), GetLastError( ) );
				return false;
			}

			TOKEN_PRIVILEGES verify_privilege{ };
			DWORD length;
			if ( GetTokenInformation( token, TokenPrivileges, &verify_privilege, sizeof( verify_privilege ), &length ) ) {
				utility::print( obf( "[ - ]" ), obf( "privilege state after adjustment: 0x%x" ),
					verify_privilege.Privileges[ 0 ].Attributes );
			}

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
