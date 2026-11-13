#pragma once
using nt_load_driver_t = NTSTATUS( __fastcall* )( PUNICODE_STRING );

namespace service {
    std::wstring get_driver_filename( const wchar_t* service_name ) {
        HKEY hKey;
        if ( RegOpenKeyW( HKEY_LOCAL_MACHINE,
            ( L"SYSTEM\\CurrentControlSet\\Services\\" + std::wstring( service_name ) ).c_str( ),
            &hKey ) != ERROR_SUCCESS )
            return L"";

        wchar_t imagePath[ MAX_PATH ];
        DWORD size = sizeof( imagePath );
        DWORD type = 0;
        if ( RegQueryValueExW( hKey, L"ImagePath", nullptr, &type,
            ( LPBYTE )imagePath, &size ) != ERROR_SUCCESS ||
            ( type != REG_SZ && type != REG_EXPAND_SZ ) ) {
            RegCloseKey( hKey );
            return L"";
        }
        RegCloseKey( hKey );

        if ( type == REG_EXPAND_SZ ) {
            wchar_t expanded[ MAX_PATH ];
            if ( ExpandEnvironmentStringsW( imagePath, expanded, MAX_PATH ) )
                wcscpy_s( imagePath, expanded );
        }

        std::wstring path( imagePath );
        const wchar_t* prefix = L"\\??\\";
        if ( path.find( prefix ) == 0 )
            path.erase( 0, wcslen( prefix ) );

        size_t pos = path.find_last_of( L'\\' );
        if ( pos != std::wstring::npos )
            return path.substr( pos + 1 );
        return path;
    }

    bool create_service( const wchar_t* service_name, const wchar_t* registry_path ) {
        if ( !service_name || !registry_path ) {
            utility::print( obf( "[ - ]" ), obf( "invalid service name or registry path" ) );
            return false;
        }

        HKEY service_key = nullptr;
        auto result = RegOpenKeyA(
            HKEY_LOCAL_MACHINE,
            obf( "system\\CurrentControlSet\\Services" ),
            &service_key
        );

        if ( result != ERROR_SUCCESS ) {
            utility::print( obf( "[ - ]" ), obf( "failed to open services key: %d" ), result );
            return false;
        }

        HKEY service_config_key = nullptr;
        result = RegCreateKeyW(
            service_key,
            service_name,
            &service_config_key
        );

        if ( result != ERROR_SUCCESS ) {
            RegCloseKey( service_key );
            utility::print( obf( "[ - ]" ), obf( "failed to create service key: %d" ), result );
            return false;
        }

        const auto path_len = ( std::wcslen( registry_path ) + 1 ) << 1;
        result = RegSetValueExW(
            service_config_key,
            obf( L"ImagePath" ),
            0,
            REG_EXPAND_SZ,
            reinterpret_cast< const std::uint8_t* >( registry_path ),
            path_len
        );

        if ( result != ERROR_SUCCESS ) {
            RegCloseKey( service_config_key );
            RegCloseKey( service_key );
            utility::print( obf( "[ - ]" ), obf( "failed to set ImagePath: %d" ), result );
            return false;
        }

        const DWORD type = 1;
        result = RegSetValueExA(
            service_config_key,
            obf( "Type" ),
            0,
            REG_DWORD,
            reinterpret_cast< const std::uint8_t* >( &type ),
            sizeof( type )
        );

        RegCloseKey( service_config_key );
        RegCloseKey( service_key );

        if ( result != ERROR_SUCCESS ) {
            utility::print( obf( "[ - ]" ), obf( "failed to set Type: %d" ), result );
            return false;
        }

        return true;
    }

    UNICODE_STRING build_driver_path( const wchar_t* service_name ) {
        if ( !service_name || service_name[ 0 ] == L'\0' ) {
            return {};
        }

        static wchar_t registry_path[ MAX_PATH ]{};
        std::memset( registry_path, 0, sizeof( registry_path ) );
        wcscpy_s( registry_path, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" );
        wcscat_s( registry_path, service_name );

        UNICODE_STRING driver_path{};
        driver_path.Length = USHORT( std::wcslen( registry_path ) << 1 );
        driver_path.Buffer = registry_path;
        driver_path.MaximumLength = driver_path.Length + 2;

        return driver_path;
    }

    bool uninstall_service( const wchar_t* service_name ) {
        if ( !service_name || service_name[ 0 ] == L'\0' ) {
            return false;
        }

        using nt_unload_driver_t = NTSTATUS( __stdcall* )( PUNICODE_STRING );
        auto* nt_unload_drv = reinterpret_cast< nt_unload_driver_t >(
            GetProcAddress(
                GetModuleHandleA( obf( "ntdll.dll" ) ),
                obf( "NtUnloadDriver" )
            )
            );

        if ( !nt_unload_drv ) {
            utility::print( obf( "[ - ]" ), obf( "failed to get NtUnloadDriver" ) );
            return false;
        }

        auto driver_nt_name = build_driver_path( service_name );
        if ( !driver_nt_name.Buffer ) {
            utility::print( obf( "[ - ]" ), obf( "failed to build driver path" ) );
            return false;
        }

        const auto status = nt_unload_drv( &driver_nt_name );
        if ( status != 0 && status != 0xc0000034 && status != 0xc000000e ) {
            // Continue cleaning registry key even if driver was not currently active in memory
        }

        HKEY services_key = nullptr;
        auto result = RegOpenKeyA(
            HKEY_LOCAL_MACHINE,
            obf( "SYSTEM\\CurrentControlSet\\Services" ),
            &services_key
        );

        if ( result != ERROR_SUCCESS ) {
            utility::print( obf( "[ - ]" ), obf( "failed to open services key: %d" ), result );
            return false;
        }

        result = RegDeleteTreeW( services_key, service_name );
        RegCloseKey( services_key );

        return result == ERROR_SUCCESS;
    }

    bool uninstall_services( ) {
        HKEY services_key = nullptr;
        if ( RegOpenKeyA(
            HKEY_LOCAL_MACHINE,
            obf( "SYSTEM\\CurrentControlSet\\Services" ),
            &services_key ) != ERROR_SUCCESS ) {
            utility::print( obf( "[ - ]" ), obf( "failed to open services key" ) );
            return false;
        }

        DWORD index = 0;
        wchar_t service_name[ MAX_PATH ];

        while ( !RegEnumKeyW( services_key, index, service_name, MAX_PATH ) ) {
            HKEY service_key = nullptr;
            if ( !RegOpenKeyW( services_key, service_name, &service_key ) ) {
                wchar_t image_path[ MAX_PATH ];
                DWORD path_size = sizeof( image_path );
                DWORD type = REG_EXPAND_SZ;

                if ( RegQueryValueExW( service_key, obf( L"ImagePath" ), nullptr, &type,
                    reinterpret_cast< LPBYTE >( image_path ), &path_size ) == ERROR_SUCCESS ) {
                    if ( wcsstr( image_path, obf( L"\\??\\" ) ) != nullptr &&
                        wcsstr( image_path, obf( L".log" ) ) != nullptr ) {
                        uninstall_service( service_name );
                    }
                }
                RegCloseKey( service_key );
            }
            index++;
        }

        RegCloseKey( services_key );
        return true;
    }

    bool load_service( const wchar_t* service_name ) {
        if ( !service_name || service_name[ 0 ] == L'\0' ) {
            utility::print( obf( "[ - ]" ), obf( "invalid service name" ) );
            return false;
        }

        auto driver_nt_name = build_driver_path( service_name );
        if ( !driver_nt_name.Buffer ) {
            utility::print( obf( "[ - ]" ), obf( "failed to build driver path" ) );
            return false;
        }

        auto* nt_load_drv = reinterpret_cast< nt_load_driver_t >(
            GetProcAddress(
                GetModuleHandleA( obf( "ntdll.dll" ) ),
                obf( "NtLoadDriver" ) )
            );

        if ( !nt_load_drv ) {
            utility::print( obf( "[ - ]" ), obf( "failed to get NtLoadDriver" ) );
            return false;
        }

        auto status = nt_load_drv( &driver_nt_name );
        if ( status == 0xc000010e || status == 0xc0000035 ) {
            using nt_unload_driver_t = NTSTATUS( __stdcall* )( PUNICODE_STRING );
            auto* nt_unload_drv = reinterpret_cast< nt_unload_driver_t >(
                GetProcAddress( GetModuleHandleA( obf( "ntdll.dll" ) ), obf( "NtUnloadDriver" ) )
            );
            if ( nt_unload_drv ) {
                nt_unload_drv( &driver_nt_name );
                status = nt_load_drv( &driver_nt_name );
            }
        }

        if ( status != 0 ) {
            utility::print( obf( "[ - ]" ), obf( "NtLoadDriver failed: 0x%08x" ), static_cast< unsigned int >( status ) );
            return false;
        }

        return true;
    }

    bool install_service( const wchar_t* service_name, const wchar_t* registry_path ) {
        if ( !service_name || service_name[ 0 ] == L'\0' || !registry_path || registry_path[ 0 ] == L'\0' ) {
            utility::print( obf( "[ - ]" ), obf( "invalid service name or driver path" ) );
            return false;
        }

        uninstall_service( service_name );

        if ( !create_service( service_name, registry_path ) ) {
            utility::print( obf( "[ - ]" ), obf( "failed to register kernel driver" ) );
            return false;
        }

        return load_service( service_name );
    }
}
