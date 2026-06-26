#pragma once

namespace device_surface {
	constexpr auto m_directory_buffer_size = 0x2000ul;

	struct target_info_t {
		const system_module_t* m_module;
		const char* m_owner;
		char m_section[ 9 ];
		bool m_executable;
		bool m_pte_valid;
		bool m_bad_backing;
		bool m_writable;
		bool m_user;
		bool m_nx;
		unsigned long long m_pfn;
		unsigned long long m_walk_pa;
		unsigned long long m_api_pa;
	};

	struct loader_module_entry_t {
		LIST_ENTRY m_load_order_links;
		void* m_exception_table;
		unsigned long m_exception_table_size;
		unsigned long m_padding;
		void* m_gp_value;
		void* m_non_paged_debug_info;
		void* m_dll_base;
		void* m_entry_point;
		unsigned long m_size_of_image;
		unsigned long m_size_padding;
		UNICODE_STRING m_full_dll_name;
		UNICODE_STRING m_base_dll_name;
		unsigned long m_flags;
		unsigned short m_load_count;
		unsigned short m_signature;
		void* m_section_pointer;
	};

	bool unicode_to_ascii( const UNICODE_STRING& unicode, char* buffer, size_t buffer_size ) {
		if ( !buffer || !buffer_size )
			return false;

		buffer[ 0 ] = 0;
		if ( !unicode.Buffer || !unicode.Length )
			return false;

		ANSI_STRING ansi{ };
		if ( RtlUnicodeStringToAnsiString( &ansi, const_cast< UNICODE_STRING* >( &unicode ), TRUE ) )
			return false;

		auto ok = !RtlStringCbCopyA( buffer, buffer_size, ansi.Buffer );
		RtlFreeAnsiString( &ansi );
		return ok;
	}

	bool open_driver_directory( HANDLE* handle ) {
		if ( !handle )
			return false;

		*handle = nullptr;
		UNICODE_STRING path = RTL_CONSTANT_STRING( L"\\Driver" );
		OBJECT_ATTRIBUTES attributes{ };
		InitializeObjectAttributes( &attributes, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr );
		return !ZwOpenDirectoryObject( handle, DIRECTORY_QUERY, &attributes );
	}

	bool open_object_directory( const wchar_t* path, HANDLE* handle ) {
		if ( !path || !handle )
			return false;

		*handle = nullptr;
		UNICODE_STRING directory_path{ };
		RtlInitUnicodeString( &directory_path, path );

		OBJECT_ATTRIBUTES attributes{ };
		InitializeObjectAttributes( &attributes, &directory_path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr );
		return !ZwOpenDirectoryObject( handle, DIRECTORY_QUERY, &attributes );
	}

	void module_driver_name( const system_module_t* module, char* buffer, size_t buffer_size ) {
		if ( !buffer || !buffer_size )
			return;

		buffer[ 0 ] = 0;
		if ( !module )
			return;

		auto name = reinterpret_cast< const char* >( module->m_full_path_name ) + module->m_offset_to_file_name;
		if ( !name )
			return;

		auto out = 0ull;
		for ( ; name[ out ] && name[ out ] != '.' && out + 1 < buffer_size; out++ )
			buffer[ out ] = name[ out ];

		buffer[ out ] = 0;
	}

	bool reference_driver_object( const char* driver_name, PDRIVER_OBJECT* driver_object ) {
		if ( !driver_name || !driver_object )
			return false;

		*driver_object = nullptr;

		char path[ 128 ]{ };
		RtlStringCbPrintfA( path, sizeof( path ), "\\Driver\\%s", driver_name );

		ANSI_STRING ansi{ };
		UNICODE_STRING unicode{ };
		RtlInitAnsiString( &ansi, path );
		if ( RtlAnsiStringToUnicodeString( &unicode, &ansi, TRUE ) )
			return false;

		void* object = nullptr;
		auto status = ObReferenceObjectByName(
			&unicode,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			nullptr,
			0,
			*IoDriverObjectType,
			KernelMode,
			nullptr,
			&object
		);

		RtlFreeUnicodeString( &unicode );
		if ( status || !object )
			return false;

		*driver_object = static_cast< PDRIVER_OBJECT >( object );
		return true;
	}

	bool reference_device_object( const char* device_name, PDEVICE_OBJECT* device_object ) {
		if ( !device_name || !device_object || !IoDeviceObjectType || !*IoDeviceObjectType )
			return false;

		*device_object = nullptr;

		char path[ 160 ]{ };
		RtlStringCbPrintfA( path, sizeof( path ), "\\Device\\%s", device_name );

		ANSI_STRING ansi{ };
		UNICODE_STRING unicode{ };
		RtlInitAnsiString( &ansi, path );
		if ( RtlAnsiStringToUnicodeString( &unicode, &ansi, TRUE ) )
			return false;

		void* object = nullptr;
		auto status = ObReferenceObjectByName(
			&unicode,
			OBJ_CASE_INSENSITIVE,
			nullptr,
			0,
			*IoDeviceObjectType,
			KernelMode,
			nullptr,
			&object
		);

		if ( !status && object ) {
			RtlFreeUnicodeString( &unicode );
			*device_object = static_cast< PDEVICE_OBJECT >( object );
			return true;
		}

		// Device object types have a parse procedure, so a direct object-manager
		// reference can fail even though the named device is reachable. Fall back
		// to the I/O-manager path and retain our own reference after releasing the
		// temporary FILE_OBJECT returned by IoGetDeviceObjectPointer.
		PFILE_OBJECT file_object = nullptr;
		PDEVICE_OBJECT resolved_device = nullptr;
		status = IoGetDeviceObjectPointer(
			&unicode,
			FILE_READ_ATTRIBUTES,
			&file_object,
			&resolved_device
		);
		RtlFreeUnicodeString( &unicode );
		if ( status || !file_object || !resolved_device ) {
			if ( file_object )
				ObDereferenceObject( file_object );
			return false;
		}

		ObReferenceObject( resolved_device );
		ObDereferenceObject( file_object );
		*device_object = resolved_device;
		return true;
	}

	bool module_has_executable_section( const system_module_t* module ) {
		if ( !module || !module->m_image_base || module->m_image_size < PAGE_SIZE )
			return false;

		auto image_base = static_cast< const unsigned char* >( module->m_image_base );
		auto nt_headers = memory::validate_pe_image( image_base, module->m_image_size );
		if ( !nt_headers )
			return false;

		auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( nt_headers ) );
		for ( auto index = 0u; index < nt_headers->FileHeader.NumberOfSections; index++ ) {
			if ( sections[ index ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
				return true;
		}

		return false;
	}

	bool is_system_module_path( const system_module_t* module ) {
		if ( !module )
			return false;

		auto path = reinterpret_cast< const char* >( module->m_full_path_name );
		return
			ascii_starts_with_insensitive( path, "\\SystemRoot\\" ) ||
			ascii_starts_with_insensitive( path, "\\Windows\\" ) ||
			ascii_starts_with_insensitive( path, "\\??\\C:\\Windows\\" ) ||
			ascii_starts_with_insensitive( path, "C:\\Windows\\" );
	}

	void strip_extension( const char* name, char* buffer, size_t buffer_size ) {
		if ( !buffer || !buffer_size )
			return;

		buffer[ 0 ] = 0;
		if ( !name )
			return;

		auto out = 0ull;
		for ( ; name[ out ] && name[ out ] != '.' && out + 1 < buffer_size; out++ )
			buffer[ out ] = name[ out ];

		buffer[ out ] = 0;
	}

	const system_module_t* find_module_by_exact_base( const system_modules_t* modules, unsigned long long base ) {
		if ( !modules || !base )
			return nullptr;

		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto module = &modules->m_modules[ index ];
			if ( reinterpret_cast< unsigned long long >( module->m_image_base ) == base )
				return module;
		}

		return nullptr;
	}

	bool read_loader_entry( LIST_ENTRY* link, loader_module_entry_t* entry ) {
		if ( !link || !entry )
			return false;

		size_t copied = 0;
		return memory::copy_kernel_memory( link, sizeof( *entry ), entry, &copied );
	}

	unsigned long long resolve_relative_address( unsigned long long instruction, long offset, unsigned long instruction_size ) {
		long displacement = 0;
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( instruction + offset ), sizeof( displacement ), &displacement, &copied ) )
			return 0;

		return instruction + instruction_size + displacement;
	}

	bool match_pattern_byte( unsigned char byte, const char* token ) {
		if ( !token || token[ 0 ] == '?' )
			return true;

		auto hex_value = []( char c ) -> int {
			if ( c >= '0' && c <= '9' )
				return c - '0';
			if ( c >= 'A' && c <= 'F' )
				return c - 'A' + 10;
			if ( c >= 'a' && c <= 'f' )
				return c - 'a' + 10;
			return -1;
		};

		auto high = hex_value( token[ 0 ] );
		auto low = hex_value( token[ 1 ] );
		if ( high < 0 || low < 0 )
			return false;

		return byte == static_cast< unsigned char >( ( high << 4 ) | low );
	}

	bool pattern_matches( const unsigned char* bytes, unsigned long size, unsigned long offset, const char* pattern ) {
		if ( !bytes || !pattern )
			return false;

		char token[ 3 ]{ };
		unsigned long pattern_index = 0;
		unsigned long byte_index = offset;

		while ( pattern[ pattern_index ] ) {
			while ( pattern[ pattern_index ] == ' ' )
				pattern_index++;

			if ( !pattern[ pattern_index ] )
				break;

			if ( byte_index >= size )
				return false;

			token[ 0 ] = pattern[ pattern_index ];
			token[ 1 ] = pattern[ pattern_index + 1 ];
			token[ 2 ] = 0;

			if ( !match_pattern_byte( bytes[ byte_index ], token ) )
				return false;

			byte_index++;
			pattern_index += token[ 0 ] == '?' ? 1 : 2;
		}

		return true;
	}

	unsigned long long find_ps_loaded_module_list_pattern( const system_modules_t* modules ) {
		auto nt = module::disk::find_module_by_file_name( modules, "ntoskrnl.exe" );
		if ( !nt || !nt->m_image_base || !nt->m_image_size )
			return 0;

		auto image = static_cast< const unsigned char* >( nt->m_image_base );
		auto headers = memory::validate_pe_image( image, nt->m_image_size );
		if ( !headers )
			return 0;

		auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( headers ) );
		for ( auto index = 0u; index < headers->FileHeader.NumberOfSections; index++ ) {
			char section_name[ 9 ]{ };
			memory::copy_section_name( &sections[ index ], section_name, sizeof( section_name ) );
			if ( !ascii_equal_insensitive( section_name, ".text" ) )
				continue;

			auto section_size = sections[ index ].Misc.VirtualSize ? sections[ index ].Misc.VirtualSize : sections[ index ].SizeOfRawData;
			auto section_base = reinterpret_cast< unsigned long long >( nt->m_image_base ) + sections[ index ].VirtualAddress;
			auto snapshot = memory::allocate_pool< unsigned char* >( section_size, 1 );
			if ( !snapshot )
				return 0;

			memset( snapshot, 0, section_size );
			size_t copied = 0;
			auto copied_section = memory::copy_kernel_memory( reinterpret_cast< void* >( section_base ), section_size, snapshot, &copied );
			if ( !copied_section ) {
				memory::free_pool( snapshot );
				return 0;
			}

			for ( auto offset = 0ul; offset + 8 < section_size; offset++ ) {
				if ( !pattern_matches( snapshot, section_size, offset, "4C 8B 35 ? ? ? ? BA" ) )
					continue;

				auto resolved = resolve_relative_address( section_base + offset, 3, 7 );
				memory::free_pool( snapshot );
				return resolved;
			}

			memory::free_pool( snapshot );
		}

		return 0;
	}

	bool copy_unicode_name( const UNICODE_STRING& unicode, char* buffer, size_t buffer_size ) {
		if ( !buffer || !buffer_size )
			return false;

		buffer[ 0 ] = 0;
		if ( !unicode.Buffer || !unicode.Length )
			return false;

		return unicode_to_ascii( unicode, buffer, buffer_size );
	}

	void query_target_info( const system_modules_t* modules, unsigned long long address, target_info_t* info ) {
		if ( !info )
			return;

		memset( info, 0, sizeof( *info ) );
		if ( !modules || !address )
			return;

		info->m_module = module::disk::find_module_by_address( modules, address );
		if ( info->m_module ) {
			info->m_owner = reinterpret_cast< const char* >( info->m_module->m_full_path_name ) + info->m_module->m_offset_to_file_name;
			info->m_executable = module::disk::is_address_in_executable_section( info->m_module, address, info->m_section, sizeof( info->m_section ) );
		}

		paging::pt_entries_t entries{ };
		info->m_pte_valid = paging::hyperspace_entries( entries, address );
		if ( !info->m_pte_valid )
			return;

		if ( entries.m_pdpte.hard.page_size ) {
			info->m_pfn = entries.m_pdpte.hard.pfn;
			info->m_writable = entries.m_pdpte.hard.read_write;
			info->m_user = entries.m_pdpte.hard.user_supervisor;
			info->m_nx = entries.m_pdpte.hard.no_execute;
		}
		else if ( entries.m_pde.hard.page_size ) {
			info->m_pfn = entries.m_pde.hard.pfn;
			info->m_writable = entries.m_pde.hard.read_write;
			info->m_user = entries.m_pde.hard.user_supervisor;
			info->m_nx = entries.m_pde.hard.no_execute;
		}
		else {
			info->m_pfn = entries.m_pte.hard.pfn;
			info->m_writable = entries.m_pte.hard.read_write;
			info->m_user = entries.m_pte.hard.user_supervisor;
			info->m_nx = entries.m_pte.hard.no_execute;
		}

		std::uint32_t page_size = 0;
		paging::translate_linear( address, &info->m_walk_pa, &page_size );
		auto api_pa = MmGetPhysicalAddress( reinterpret_cast< void* >( address ) );
		info->m_api_pa = static_cast< unsigned long long >( api_pa.QuadPart );
		info->m_bad_backing = ( info->m_walk_pa && info->m_api_pa && info->m_walk_pa != info->m_api_pa ) || info->m_user || info->m_nx;
	}
}

namespace device_surface::object {
	unsigned long scan_device_chain( ioctl::command_t* command, PDRIVER_OBJECT driver_object, const char* driver_name ) {
		if ( !command || !driver_object )
			return 0;

		unsigned long detections = 0;
		unsigned long devices = 0;
		auto device = driver_object->DeviceObject;

		while ( device && devices < 256 ) {
			devices++;
			if ( device->DriverObject != driver_object ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"device=0x%llx driver=0x%llx expected=0x%llx index=%lu",
					reinterpret_cast< unsigned long long >( device ),
					reinterpret_cast< unsigned long long >( device->DriverObject ),
					reinterpret_cast< unsigned long long >( driver_object ),
					devices - 1
				);

				report::add_memory_detection(
					command,
					driver_name ? driver_name : "driver",
					report::m_device_object_chain_violation,
					detail,
					reinterpret_cast< unsigned long long >( device ),
					sizeof( DEVICE_OBJECT )
				);
				detections++;
			}

			device = device->NextDevice;
		}

		if ( device ) {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA( detail, sizeof( detail ), "driver=0x%llx device_chain_limit=256", reinterpret_cast< unsigned long long >( driver_object ) );
			report::add_memory_detection(
				command,
				driver_name ? driver_name : "driver",
				report::m_device_object_chain_violation,
				detail,
				reinterpret_cast< unsigned long long >( driver_object ),
				sizeof( DRIVER_OBJECT )
			);
			detections++;
		}

		return detections;
	}
}
