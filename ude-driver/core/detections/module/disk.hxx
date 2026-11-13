#pragma once

namespace module::disk {
	constexpr auto m_text_chunk_size = 0x1000ul;

	constexpr const char* m_whitelisted_modules[] = {
		"ntoskrnl.exe",
		"tm.sys",
		"clipsp.sys",
		"PSHED.dll",
		"BOOTVID.dll",
		"cng.sys",
		"kdcom.dll",
		"kd.dll",
		"NETIO.SYS",
		"TDI.SYS",
		"storport.sys",
		"ndis.sys",
		"WppRecorder.sys",
		"WDFLDR.SYS",
		"CLASSPNP.SYS",
		"WMILIB.SYS",
		"Wdf01000.sys",
		"CLFS.SYS",
		"msrpc.sys",
		"cmimcext.sys",
		"CI.dll",
		"dxgkrnl.sys",
		"werkernel.sys",
		"ntosext.sys"
	};

	const IMAGE_NT_HEADERS64* validate_pe_image( const unsigned char* image_base, size_t image_size ) {
		return memory::validate_pe_image( image_base, image_size );
	}

	const IMAGE_SECTION_HEADER* find_section_by_name( const unsigned char* image_base, size_t image_size, const char* section_name ) {
		auto nt_headers = validate_pe_image( image_base, image_size );
		if ( !nt_headers )
			return nullptr;

		auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( nt_headers ) );
		for ( auto index = 0u; index < nt_headers->FileHeader.NumberOfSections; index++ ) {
			char current_name[ 9 ]{ };
			memcpy( current_name, sections[ index ].Name, sizeof( sections[ index ].Name ) );

			if ( ascii_equal_insensitive( current_name, section_name ) )
				return &sections[ index ];
		}

		return nullptr;
	}

	const IMAGE_SECTION_HEADER* find_section_by_rva( const unsigned char* image_base, size_t image_size, unsigned long rva ) {
		auto nt_headers = validate_pe_image( image_base, image_size );
		if ( !nt_headers )
			return nullptr;

		auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( nt_headers ) );
		for ( auto index = 0u; index < nt_headers->FileHeader.NumberOfSections; index++ ) {
			auto section = &sections[ index ];
			auto section_size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;

			if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section_size )
				return section;
		}

		return nullptr;
	}

	const unsigned char* rva_to_raw_pointer( const unsigned char* image_base, size_t image_size, unsigned long rva, size_t bytes ) {
		auto nt_headers = validate_pe_image( image_base, image_size );
		if ( !nt_headers )
			return nullptr;

		if ( rva < nt_headers->OptionalHeader.SizeOfHeaders ) {
			if ( bytes > image_size || rva > image_size - bytes || !memory::is_range_resident( image_base + rva, bytes ) )
				return nullptr;

			return image_base + rva;
		}

		auto section = find_section_by_rva( image_base, image_size, rva );
		if ( !section )
			return nullptr;

		auto section_offset = rva - section->VirtualAddress;
		if ( section_offset >= section->SizeOfRawData )
			return nullptr;

		auto raw_offset = section->PointerToRawData + section_offset;
		if ( raw_offset >= image_size || bytes > image_size - raw_offset || !memory::is_range_resident( image_base + raw_offset, bytes ) )
			return nullptr;

		return image_base + raw_offset;
	}

	const system_module_t* find_module_by_file_name( const system_modules_t* modules, const char* module_name ) {
		if ( !modules || !module_name )
			return nullptr;

		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto module = &modules->m_modules[ index ];
			auto file_name = reinterpret_cast< const char* >( module->m_full_path_name ) + module->m_offset_to_file_name;

			if ( ascii_equal_insensitive( file_name, module_name ) )
				return module;
		}

		return nullptr;
	}

	const char* lookup_address_owner( const system_modules_t* modules, unsigned long long address ) {
		if ( !modules || !address )
			return nullptr;

		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto module = &modules->m_modules[ index ];
			auto base = reinterpret_cast< unsigned long long >( module->m_image_base );
			auto end = base + module->m_image_size;

			if ( address >= base && address < end )
				return reinterpret_cast< const char* >( module->m_full_path_name ) + module->m_offset_to_file_name;
		}

		return nullptr;
	}

	const system_module_t* find_module_by_address( const system_modules_t* modules, unsigned long long address ) {
		if ( !modules || !address )
			return nullptr;

		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto module = &modules->m_modules[ index ];
			auto base = reinterpret_cast< unsigned long long >( module->m_image_base );
			auto end = base + module->m_image_size;

			if ( address >= base && address < end )
				return module;
		}

		return nullptr;
	}

	bool is_address_in_executable_section( const system_module_t* module, unsigned long long address, char* section_name, size_t section_name_size ) {
		if ( section_name && section_name_size )
			section_name[ 0 ] = 0;

		if ( !module || !module->m_image_base || !address || module->m_image_size < PAGE_SIZE )
			return false;

		auto base = reinterpret_cast< unsigned long long >( module->m_image_base );
		if ( address < base || address >= base + module->m_image_size )
			return false;

		unsigned char header_page[ PAGE_SIZE ]{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( module->m_image_base, sizeof( header_page ), header_page, &copied ) ) {
			paging::pt_entries_t entries{ };
			if ( !paging::hyperspace_entries( entries, address ) )
				return false;
			if ( section_name && section_name_size )
				RtlStringCbCopyA( section_name, section_name_size, ".code" );
			return entries.m_pdpte.hard.page_size ? !entries.m_pdpte.hard.no_execute :
				entries.m_pde.hard.page_size ? !entries.m_pde.hard.no_execute :
				!entries.m_pte.hard.no_execute;
		}

		auto nt_headers = validate_pe_image( header_page, sizeof( header_page ) );
		if ( !nt_headers )
			return false;

		auto rva = static_cast< unsigned long >( address - base );
		auto section = find_section_by_rva( header_page, sizeof( header_page ), rva );
		if ( !section )
			return false;

		if ( section_name && section_name_size ) {
			auto copy_size = sizeof( section->Name );
			if ( copy_size >= section_name_size )
				copy_size = section_name_size - 1;

			memcpy( section_name, section->Name, copy_size );
			section_name[ copy_size ] = 0;
		}

		return ( section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0;
	}

	bool is_whitelisted_owner( const char* owner ) {
		if ( !owner )
			return false;

		for ( auto index = 0ul; index < ARRAYSIZE( m_whitelisted_modules ); index++ ) {
			if ( ascii_equal_insensitive( owner, m_whitelisted_modules[ index ] ) )
				return true;
		}

		return false;
	}

	NTSTATUS read_module_image_from_disk( const system_module_t& module, void** image_buffer, unsigned long* image_size ) {
		if ( !image_buffer || !image_size )
			return STATUS_INVALID_PARAMETER;

		*image_buffer = nullptr;
		*image_size = 0;

		ANSI_STRING ansi_path{ };
		UNICODE_STRING unicode_path{ };
		RtlInitAnsiString( &ansi_path, reinterpret_cast< const char* >( module.m_full_path_name ) );

		auto status = RtlAnsiStringToUnicodeString( &unicode_path, &ansi_path, TRUE );
		if ( status )
			return status;

		OBJECT_ATTRIBUTES attributes{ };
		IO_STATUS_BLOCK io_status{ };
		InitializeObjectAttributes( &attributes, &unicode_path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr );

		HANDLE file_handle = nullptr;
		status = ZwCreateFile(
			&file_handle,
			GENERIC_READ,
			&attributes,
			&io_status,
			nullptr,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			nullptr,
			0
		);

		RtlFreeUnicodeString( &unicode_path );

		if ( status )
			return status;

		FILE_STANDARD_INFORMATION standard_information{ };
		status = ZwQueryInformationFile(
			file_handle,
			&io_status,
			&standard_information,
			sizeof( standard_information ),
			FileStandardInformation
		);

		if ( status ) {
			ZwClose( file_handle );
			return status;
		}

		if ( standard_information.EndOfFile.QuadPart <= 0 || standard_information.EndOfFile.QuadPart > 64ll * 1024ll * 1024ll ) {
			ZwClose( file_handle );
			return STATUS_INVALID_IMAGE_FORMAT;
		}

		auto size = static_cast< unsigned long >( standard_information.EndOfFile.QuadPart );
		auto buffer = memory::allocate_pool ( size, 1 );
		if ( !buffer ) {
			ZwClose( file_handle );
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		memset( buffer, 0, size );

		LARGE_INTEGER byte_offset{ };
		status = ZwReadFile( file_handle, nullptr, nullptr, nullptr, &io_status, buffer, size, &byte_offset, nullptr );
		ZwClose( file_handle );

		if ( status ) {
			memory::free_pool( buffer );
			return status;
		}

		*image_buffer = buffer;
		*image_size = size;
		return STATUS_SUCCESS;
	}

	bool copy_export_name( const unsigned char* disk_image, unsigned long disk_image_size, const IMAGE_EXPORT_DIRECTORY* export_directory, unsigned long ordinal, char* buffer, size_t buffer_size ) {
		if ( !disk_image || !export_directory || !buffer || !buffer_size )
			return false;

		buffer[ 0 ] = 0;

		auto names = reinterpret_cast< const unsigned long* >( rva_to_raw_pointer(
			disk_image,
			disk_image_size,
			export_directory->AddressOfNames,
			sizeof( unsigned long ) * export_directory->NumberOfNames
		) );

		auto ordinals = reinterpret_cast< const unsigned short* >( rva_to_raw_pointer(
			disk_image,
			disk_image_size,
			export_directory->AddressOfNameOrdinals,
			sizeof( unsigned short ) * export_directory->NumberOfNames
		) );

		if ( !names || !ordinals )
			return false;

		for ( auto index = 0ul; index < export_directory->NumberOfNames; index++ ) {
			if ( ordinals[ index ] != ordinal )
				continue;

			auto name = reinterpret_cast< const char* >( rva_to_raw_pointer( disk_image, disk_image_size, names[ index ], 1 ) );
			if ( !name )
				return false;

			return !RtlStringCbCopyA( buffer, buffer_size, name );
		}

		return false;
	}

	unsigned long relocation_entry_size( unsigned short relocation_type ) {
		switch ( relocation_type ) {
		case 3:
			return sizeof( unsigned long );
		case 10:
			return sizeof( unsigned long long );
		default:
			return 0;
		}
	}

	unsigned long normalize_relocated_bytes( const unsigned char* disk_image, unsigned long disk_image_size, unsigned long section_rva, unsigned long section_size, const unsigned char* live_bytes, unsigned char* disk_bytes ) {
		if ( !disk_image || !section_size || !live_bytes || !disk_bytes )
			return 0;

		auto nt_headers = validate_pe_image( disk_image, disk_image_size );
		if ( !nt_headers )
			return 0;

		auto directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
		if ( !directory.VirtualAddress || directory.Size < sizeof( IMAGE_BASE_RELOCATION ) )
			return 0;

		unsigned long normalized = 0;
		unsigned long offset = 0;
		auto section_end = section_rva + section_size;

		while ( offset + sizeof( IMAGE_BASE_RELOCATION ) <= directory.Size ) {
			auto block = reinterpret_cast< const IMAGE_BASE_RELOCATION* >( rva_to_raw_pointer(
				disk_image,
				disk_image_size,
				directory.VirtualAddress + offset,
				sizeof( IMAGE_BASE_RELOCATION )
			) );

			if ( !block || block->SizeOfBlock < sizeof( IMAGE_BASE_RELOCATION ) )
				break;

			if ( offset + block->SizeOfBlock > directory.Size )
				break;

			auto entry_bytes = block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION );
			auto entries = reinterpret_cast< const unsigned short* >( rva_to_raw_pointer(
				disk_image,
				disk_image_size,
				directory.VirtualAddress + offset + sizeof( IMAGE_BASE_RELOCATION ),
				entry_bytes
			) );

			if ( !entries )
				break;

			auto entry_count = entry_bytes / sizeof( unsigned short );
			for ( auto index = 0ul; index < entry_count; index++ ) {
				auto entry = entries[ index ];
				auto type = static_cast< unsigned short >( entry >> 12 );
				auto fixup_size = relocation_entry_size( type );
				if ( !fixup_size )
					continue;

				auto fixup_rva = block->VirtualAddress + ( entry & 0xfff );
				auto fixup_end = fixup_rva + fixup_size;
				if ( fixup_end <= section_rva || fixup_rva >= section_end )
					continue;

				auto overlap_start = fixup_rva > section_rva ? fixup_rva : section_rva;
				auto overlap_end = fixup_end < section_end ? fixup_end : section_end;

				for ( auto rva = overlap_start; rva < overlap_end; rva++ ) {
					auto section_offset = rva - section_rva;
					disk_bytes[ section_offset ] = live_bytes[ section_offset ];
					normalized++;
				}
			}

			offset += block->SizeOfBlock;
		}

		return normalized;
	}

	void copy_section_name( const IMAGE_SECTION_HEADER* section, char* buffer, size_t buffer_size ) {
		if ( !section || !buffer || !buffer_size )
			return;

		buffer[ 0 ] = 0;
		auto copy_size = sizeof( section->Name );
		if ( copy_size >= buffer_size )
			copy_size = buffer_size - 1;

		memcpy( buffer, section->Name, copy_size );
		buffer[ copy_size ] = 0;
	}
}
