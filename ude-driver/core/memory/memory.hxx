#pragma once

namespace memory {
	bool is_canonical_kernel_address( unsigned long long address ) {
		return address >= 0xffff800000000000ull;
	}

	template < typename type_t >
	type_t allocate_pages( std::size_t size ) {
		if ( !size )
			return { };

		auto base_address = allocate_pool< void* >( size, NonPagedPool );
		if ( !base_address )
			return { };

		memset( base_address, 0, size );
		return reinterpret_cast< type_t >( base_address );
	}

	void free_pages( std::uint64_t base_address, std::size_t size ) {
		UNREFERENCED_PARAMETER( size );
		if ( base_address )
			free_pool( reinterpret_cast< void* >( base_address ) );
	}

	struct scoped_page_t {
		unsigned char* m_bytes;

		scoped_page_t( )
			: m_bytes( allocate_pool< unsigned char* >( PAGE_SIZE, 1 ) ) {
			if ( m_bytes )
				memset( m_bytes, 0, PAGE_SIZE );
		}

		~scoped_page_t( ) {
			if ( m_bytes )
				free_pool( m_bytes );
		}

		scoped_page_t( const scoped_page_t& ) = delete;
		scoped_page_t& operator=( const scoped_page_t& ) = delete;

		explicit operator bool( ) const {
			return m_bytes != nullptr;
		}

		unsigned char* get( ) const {
			return m_bytes;
		}
	};

	bool copy_kernel_memory( void* source, size_t size, void* destination, size_t* bytes_copied ) {
		if ( bytes_copied )
			*bytes_copied = 0;

		if ( !source || !destination || !size )
			return false;

		auto current_va = reinterpret_cast< unsigned long long >( source );
		if ( !is_canonical_kernel_address( current_va ) || current_va + size < current_va )
			return false;

		auto dst = static_cast< unsigned char* >( destination );
		size_t total_copied = 0;

		while ( total_copied < size ) {
			if ( !is_canonical_kernel_address( current_va ) ||
				!MmIsAddressValid( reinterpret_cast< void* >( current_va ) ) )
				return false;

			auto page_offset = static_cast< size_t >( current_va & ( PAGE_SIZE - 1 ) );
			auto chunk = static_cast< size_t >( PAGE_SIZE ) - page_offset;
			auto remaining = size - total_copied;
			if ( chunk > remaining )
				chunk = remaining;

			std::uint64_t physical_address = 0;
			std::uint32_t translated_page_size = 0;
			if ( !paging::translate_linear( current_va, &physical_address, &translated_page_size ) || !physical_address )
				return false;

			if ( !paging::remap::read_physical_page_chunk( physical_address, dst + total_copied, chunk ) )
				return false;

			current_va += chunk;
			total_copied += chunk;
		}

		if ( bytes_copied )
			*bytes_copied = total_copied;

		return true;
	}

	bool query_system_modules( system_modules_t** modules ) {
		if ( !modules )
			return false;

		*modules = nullptr;

		unsigned long bytes = 0;
		auto status = ZwQuerySystemInformation( m_system_module_information, nullptr, 0, &bytes );
		if ( status != STATUS_INFO_LENGTH_MISMATCH )
			return false;

		for ( auto attempt = 0ul; attempt < 3; attempt++ ) {
			if ( !bytes )
				return false;

			auto buffer = allocate_pool< void* >( bytes, 1 );
			if ( !buffer )
				return false;

			memset( buffer, 0, bytes );

			auto query_bytes = bytes;
			status = ZwQuerySystemInformation( m_system_module_information, buffer, bytes, &query_bytes );
			if ( !status ) {
				*modules = static_cast< system_modules_t* >( buffer );
				return true;
			}

			free_pool( buffer );

			if ( status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW )
				return false;

			bytes = query_bytes;
		}

		return false;
	}

	bool is_range_resident( const void* address, size_t size ) {
		if ( !address || !size )
			return false;

		auto start = reinterpret_cast< unsigned long long >( address );
		if ( !is_canonical_kernel_address( start ) )
			return false;

		auto end = start + size;
		if ( end < start )
			return false;

		auto first_page = start & ~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 );
		auto last_page = ( end - 1 ) & ~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 );
		for ( auto page = first_page; page <= last_page; page += PAGE_SIZE ) {
			if ( !MmIsAddressValid( reinterpret_cast< void* >( page ) ) )
				return false;
		}

		return true;
	}

	const IMAGE_NT_HEADERS64* validate_pe_image( const unsigned char* image_base, size_t image_size ) {
		if ( !image_base || image_size < 0x400 )
			return nullptr;

		if ( !is_range_resident( image_base, sizeof( IMAGE_DOS_HEADER ) ) )
			return nullptr;

		auto dos_header = reinterpret_cast< const IMAGE_DOS_HEADER* >( image_base );
		if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
			return nullptr;

		if ( dos_header->e_lfanew <= 0 ||
			static_cast< size_t >( dos_header->e_lfanew ) > 0x100000ul ||
			static_cast< size_t >( dos_header->e_lfanew ) > image_size - sizeof( IMAGE_NT_HEADERS64 ) )
			return nullptr;

		auto nt_headers = reinterpret_cast< const IMAGE_NT_HEADERS64* >( image_base + dos_header->e_lfanew );
		if ( !is_range_resident( nt_headers, sizeof( IMAGE_NT_HEADERS64 ) ) )
			return nullptr;

		if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
			return nullptr;

		if ( nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 )
			return nullptr;

		if ( nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return nullptr;

		if ( nt_headers->FileHeader.NumberOfSections > 96u )
			return nullptr;

		auto section_table_end =
			static_cast< size_t >( dos_header->e_lfanew ) +
			FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +
			nt_headers->FileHeader.SizeOfOptionalHeader +
			sizeof( IMAGE_SECTION_HEADER ) * nt_headers->FileHeader.NumberOfSections;

		if ( section_table_end > image_size || !is_range_resident( image_base, section_table_end ) )
			return nullptr;

		return nt_headers;
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
			if ( bytes > image_size || rva > image_size - bytes )
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
		if ( raw_offset >= image_size || bytes > image_size - raw_offset )
			return nullptr;

		return image_base + raw_offset;
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
}
