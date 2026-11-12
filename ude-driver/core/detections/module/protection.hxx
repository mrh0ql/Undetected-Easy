#pragma once

namespace module::protection {
	struct kernel_image_page_snapshot_t {
		unsigned long long m_virtual_address;
		unsigned long long m_pfn;
		unsigned long long m_leaf_value;
		unsigned long m_mapping_size;
		sha1_digest_t m_digest;
		char m_section[ 9 ];
		bool m_valid;
	};

	EX_PUSH_LOCK m_kernel_image_snapshot_lock{ };
	kernel_image_page_snapshot_t* m_kernel_image_snapshot = nullptr;
	unsigned long m_kernel_image_snapshot_count = 0;
	unsigned long long m_kernel_image_snapshot_base = 0;
	unsigned long m_kernel_image_snapshot_size = 0;

	bool copy_section_name( const IMAGE_SECTION_HEADER* section, char* buffer, size_t buffer_size );

	void lock_kernel_image_snapshot( ) {
		KeEnterCriticalRegion( );
		ExAcquirePushLockExclusive( &m_kernel_image_snapshot_lock );
	}

	void unlock_kernel_image_snapshot( ) {
		ExReleasePushLockExclusive( &m_kernel_image_snapshot_lock );
		KeLeaveCriticalRegion( );
	}

	void free_kernel_image_snapshot_locked( ) {
		if ( m_kernel_image_snapshot )
			memory::free_pool( m_kernel_image_snapshot );

		m_kernel_image_snapshot = nullptr;
		m_kernel_image_snapshot_count = 0;
		m_kernel_image_snapshot_base = 0;
		m_kernel_image_snapshot_size = 0;
	}

	void free_kernel_image_snapshot( ) {
		lock_kernel_image_snapshot( );
		free_kernel_image_snapshot_locked( );
		unlock_kernel_image_snapshot( );
	}

	bool query_kernel_image_page(
		unsigned long long page,
		unsigned long long* pfn,
		unsigned long long* leaf_value,
		unsigned long* mapping_size,
		sha1_digest_t* digest ) {
		if ( !pfn || !leaf_value || !mapping_size || !digest )
			return false;

		unsigned long long physical_address = 0;
		std::uint32_t translated_size = 0;
		paging::pt_entries_t entries{ };
		if ( !paging::hyperspace_entries( entries, page ) ||
			!paging::translate_linear( page, &physical_address, &translated_size ) ||
			!physical_address || !translated_size )
			return false;

		unsigned char bytes[ PAGE_SIZE ]{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( page ), sizeof( bytes ), bytes, &copied ) )
			return false;

		*pfn = physical_address >> PAGE_SHIFT;
		*mapping_size = translated_size;
		*leaf_value = entries.m_pdpte.hard.page_size ? entries.m_pdpte.value :
			entries.m_pde.hard.page_size ? entries.m_pde.value : entries.m_pte.value;
		*digest = c_sha1::hash_buffer( bytes, copied );
		return true;
	}

	unsigned long scan_persistent_kernel_image_snapshot(
		ioctl::command_t* command,
		const system_module_t* module,
		const char* module_name ) {
		if ( !command || !module || !module_name || !module->m_image_base || !module->m_image_size )
			return 0;

		auto image_base = reinterpret_cast< unsigned long long >( module->m_image_base );
		auto nt = memory::validate_pe_image(
			static_cast< const unsigned char* >( module->m_image_base ),
			module->m_image_size
		);
		if ( !nt )
			return 0;

		auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( nt ) );
		unsigned long page_count = 0;
		for ( auto index = 0u; index < nt->FileHeader.NumberOfSections; index++ ) {
			auto section = &sections[ index ];
			if ( !( section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
				continue;

			auto size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
			if ( !size || section->VirtualAddress >= module->m_image_size )
				continue;

			auto available = module->m_image_size - section->VirtualAddress;
			if ( size > available )
				size = available;

			auto first = ( image_base + section->VirtualAddress ) & ~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 );
			auto end = image_base + section->VirtualAddress + size;
			page_count += static_cast< unsigned long >( ( end - first + PAGE_SIZE - 1 ) / PAGE_SIZE );
		}

		if ( !page_count || page_count > module->m_image_size / PAGE_SIZE + nt->FileHeader.NumberOfSections )
			return 0;

		lock_kernel_image_snapshot( );
		const auto baseline_matches = m_kernel_image_snapshot &&
			m_kernel_image_snapshot_base == image_base &&
			m_kernel_image_snapshot_size == module->m_image_size &&
			m_kernel_image_snapshot_count == page_count;

		if ( !baseline_matches ) {
			free_kernel_image_snapshot_locked( );
			m_kernel_image_snapshot = memory::allocate_pool< kernel_image_page_snapshot_t* >(
				sizeof( kernel_image_page_snapshot_t ) * page_count,
				1
			);
			if ( !m_kernel_image_snapshot ) {
				unlock_kernel_image_snapshot( );
				return 0;
			}

			memset( m_kernel_image_snapshot, 0, sizeof( kernel_image_page_snapshot_t ) * page_count );
			m_kernel_image_snapshot_count = page_count;
			m_kernel_image_snapshot_base = image_base;
			m_kernel_image_snapshot_size = module->m_image_size;
		}

		unsigned long snapshot_index = 0;
		unsigned long detections = 0;
		for ( auto section_index = 0u; section_index < nt->FileHeader.NumberOfSections; section_index++ ) {
			auto section = &sections[ section_index ];
			if ( !( section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
				continue;

			auto size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
			if ( !size || section->VirtualAddress >= module->m_image_size )
				continue;

			auto available = module->m_image_size - section->VirtualAddress;
			if ( size > available )
				size = available;

			auto first = ( image_base + section->VirtualAddress ) & ~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 );
			auto end = image_base + section->VirtualAddress + size;
			for ( auto page = first; page < end && snapshot_index < page_count; page += PAGE_SIZE, snapshot_index++ ) {
				unsigned long long pfn = 0;
				unsigned long long leaf_value = 0;
				unsigned long mapping_size = 0;
				sha1_digest_t digest{ };
				if ( !query_kernel_image_page( page, &pfn, &leaf_value, &mapping_size, &digest ) )
					continue;

				auto baseline = &m_kernel_image_snapshot[ snapshot_index ];
				if ( !baseline_matches || !baseline->m_valid ) {
					baseline->m_virtual_address = page;
					baseline->m_pfn = pfn;
					baseline->m_leaf_value = leaf_value;
					baseline->m_mapping_size = mapping_size;
					baseline->m_digest = digest;
					copy_section_name( section, baseline->m_section, sizeof( baseline->m_section ) );
					baseline->m_valid = true;
					continue;
				}

				if ( baseline->m_virtual_address != page || baseline->m_pfn == pfn )
					continue;

				char target[ ioctl::m_detection_target_size ]{ };
				char detail[ ioctl::m_detection_text_size ]{ };
				auto hash_changed = memcmp( &baseline->m_digest, &digest, sizeof( digest ) ) != 0;
				auto pte_changed = baseline->m_leaf_value != leaf_value;
				RtlStringCbPrintfA( target, sizeof( target ), "%s!%s+0x%llx", module_name, baseline->m_section, page - image_base );
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"old_pfn=0x%llx new_pfn=0x%llx page=0x%lx->0x%lx hash=%u pte=%u",
					baseline->m_pfn,
					pfn,
					baseline->m_mapping_size,
					mapping_size,
					static_cast< unsigned long >( hash_changed ),
					static_cast< unsigned long >( pte_changed )
				);
				report::add_memory_detection(
					command,
					target,
					report::m_image_page_private_cow_violation,
					detail,
					page,
					PAGE_SIZE
				);
				detections++;
			}
		}

		unlock_kernel_image_snapshot( );
		return detections;
	}

	enum class pfn_suspicion_t : unsigned long {
	clean = 0,
	large_page_split = 1 << 0,
	ept_shadow = 1 << 1,
	high_zero_density = 1 << 2,
};

struct pfn_scan_result_t {
	pfn_suspicion_t m_flags;
	unsigned long long m_pa_from_walk;
	unsigned long long m_pa_from_api;
	unsigned long m_zero_byte_count;

	bool suspicious( ) const {
		return m_flags != pfn_suspicion_t::clean;
	}
};

pfn_scan_result_t scan_page_pfn(
	unsigned long long virtual_address,
	const paging::pt_entries_t& pt_entries,
	const unsigned char* page_bytes,
	unsigned long page_size ) {
	pfn_scan_result_t result{ };

	const auto one_gb = pt_entries.m_pdpte.hard.page_size != 0;
	const auto two_mb = !one_gb && pt_entries.m_pde.hard.page_size != 0;

	if ( !one_gb && !two_mb && !pt_entries.m_pte.hard.pfn )
		return result;

	if ( one_gb ) {
		auto pfn = pt_entries.m_pdpte.hard.pfn & ~( ( page_1gb_size / page_4kb_size ) - 1 );
		result.m_pa_from_walk = ( static_cast< unsigned long long >( pfn ) << PAGE_SHIFT ) |
			( virtual_address & page_1gb_mask );
	}
	else if ( two_mb ) {
		auto pfn = pt_entries.m_pde.hard.pfn & ~( ( page_2mb_size / page_4kb_size ) - 1 );
		result.m_pa_from_walk = ( static_cast< unsigned long long >( pfn ) << PAGE_SHIFT ) |
			( virtual_address & page_2mb_mask );
	}
	else {
		result.m_pa_from_walk = ( static_cast< unsigned long long >( pt_entries.m_pte.hard.pfn ) << PAGE_SHIFT ) |
			( virtual_address & page_4kb_mask );
	}

	PHYSICAL_ADDRESS pa{ };
	pa = MmGetPhysicalAddress( reinterpret_cast< void* >( virtual_address ) );
	result.m_pa_from_api = static_cast< unsigned long long >( pa.QuadPart );

	if ( result.m_pa_from_api && result.m_pa_from_walk ) {
		if ( result.m_pa_from_api != result.m_pa_from_walk ) {
			result.m_flags = static_cast< pfn_suspicion_t >(
				static_cast< unsigned long >( result.m_flags ) |
				static_cast< unsigned long >( pfn_suspicion_t::ept_shadow )
				);
		}
	}

	if ( !one_gb && !two_mb && ( pt_entries.m_pte.hard.dirty || pt_entries.m_pte.hard.read_write ) ) {
		result.m_flags = static_cast< pfn_suspicion_t >(
			static_cast< unsigned long >( result.m_flags ) |
			static_cast< unsigned long >( pfn_suspicion_t::large_page_split )
		);
	}

	if ( page_bytes && page_size ) {
		for ( auto i = 0ul; i < page_size; i++ )
			if ( page_bytes[ i ] == 0 )
				result.m_zero_byte_count++;

		if ( result.m_zero_byte_count > ( page_size * 3 ) / 4 ) {
			result.m_flags = static_cast< pfn_suspicion_t >(
				static_cast< unsigned long >( result.m_flags ) |
				static_cast< unsigned long >( pfn_suspicion_t::high_zero_density )
			);
		}
	}

	return result;
}

	bool copy_section_name( const IMAGE_SECTION_HEADER* section, char* buffer, size_t buffer_size ) {
		if ( !section || !buffer || !buffer_size )
			return false;

		buffer[ 0 ] = 0;
		auto copy_size = sizeof( section->Name );
		if ( copy_size >= buffer_size )
			copy_size = buffer_size - 1;

		memcpy( buffer, section->Name, copy_size );
		buffer[ copy_size ] = 0;
		return true;
	}

	unsigned long scan_section_permissions( ioctl::command_t* command, const system_module_t* module, const char* module_name ) {
		if ( !command || !module || !module_name || !module->m_image_base )
			return 0;

		auto dos_header = static_cast< const IMAGE_DOS_HEADER* >( module->m_image_base );
		if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
			return 0;

		auto nt_headers = reinterpret_cast< const IMAGE_NT_HEADERS64* >( reinterpret_cast< const unsigned char* >( module->m_image_base ) + dos_header->e_lfanew );
		if ( nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return 0;

		auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( nt_headers ) );
		unsigned long detections = scan_persistent_kernel_image_snapshot( command, module, module_name );

		for ( auto section_index = 0u; section_index < nt_headers->FileHeader.NumberOfSections; section_index++ ) {
			auto section = &sections[ section_index ];
			auto section_size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
			if ( !section_size || section->VirtualAddress >= module->m_image_size )
				continue;

			auto available = module->m_image_size - section->VirtualAddress;
			if ( section_size > available )
				section_size = available;

			char section_name[ 9 ]{ };
			copy_section_name( section, section_name, sizeof( section_name ) );
			const auto expected_executable = ( section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0;
			const auto expected_writable = ( section->Characteristics & IMAGE_SCN_MEM_WRITE ) != 0;
			auto section_start = reinterpret_cast< unsigned long long >( module->m_image_base ) + section->VirtualAddress;
			auto section_end = section_start + section_size;
			auto page = section_start & ~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 );

			while ( page < section_end ) {
				paging::pt_entries_t pt_entries{ };
				if ( !paging::hyperspace_entries( pt_entries, page ) ) {
					page += PAGE_SIZE;
					continue;
				}

			const auto one_gb = pt_entries.m_pdpte.hard.page_size != 0;
			const auto two_mb = !one_gb && pt_entries.m_pde.hard.page_size != 0;
			const auto leaf_value = one_gb ? pt_entries.m_pdpte.value :
				two_mb ? pt_entries.m_pde.value : pt_entries.m_pte.value;
			const auto mapping_size = one_gb ? 0x40000000ul : two_mb ? 0x200000ul : PAGE_SIZE;
			const auto writable = pt_entries.m_pml4e.hard.read_write &&
				pt_entries.m_pdpte.hard.read_write &&
				( one_gb || ( pt_entries.m_pde.hard.read_write &&
					( two_mb || pt_entries.m_pte.hard.read_write ) ) );
			const auto executable = !pt_entries.m_pml4e.hard.no_execute &&
				!pt_entries.m_pdpte.hard.no_execute &&
				( one_gb || ( !pt_entries.m_pde.hard.no_execute &&
					( two_mb || !pt_entries.m_pte.hard.no_execute ) ) );
			const auto user_accessible = pt_entries.m_pml4e.hard.user_supervisor &&
				pt_entries.m_pdpte.hard.user_supervisor &&
				( one_gb || ( pt_entries.m_pde.hard.user_supervisor &&
					( two_mb || pt_entries.m_pte.hard.user_supervisor ) ) );

			if ( expected_executable && !expected_writable && writable ) {
				report::add_section_permission_detection(
					command, module_name, section_name, report::m_writable_code_section_violation,
					page, leaf_value, mapping_size, writable, executable, user_accessible );
				detections++;
			}

			// Large image mappings legitimately share execute permission across sections.
			// A 4 KB executable page in a PE section that does not request execute is not expected.
			if ( !expected_executable && executable && !one_gb && !two_mb ) {
				report::add_section_permission_detection(
					command, module_name, section_name, report::m_executable_non_code_page_violation,
					page, leaf_value, mapping_size, writable, executable, user_accessible );
				detections++;
			}

			if ( expected_executable && !executable ) {
				report::add_section_permission_detection(
					command, module_name, section_name, report::m_non_executable_code_page_violation,
					page, leaf_value, mapping_size, writable, executable, user_accessible );
				detections++;
			}

			if ( user_accessible ) {
				report::add_section_permission_detection(
					command, module_name, section_name, report::m_user_accessible_image_page_violation,
					page, leaf_value, mapping_size, writable, executable, user_accessible );
				detections++;
			}

			if ( expected_executable ) {
				unsigned char page_bytes[ PAGE_SIZE ]{ };
				size_t bytes_copied = 0;
				memory::copy_kernel_memory( reinterpret_cast< void* >( page ), PAGE_SIZE, page_bytes, &bytes_copied );

				auto pfn_result = scan_page_pfn( page, pt_entries, page_bytes, bytes_copied );
				if ( pfn_result.suspicious( ) && pt_entries.m_pte.value && pt_entries.m_pte.hard.pfn ) {
				const char* reason = nullptr;

				if ( static_cast< unsigned long >( pfn_result.m_flags ) &
					static_cast< unsigned long >( pfn_suspicion_t::ept_shadow ) )
					reason = "ept shadow";
				else if ( static_cast< unsigned long >( pfn_result.m_flags ) &
					static_cast< unsigned long >( pfn_suspicion_t::large_page_split ) )
					reason = "suspicious pte flags";
				else
					reason = "suspicious pfn";

				report::add_pfn_backing_detection(
					command,
					module_name,
					section_name,
					page,
					pt_entries.m_pte,
					reason
				);
				}
			}

				page += PAGE_SIZE;
			}
		}

		return detections;
	}

	unsigned long scan_stack_frames( ioctl::command_t* command, const system_modules_t* modules, const char* module_name ) {
		if ( !command || !modules || !module_name )
			return 0;

		void* frames[ 32 ]{ };
		auto frame_count = RtlWalkFrameChain( frames, ARRAYSIZE( frames ), 0 );
		unsigned long detections = 0;

		for ( auto index = 0ul; index < frame_count; index++ ) {
			auto frame = reinterpret_cast< unsigned long long >( frames[ index ] );
			if ( !frame )
				continue;

			auto owner = disk::lookup_address_owner( modules, frame );
			if ( owner && ascii_equal_insensitive( owner, module_name ) )
				continue;

			if ( owner && ascii_equal_insensitive( owner, "ude-driver.sys" ) )
				continue;

			if ( owner && disk::is_whitelisted_owner( owner ) )
				continue;

			report::add_stack_frame_detection( command, module_name, index, frame, owner );
			detections++;
		}

		return detections;
	}
}
