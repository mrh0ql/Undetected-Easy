#pragma once

namespace pool_integrity {
	constexpr auto m_max_big_pool_bytes = 16ul * 1024ul * 1024ul;
	constexpr auto m_scan_bytes = PAGE_SIZE;

	void tag_to_string( ULONG tag, char* buffer, size_t buffer_size ) {
		if ( !buffer || buffer_size < 5 )
			return;

		buffer[ 0 ] = static_cast< char >( tag & 0xff );
		buffer[ 1 ] = static_cast< char >( ( tag >> 8 ) & 0xff );
		buffer[ 2 ] = static_cast< char >( ( tag >> 16 ) & 0xff );
		buffer[ 3 ] = static_cast< char >( ( tag >> 24 ) & 0xff );
		buffer[ 4 ] = 0;
	}

	bool tag_equals( ULONG tag, char a, char b, char c, char d ) {
		return
			static_cast< unsigned char >( tag & 0xff ) == static_cast< unsigned char >( a ) &&
			static_cast< unsigned char >( ( tag >> 8 ) & 0xff ) == static_cast< unsigned char >( b ) &&
			static_cast< unsigned char >( ( tag >> 16 ) & 0xff ) == static_cast< unsigned char >( c ) &&
			static_cast< unsigned char >( ( tag >> 24 ) & 0xff ) == static_cast< unsigned char >( d );
	}

	bool is_noisy_system_tag( ULONG tag ) {
		return
			tag_equals( tag, 'A', 'f', 'd', 'B' ) ||
			tag_equals( tag, 'S', 'm', 'B', 'f' ) ||
			tag_equals( tag, 'C', 'o', 'n', 'T' ) ||
			tag_equals( tag, 'F', 'O', 'C', 'X' ) ||
			tag_equals( tag, 'F', 'I', 'v', 'p' ) ||
			tag_equals( tag, 'I', 'o', ' ', ' ' ) ||
			 tag_equals( tag, 'C', 'o', 'Z', 's' ) ||
			tag_equals( tag, 'C', 'c', 'B', 'c' ) ||
			tag_equals( tag, 'C', 'c', 'Z', 'e' ) ||
			tag_equals( tag, 'C', 'd', 'm', 'a' ) ||
			tag_equals( tag, 'M', 'd', 'C', 'v' ) ||
			tag_equals( tag, 'N', 't', 'F', 'W' );
	}

	bool query_big_pool( system_bigpool_information_t** info ) {
		if ( !info )
			return false;

		*info = nullptr;
		ULONG bytes = 0;
		auto status = ZwQuerySystemInformation( m_system_big_pool_information, nullptr, 0, &bytes );
		if ( status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW )
			return false;

		for ( auto attempt = 0ul; attempt < 3; attempt++ ) {
			if ( !bytes )
				return false;

			auto buffer = memory::allocate_pool< system_bigpool_information_t* >( bytes, 1 );
			if ( !buffer )
				return false;

			memset( buffer, 0, bytes );
			auto query_bytes = bytes;
			status = ZwQuerySystemInformation( m_system_big_pool_information, buffer, bytes, &query_bytes );
			if ( !status ) {
				*info = buffer;
				return true;
			}

			memory::free_pool( buffer );
			if ( status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW )
				return false;

			bytes = query_bytes;
		}

		return false;
	}

	unsigned long long pool_address( const system_bigpool_entry_t& entry ) {
		return reinterpret_cast< unsigned long long >( entry.m_virtual_address ) & ~1ull;
	}

	struct pool_permissions_t {
		bool m_executable;
		bool m_writable_executable;
		unsigned long long m_first_wx;
	};

	pool_permissions_t query_pool_permissions( unsigned long long address, unsigned long size ) {
		pool_permissions_t result{ };
		if ( !address || !size )
			return result;

		auto end = address + size;
		if ( end <= address )
			return result;

		for ( auto page = address & ~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 ); page < end; page += PAGE_SIZE ) {
			paging::pt_entries_t entries{ };
			if ( !paging::hyperspace_entries( entries, page ) )
				continue;

			const auto one_gb = entries.m_pdpte.hard.page_size != 0;
			const auto two_mb = !one_gb && entries.m_pde.hard.page_size != 0;
			const auto writable = entries.m_pml4e.hard.read_write &&
				entries.m_pdpte.hard.read_write &&
				( one_gb || ( entries.m_pde.hard.read_write &&
					( two_mb || entries.m_pte.hard.read_write ) ) );
			const auto executable = !entries.m_pml4e.hard.no_execute &&
				!entries.m_pdpte.hard.no_execute &&
				( one_gb || ( !entries.m_pde.hard.no_execute &&
					( two_mb || !entries.m_pte.hard.no_execute ) ) );

			result.m_executable = result.m_executable || executable;
			if ( writable && executable ) {
				result.m_writable_executable = true;
				if ( !result.m_first_wx )
					result.m_first_wx = page;
			}
		}

		return result;
	}

	bool is_suspicious_pool_target( const system_modules_t* modules, unsigned long long target, unsigned long long allocation_base, unsigned long allocation_size ) {
		if ( !memory::is_canonical_kernel_address( target ) )
			return false;

		if ( allocation_base && allocation_size && target >= allocation_base && target < allocation_base + allocation_size )
			return false;

		auto owner = memory::lookup_address_owner( modules, target );
		if ( !owner )
			return true;

		return !module::disk::is_whitelisted_owner( owner );
	}

	bool has_code_signature( const system_modules_t* modules, const unsigned char* bytes, unsigned long size, unsigned long long address, unsigned long allocation_size ) {
		for ( auto offset = 0ul; offset < size; offset++ ) {
			signatures::mov_branch_signature_t mov{ };
			signatures::push_ret_signature_t push{ };
			signatures::rip_indirect_branch_signature_t rip{ };
			signatures::relative_branch_signature_t rel{ };
			signatures::rip_register_branch_signature_t rip_reg{ };

			if ( signatures::match_mov_branch_signature( bytes, size, offset, &mov ) && is_suspicious_pool_target( modules, mov.m_target, address, allocation_size ) )
				return true;

			if ( signatures::match_push_ret_signature( bytes, size, offset, &push ) && is_suspicious_pool_target( modules, push.m_target, address, allocation_size ) )
				return true;

			if ( signatures::match_relative_branch_signature( bytes, size, offset, address + offset, &rel ) && is_suspicious_pool_target( modules, rel.m_target, address, allocation_size ) )
				return true;

			if ( signatures::match_rip_indirect_branch_signature( bytes, size, offset, &rip ) ) {
				auto pointer_address = address + offset + rip.m_size + rip.m_displacement;
				unsigned long long target = 0;
				size_t bytes_copied = 0;
				if ( memory::copy_kernel_memory( reinterpret_cast< void* >( pointer_address ), sizeof( target ), &target, &bytes_copied ) &&
					is_suspicious_pool_target( modules, target, address, allocation_size ) )
					return true;
			}

			if ( signatures::match_rip_register_branch_signature( bytes, size, offset, &rip_reg ) ) {
				auto pointer_address = address + offset + 7 + rip_reg.m_displacement;
				auto target = pointer_address;
				if ( rip_reg.m_dereference ) {
					size_t bytes_copied = 0;
					if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( pointer_address ), sizeof( target ), &target, &bytes_copied ) )
						continue;
				}

				if ( is_suspicious_pool_target( modules, target, address, allocation_size ) )
					return true;
			}
		}

		return false;
	}

	bool find_mapped_pe_image( unsigned long long allocation_base, unsigned long allocation_size, unsigned long long* image_base, unsigned long* image_size ) {
		if ( image_base )
			*image_base = 0;
		if ( image_size )
			*image_size = 0;
		if ( !allocation_base || allocation_size < PAGE_SIZE )
			return false;

		auto allocation_end = allocation_base + allocation_size;
		if ( allocation_end <= allocation_base )
			return false;

		memory::scoped_page_t bytes{ };
		if ( !bytes )
			return false;

		for ( auto page = allocation_base; page < allocation_end; page += PAGE_SIZE ) {
			memset( bytes.get( ), 0, PAGE_SIZE );
			size_t copied = 0;
			if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( page ), PAGE_SIZE, bytes.get( ), &copied ) )
				continue;

			for ( auto offset = 0ul; offset + sizeof( unsigned short ) <= PAGE_SIZE; offset += 16 ) {
				if ( *reinterpret_cast< const unsigned short* >( bytes.get( ) + offset ) != IMAGE_DOS_SIGNATURE )
					continue;

				auto candidate = page + offset;
				unsigned long mapped_size = 0;
				auto valid = memory_scan::permissions::validate_mapped_pe_image(
					candidate,
					allocation_end,
					&mapped_size,
					nullptr,
					nullptr );
				if ( !valid )
					valid = memory_scan::permissions::validate_resident_pe_header( candidate, allocation_end, &mapped_size );
				if ( !valid )
					continue;

				if ( image_base )
					*image_base = candidate;
				if ( image_size )
					*image_size = mapped_size;
				return true;
			}
		}

		return false;
	}

	unsigned long inspect_allocation( ioctl::command_t* command, const system_modules_t* modules, const system_bigpool_entry_t& entry ) {
		auto address = pool_address( entry );
		auto size = static_cast< unsigned long >( entry.m_size_in_bytes );
		if ( !address || !memory::is_canonical_kernel_address( address ) || !size || size > m_max_big_pool_bytes )
			return 0;

		if ( memory::pool::owns_allocation_address( address ) )
			return 0;

		auto owner = memory::lookup_address_owner( modules, address );
		if ( owner )
			return 0;

		unsigned long detections = 0;
		char tag[ 5 ]{ };
		tag_to_string( entry.m_tag_ulong, tag, sizeof( tag ) );

		auto noisy_tag = is_noisy_system_tag( entry.m_tag_ulong );
		auto permissions = query_pool_permissions( address, size );
		auto executable = permissions.m_executable;
		bool reported_pe_image = false;

		memory::scoped_page_t bytes{ };
		size_t copied = 0;
		auto read_size = size < PAGE_SIZE ? size : PAGE_SIZE;
		if ( bytes && memory::copy_kernel_memory( reinterpret_cast< void* >( address ), read_size, bytes.get( ), &copied ) && copied >= 2 ) {
			unsigned long long mapped_image = 0;
			unsigned long mapped_image_size = 0;
			auto pe_image = find_mapped_pe_image( address, size, &mapped_image, &mapped_image_size );
			if ( pe_image && executable && !noisy_tag ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA( detail, sizeof( detail ), "pool=0x%llx image=0x%llx image_size=0x%lx tag=%s", address, mapped_image, mapped_image_size, tag );
				report::add_memory_detection( command, "pool!pe", report::m_pool_pe_header_violation, detail, mapped_image, mapped_image_size );
				detections++;
				reported_pe_image = true;
			}

			// Arbitrary pool data frequently decodes as a valid x64 branch sequence.
			// Preserve this as candidate telemetry, but require a PE image or an
			// active execution reference from another scanner before reporting it.
			if ( executable && !noisy_tag &&
				has_code_signature( modules, bytes.get( ), static_cast< unsigned long >( copied ), address, size ) )
				command->m_signature_candidates++;

			if ( copied >= sizeof( KDPC ) && dpc_integrity::is_plausible_dpc( reinterpret_cast< KDPC* >( bytes.get( ) ) ) ) {
				command->m_signature_candidates++;
				detections += dpc_integrity::inspect_candidate( command, modules, reinterpret_cast< KDPC* >( bytes.get( ) ), "bigpool" );
			}
		}

		if ( executable && !noisy_tag && !reported_pe_image ) {
			auto evidence = memory_scan::permissions::analyze_headerless_image_region(
				modules,
				address,
				address + size
			);
			if ( evidence.m_private_4kb_pages >= 4 && evidence.m_executable_pages >= 4 &&
				evidence.m_max_unwind_run >= memory_scan::permissions::m_min_unwind_run &&
				evidence.m_max_import_run >= memory_scan::permissions::m_min_import_run ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"base=0x%llx size=0x%lx tag=%s private4k=%lu exec=%lu unwind=%lu imports=%lu",
					address,
					size,
					tag,
					evidence.m_private_4kb_pages,
					evidence.m_executable_pages,
					evidence.m_max_unwind_run,
					evidence.m_max_import_run
				);
				report::add_memory_detection(
					command,
					"pool!headerless_image",
					report::m_headerless_unlisted_image_violation,
					detail,
					address,
					size
				);
				detections++;
			}
			else if ( size >= 0x10000ul &&
				!tag_equals( entry.m_tag_ulong, 'N', 'o', 'n', 'e' ) ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"base=0x%llx size=0x%lx tag=%s first_wx=0x%llx exec=1 image_evidence=0",
					address,
					size,
					tag,
					permissions.m_first_wx
				);
				report::add_memory_detection(
					command,
					"pool!large_execute",
					report::m_executable_pool_violation,
					detail,
					address,
					size
				);
				detections++;
			}
		}

		return detections;
	}

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		system_bigpool_information_t* info = nullptr;
		if ( !query_big_pool( &info ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		unsigned long detections = 0;
		for ( auto index = 0ul; index < info->m_count; index++ )
			detections += inspect_allocation( command, modules, info->m_allocated_info[ index ] );

		command->m_modules_scanned = modules->m_count;
		command->m_sections_scanned = info->m_count;
		command->m_signature_detections = detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		utility::print( "pool integrity: allocations=%lu dpc_candidates=%lu detections=%lu\n", info->m_count, command->m_signature_candidates, command->m_total_detection_count );
		memory::free_pool( info );
		return true;
	}
}
