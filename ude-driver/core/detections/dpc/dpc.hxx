#pragma once

namespace dpc_integrity {
	constexpr auto m_dpc_object_type = 0x13u;
	constexpr auto m_high_importance = 3u;

	struct target_info_t {
		const char* m_owner;
		char m_section[ 9 ];
		bool m_executable;
		bool m_bad_backing;
		unsigned long long m_pfn;
		unsigned long long m_walk_pa;
		unsigned long long m_api_pa;
	};

	void query_target_info( const system_modules_t* modules, unsigned long long address, target_info_t* info ) {
		if ( !info )
			return;

		memset( info, 0, sizeof( *info ) );
		auto module = module::disk::find_module_by_address( modules, address );
		if ( module ) {
			info->m_owner = reinterpret_cast< const char* >( module->m_full_path_name ) + module->m_offset_to_file_name;
			info->m_executable = module::disk::is_address_in_executable_section( module, address, info->m_section, sizeof( info->m_section ) );
		}

		paging::pt_entries_t entries{ };
		if ( !paging::hyperspace_entries( entries, address ) )
			return;

		if ( entries.m_pdpte.hard.page_size )
			info->m_pfn = entries.m_pdpte.hard.pfn;
		else if ( entries.m_pde.hard.page_size )
			info->m_pfn = entries.m_pde.hard.pfn;
		else
			info->m_pfn = entries.m_pte.hard.pfn;

		std::uint32_t page_size = 0;
		paging::translate_linear( address, &info->m_walk_pa, &page_size );
		auto api_pa = MmGetPhysicalAddress( reinterpret_cast< void* >( address ) );
		info->m_api_pa = static_cast< unsigned long long >( api_pa.QuadPart );
		info->m_bad_backing = info->m_walk_pa && info->m_api_pa && info->m_walk_pa != info->m_api_pa;
	}

	bool is_plausible_dpc( KDPC* dpc ) {
		if ( !dpc )
			return false;

		auto routine = reinterpret_cast< unsigned long long >( dpc->DeferredRoutine );
		if ( dpc->Type != m_dpc_object_type || !memory::is_canonical_kernel_address( routine ) )
			return false;

		return true;
	}

	bool is_bigpool_source( const char* source ) {
		if ( !source )
			return false;

		return source[ 0 ] == 'b' &&
			source[ 1 ] == 'i' &&
			source[ 2 ] == 'g' &&
			source[ 3 ] == 'p' &&
			source[ 4 ] == 'o' &&
			source[ 5 ] == 'o' &&
			source[ 6 ] == 'l' &&
			source[ 7 ] == 0;
	}

	unsigned long inspect_candidate( ioctl::command_t* command, const system_modules_t* modules, KDPC* dpc, const char* source ) {
		if ( !command || !modules || !dpc )
			return 0;

		if ( !is_plausible_dpc( dpc ) )
			return 0;

		unsigned long detections = 0;
		auto weak_candidate = is_bigpool_source( source );
		if ( !weak_candidate && static_cast< unsigned long >( dpc->Importance ) > m_high_importance ) {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"source=%s dpc=0x%llx type=0x%x importance=0x%x number=0x%x",
				source ? source : "candidate",
				reinterpret_cast< unsigned long long >( dpc ),
				static_cast< unsigned long >( dpc->Type ),
				static_cast< unsigned long >( dpc->Importance ),
				static_cast< unsigned long >( dpc->Number )
			);

			report::add_memory_detection( command, "dpc!object", report::m_dpc_flags_violation, detail, reinterpret_cast< unsigned long long >( dpc ), sizeof( KDPC ) );
			detections++;
		}

		auto routine = reinterpret_cast< unsigned long long >( dpc->DeferredRoutine );
		if ( routine ) {
			target_info_t info{ };
			query_target_info( modules, routine, &info );
			auto suspicious_target = info.m_bad_backing || ( !weak_candidate && ( !info.m_owner || !info.m_executable ) );
			if ( suspicious_target ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"source=%s dpc=0x%llx routine=0x%llx owner=%s section=%s pfn=0x%llx",
					source ? source : "candidate",
					reinterpret_cast< unsigned long long >( dpc ),
					routine,
					info.m_owner ? info.m_owner : "unknown",
					info.m_section[ 0 ] ? info.m_section : "unknown",
					info.m_pfn
				);

				report::add_memory_detection( command, "dpc!routine", report::m_dpc_target_violation, detail, routine, sizeof( void* ) );
				detections++;
			}
		}

		return detections;
	}

	KDPC* decode_timer_dpc(
		unsigned long long timer_va,
		unsigned long long encoded_dpc,
		unsigned long long wait_never,
		unsigned long long wait_always ) {
		if ( !timer_va || !encoded_dpc || !wait_never || !wait_always )
			return nullptr;

		auto step1 = encoded_dpc ^ wait_always;
		auto step2 = _rotl64( step1, static_cast< int >( wait_never & 0xff ) );
		auto step3 = step2 ^ timer_va;
		auto step4 = _byteswap_uint64( step3 );
		auto decoded = step4 ^ wait_never;
		if ( !memory::is_canonical_kernel_address( decoded ) )
			return nullptr;

		return reinterpret_cast< KDPC* >( decoded );
	}

	unsigned long inspect_timer_candidate(
		ioctl::command_t* command,
		const system_modules_t* modules,
		unsigned long long timer_va,
		const KTIMER& timer,
		unsigned long long wait_never,
		unsigned long long wait_always ) {
		if ( !command || !modules || !timer_va || !wait_never || !wait_always )
			return 0;

		if ( timer.Header.Type != 8 && timer.Header.Type != 9 )
			return 0;

		auto encoded_dpc = reinterpret_cast< unsigned long long >( timer.Dpc );
		if ( !encoded_dpc )
			return 0;

		auto dpc_ptr = decode_timer_dpc( timer_va, encoded_dpc, wait_never, wait_always );
		if ( !dpc_ptr )
			return 0;

		KDPC dpc_copy{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( dpc_ptr, sizeof( dpc_copy ), &dpc_copy, &copied ) )
			return 0;

		if ( !is_plausible_dpc( &dpc_copy ) )
			return 0;

		command->m_signature_candidates++;
		auto routine = reinterpret_cast< unsigned long long >( dpc_copy.DeferredRoutine );
		target_info_t info{ };
		query_target_info( modules, routine, &info );

		if ( info.m_owner && info.m_executable && !info.m_bad_backing )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"timer=0x%llx dpc=0x%llx routine=0x%llx period=%lu owner=%s section=%s pfn=0x%llx",
			timer_va,
			reinterpret_cast< unsigned long long >( dpc_ptr ),
			routine,
			timer.Period,
			info.m_owner ? info.m_owner : "unknown",
			info.m_section[ 0 ] ? info.m_section : "unknown",
			info.m_pfn
		);

		report::add_memory_detection(
			command,
			"dpc!timer",
			report::m_timer_dpc_target_violation,
			detail,
			routine,
			sizeof( void* )
		);
		return 1;
	}

	bool query_big_pool_for_dpc( system_bigpool_information_t** info ) {
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

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		unsigned long long wait_never = 0;
		unsigned long long wait_always = 0;
		size_t copied = 0;
		if ( m_entry.m_pdb.m_ki_wait_never && m_entry.m_pdb.m_ki_wait_always ) {
			memory::copy_kernel_memory( reinterpret_cast< void* >( m_entry.m_pdb.m_ki_wait_never ), sizeof( wait_never ), &wait_never, &copied );
			memory::copy_kernel_memory( reinterpret_cast< void* >( m_entry.m_pdb.m_ki_wait_always ), sizeof( wait_always ), &wait_always, &copied );
		}

		unsigned long detections = 0;
		unsigned long scanned_allocations = 0;
		system_bigpool_information_t* pool_info = nullptr;
		if ( query_big_pool_for_dpc( &pool_info ) && pool_info ) {
			for ( auto index = 0ul; index < pool_info->m_count; index++ ) {
				const auto& entry = pool_info->m_allocated_info[ index ];
				auto address = reinterpret_cast< unsigned long long >( entry.m_virtual_address ) & ~1ull;
				auto size = static_cast< unsigned long >( entry.m_size_in_bytes );
				if ( !address || !memory::is_canonical_kernel_address( address ) || size < sizeof( KDPC ) || size > 16ul * 1024ul * 1024ul )
					continue;

				if ( memory::pool::owns_allocation_address( address ) || memory::lookup_address_owner( modules, address ) )
					continue;

				unsigned char bytes[ 512 ]{ };
				auto read_size = size < sizeof( bytes ) ? size : sizeof( bytes );
				if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( address ), read_size, bytes, &copied ) || copied < sizeof( KDPC ) )
					continue;

				scanned_allocations++;
				for ( auto offset = 0ul; offset + sizeof( KDPC ) <= copied; offset += 8 ) {
					auto dpc_candidate = reinterpret_cast< KDPC* >( bytes + offset );
					if ( is_plausible_dpc( dpc_candidate ) &&
						dpc_candidate->Importance <= m_high_importance &&
						memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( dpc_candidate->DpcListEntry.Next ) ) ) {
						command->m_signature_candidates++;
						detections += inspect_candidate( command, modules, dpc_candidate, "dpc_queue" );
					}

					if ( wait_never && wait_always && offset + sizeof( KTIMER ) <= copied ) {
						auto timer_candidate = reinterpret_cast< const KTIMER* >( bytes + offset );
						detections += inspect_timer_candidate( command, modules, address + offset, *timer_candidate, wait_never, wait_always );
					}
				}
			}

			memory::free_pool( pool_info );
		}

		command->m_modules_scanned = modules->m_count;
		command->m_sections_scanned = scanned_allocations;
		command->m_signature_detections = detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		utility::print( "dpc integrity: allocations=%lu candidates=%lu detections=%lu\n", scanned_allocations, command->m_signature_candidates, command->m_total_detection_count );
		return true;
	}
}
