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

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		command->m_modules_scanned = modules->m_count;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		utility::print( "dpc integrity: candidates=%lu detections=%lu\n", command->m_signature_candidates, command->m_total_detection_count );
		return true;
	}
}
