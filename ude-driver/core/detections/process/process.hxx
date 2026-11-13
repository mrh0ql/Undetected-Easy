#pragma once

namespace process_integrity {
	constexpr auto m_system_process_information = 5ul;
	constexpr auto m_max_kernel_pfns = 262144ul;
	constexpr auto m_max_processes = 256ul;
	constexpr auto m_max_process_leaf_entries = 1048576ul;
	constexpr auto m_max_physical_window_reports = 32ul;
	constexpr auto m_min_physical_window_1gb_pages = 1ul;
	constexpr auto m_min_physical_window_2mb_pages = 16ul;
	constexpr auto m_min_physical_window_4kb_pages = MAXULONG;
	constexpr auto m_max_visible_processes = 4096ul;
	constexpr auto m_max_visible_threads = 65536ul;
	constexpr auto m_max_hidden_reports = 64ul;
	constexpr auto m_cid_probe_slack = 0x4000ull;
	constexpr auto m_cid_probe_hard_limit = 0x40000ull;
	constexpr auto m_kprocess_directory_table_base_offset = 0x28ul;

	struct client_id_t {
		HANDLE m_unique_process;
		HANDLE m_unique_thread;
	};

	struct system_process_information_t {
		unsigned long m_next_entry_offset;
		unsigned long m_thread_count;
		unsigned char m_reserved1[ 48 ];
		UNICODE_STRING m_image_name;
		KPRIORITY m_base_priority;
		HANDLE m_process_id;
		void* m_reserved2;
		unsigned long m_handle_count;
		unsigned long m_session_id;
		void* m_reserved3;
		size_t m_peak_virtual_size;
		size_t m_virtual_size;
		unsigned long m_reserved4;
		size_t m_peak_working_set_size;
		size_t m_working_set_size;
		void* m_reserved5;
		size_t m_quota_paged_pool_usage;
		void* m_reserved6;
		size_t m_quota_non_paged_pool_usage;
		size_t m_pagefile_usage;
		size_t m_peak_pagefile_usage;
		size_t m_private_page_count;
		LARGE_INTEGER m_reserved7[ 6 ];
	};

	struct system_thread_information_t {
		LARGE_INTEGER m_kernel_time;
		LARGE_INTEGER m_user_time;
		LARGE_INTEGER m_create_time;
		unsigned long m_wait_time;
		void* m_start_address;
		client_id_t m_client_id;
		KPRIORITY m_priority;
		LONG m_base_priority;
		unsigned long m_context_switches;
		unsigned long m_thread_state;
		unsigned long m_wait_reason;
	};

	struct kernel_pfn_t {
		unsigned long long m_pfn;
		unsigned long long m_kernel_va;
		const char* m_owner;
	};

	struct scan_state_t {
		ioctl::command_t* m_command;
		kernel_pfn_t* m_kernel_pfns;
		PPHYSICAL_MEMORY_RANGE m_physical_ranges;
		unsigned long m_kernel_pfn_count;
		unsigned long m_process_count;
		unsigned long m_leaf_count;
		unsigned long m_detection_count;
		unsigned long m_physical_window_count;
		unsigned long m_large_page_window_count;
		unsigned long long* m_visible_pids;
		unsigned long long* m_visible_tids;
		unsigned long m_visible_pid_count;
		unsigned long m_visible_tid_count;
		unsigned long m_hidden_detection_count;
		unsigned long long m_max_seen_cid;
	};

	bool query_processes( void** process_buffer );

	bool append_unique_id( unsigned long long* ids, unsigned long* count, unsigned long capacity, unsigned long long id ) {
		if ( !ids || !count || !id )
			return false;

		for ( auto index = 0ul; index < *count; index++ ) {
			if ( ids[ index ] == id )
				return true;
		}

		if ( *count >= capacity )
			return false;

		ids[ ( *count )++ ] = id;
		return true;
	}

	bool contains_id( const unsigned long long* ids, unsigned long count, unsigned long long id ) {
		if ( !ids || !id )
			return false;

		for ( auto index = 0ul; index < count; index++ ) {
			if ( ids[ index ] == id )
				return true;
		}

		return false;
	}

	bool query_contains_process_id( unsigned long long pid ) {
		if ( !pid )
			return false;

		void* process_buffer = nullptr;
		if ( !query_processes( &process_buffer ) )
			return false;

		bool found = false;
		auto process_info = static_cast< system_process_information_t* >( process_buffer );
		while ( process_info ) {
			if ( reinterpret_cast< unsigned long long >( process_info->m_process_id ) == pid ) {
				found = true;
				break;
			}

			if ( !process_info->m_next_entry_offset )
				break;

			process_info = reinterpret_cast< system_process_information_t* >(
				reinterpret_cast< unsigned char* >( process_info ) + process_info->m_next_entry_offset
			);
		}

		memory::free_pool( process_buffer );
		return found;
	}

	bool is_protected_process_api( PEPROCESS process ) {
		if ( !process )
			return false;

		using ps_is_protected_process_t = BOOLEAN( NTAPI* )( PEPROCESS );

		static ps_is_protected_process_t ps_is_protected_process = nullptr;
		static bool resolved = false;

		if ( !resolved ) {
			UNICODE_STRING routine_name{ };
			RtlInitUnicodeString( &routine_name, L"PsIsProtectedProcess" );
			ps_is_protected_process = reinterpret_cast< ps_is_protected_process_t >( MmGetSystemRoutineAddress( &routine_name ) );
			resolved = true;
		}

		return ps_is_protected_process && ps_is_protected_process( process );
	}

	bool is_whitelisted_session_process( PEPROCESS process ) {
		if ( !process )
			return false;

		auto pid = reinterpret_cast< unsigned long long >( PsGetProcessId( process ) );
		if ( pid == 4 )
			return true;

		return PsGetProcessSessionId( process ) != 0;
	}

	bool is_active_process( PEPROCESS process ) {
		if ( !process )
			return false;

		return PsGetProcessExitStatus( process ) == STATUS_PENDING;
	}

	bool query_processes( void** process_buffer ) {
		if ( !process_buffer )
			return false;

		*process_buffer = nullptr;

		unsigned long bytes = 0;
		auto status = ZwQuerySystemInformation( m_system_process_information, nullptr, 0, &bytes );
		if ( status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW )
			return false;

		for ( auto attempt = 0ul; attempt < 3; attempt++ ) {
			if ( !bytes )
				return false;

			auto buffer = memory::allocate_pool( bytes, 1 );
			if ( !buffer )
				return false;

			memset( buffer, 0, bytes );

			auto query_bytes = bytes;
			status = ZwQuerySystemInformation( m_system_process_information, buffer, bytes, &query_bytes );
			if ( !status ) {
				*process_buffer = buffer;
				return true;
			}

			memory::free_pool( buffer );
			if ( status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW )
				return false;

			bytes = query_bytes;
		}

		return false;
	}

	unsigned long long entry_pfn( const pdpte& entry ) {
		return entry.hard.page_size ? memory_scan::pdpte_page_pfn( entry ) : entry.hard.pfn;
	}

	unsigned long long entry_pfn( const pde& entry ) {
		return entry.hard.page_size ? memory_scan::pde_page_pfn( entry ) : entry.hard.pfn;
	}

	unsigned long long entry_pfn( const pte& entry ) {
		return memory_scan::pte_page_pfn( entry );
	}

	bool add_kernel_pfn( scan_state_t* state, unsigned long long pfn, unsigned long long kernel_va, const char* owner ) {
		if ( !state || !pfn || !owner || state->m_kernel_pfn_count >= m_max_kernel_pfns )
			return false;

		for ( auto index = 0ul; index < state->m_kernel_pfn_count; index++ ) {
			if ( state->m_kernel_pfns[ index ].m_pfn == pfn )
				return true;
		}

		auto record = &state->m_kernel_pfns[ state->m_kernel_pfn_count++ ];
		record->m_pfn = pfn;
		record->m_kernel_va = kernel_va;
		record->m_owner = owner;
		return true;
	}

	bool find_kernel_pfn( const scan_state_t* state, unsigned long long pfn, unsigned long page_count, kernel_pfn_t* owner ) {
		if ( !state || !pfn || !owner )
			return false;

		if ( !page_count )
			page_count = 1;

		if ( page_count > 512 )
			page_count = 512;

		for ( auto page = 0ul; page < page_count; page++ ) {
			auto test_pfn = pfn + page;
			for ( auto index = 0ul; index < state->m_kernel_pfn_count; index++ ) {
				if ( state->m_kernel_pfns[ index ].m_pfn != test_pfn )
					continue;

				*owner = state->m_kernel_pfns[ index ];
				return true;
			}
		}

		return false;
	}

	bool mapping_overlaps_physical_ranges( const scan_state_t* state, unsigned long long pfn, unsigned long page_size ) {
		if ( !state || !state->m_physical_ranges || !page_size )
			return true;

		auto mapping_start = pfn << page_shift;
		auto mapping_end = mapping_start + page_size;
		if ( mapping_end <= mapping_start )
			return false;

		for ( auto range = state->m_physical_ranges; range->NumberOfBytes.QuadPart; range++ ) {
			auto range_start = static_cast< unsigned long long >( range->BaseAddress.QuadPart );
			auto range_size = static_cast< unsigned long long >( range->NumberOfBytes.QuadPart );
			auto range_end = range_start + range_size;

			if ( range_end <= range_start )
				continue;

			if ( mapping_start < range_end && mapping_end > range_start )
				return true;
		}

		return false;
	}

	unsigned long long process_directory_table_base( PEPROCESS process ) {
		if ( !process )
			return 0;

		unsigned long long directory_table_base = 0;
		size_t copied = 0;
		if ( !memory::copy_kernel_memory(
			reinterpret_cast< unsigned char* >( process ) + m_kprocess_directory_table_base_offset,
			sizeof( directory_table_base ),
			&directory_table_base,
			&copied ) )
			return 0;

		return directory_table_base & ~0xfffull;
	}

	bool cr3_maps_address( unsigned long long directory_table_base, unsigned long long address ) {
		if ( !directory_table_base || !address )
			return false;

		virt_addr_t va{ };
		va.value = address;

		pml4e pml4{ };
		if ( !paging::remap::read_physical( directory_table_base + va.pml4e_index * sizeof( pml4e ), &pml4, sizeof( pml4 ) ) || !pml4.hard.present )
			return false;

		pdpte pdpt{ };
		if ( !memory_scan::read_entry( pml4.hard.pfn, static_cast< unsigned long >( va.pdpte_index ), &pdpt ) || !pdpt.hard.present )
			return false;

		if ( pdpt.hard.page_size )
			return true;

		pde pd{ };
		if ( !memory_scan::read_entry( pdpt.hard.pfn, static_cast< unsigned long >( va.pde_index ), &pd ) || !pd.hard.present )
			return false;

		if ( pd.hard.page_size )
			return true;

		pte pt{ };
		return memory_scan::read_entry( pd.hard.pfn, static_cast< unsigned long >( va.pte_index ), &pt ) && pt.hard.present;
	}

	bool has_orphan_address_space( PEPROCESS process, const system_modules_t* modules ) {
		if ( !process )
			return false;

		auto directory_table_base = process_directory_table_base( process );
		if ( !directory_table_base )
			return false;

		auto probe = m_entry.m_ntoskrnl_base;
		if ( !probe && modules && modules->m_count )
			probe = reinterpret_cast< unsigned long long >( modules->m_modules[ 0 ].m_image_base );

		return cr3_maps_address( directory_table_base, probe );
	}

	void build_kernel_pfn_index( scan_state_t* state, const system_modules_t* modules ) {
		if ( !state || !modules )
			return;

		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto module = &modules->m_modules[ index ];
			auto base = reinterpret_cast< unsigned long long >( module->m_image_base );
			auto end = base + module->m_image_size;
			auto owner = reinterpret_cast< const char* >( module->m_full_path_name ) + module->m_offset_to_file_name;

			for ( auto address = base; address < end && state->m_kernel_pfn_count < m_max_kernel_pfns; address += PAGE_SIZE ) {
				paging::pt_entries_t entries{ };
				if ( !paging::hyperspace_entries( entries, address ) )
					continue;

				unsigned long long pfn = 0;
				if ( entries.m_pdpte.hard.page_size )
					pfn = memory_scan::pdpte_page_pfn( entries.m_pdpte ) + ( ( address & page_1gb_mask ) >> page_shift );
				else if ( entries.m_pde.hard.page_size )
					pfn = memory_scan::pde_page_pfn( entries.m_pde ) + ( ( address & page_2mb_mask ) >> page_shift );
				else
					pfn = memory_scan::pte_page_pfn( entries.m_pte );

				add_kernel_pfn( state, pfn, address, owner );
			}
		}
	}

	void report_kernel_page_mapping( scan_state_t* state, PEPROCESS process, unsigned long long user_va, unsigned long long pfn, unsigned long page_size, bool writable, bool executable, const kernel_pfn_t& owner ) {
		if ( !state || !state->m_command || !process )
			return;

		auto pid = reinterpret_cast< unsigned long long >( PsGetProcessId( process ) );
		auto name = PsGetProcessImageFileName( process );

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"process!%s:%llu",
			name ? name : "unknown",
			pid
		);

		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"user_va=0x%llx pfn=0x%llx owner=%s kernel_va=0x%llx rw=%u nx=%u",
			user_va,
			pfn,
			owner.m_owner ? owner.m_owner : "unknown",
			owner.m_kernel_va,
			static_cast< unsigned long >( writable ),
			static_cast< unsigned long >( !executable )
		);

		report::add_memory_detection(
			state->m_command,
			target,
			report::m_process_kernel_page_violation,
			detail,
			user_va,
			page_size
		);

		state->m_detection_count++;
	}

	void report_physical_window_mapping( scan_state_t* state, PEPROCESS process, unsigned long long user_va, unsigned long long pfn, unsigned long page_size, bool writable, bool executable ) {
		if ( !state || !state->m_command || !process || state->m_physical_window_count >= m_max_physical_window_reports )
			return;

		auto pid = reinterpret_cast< unsigned long long >( PsGetProcessId( process ) );
		auto name = PsGetProcessImageFileName( process );

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"process!%s:%llu",
			name ? name : "unknown",
			pid
		);

		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"user_va=0x%llx pfn=0x%llx size=0x%x rw=%u nx=%u",
			user_va,
			pfn,
			page_size,
			static_cast< unsigned long >( writable ),
			static_cast< unsigned long >( !executable )
		);

		report::add_memory_detection(
			state->m_command,
			target,
			report::m_process_physical_window_violation,
			detail,
			user_va,
			page_size
		);

		state->m_physical_window_count++;
		state->m_detection_count++;
	}

	void report_hidden_process_detection( scan_state_t* state, PEPROCESS process, const char* type, const char* reason ) {
		if ( !state || !state->m_command || !process || state->m_hidden_detection_count >= m_max_hidden_reports )
			return;

		if ( is_whitelisted_session_process( process ) )
			return;

		auto pid = reinterpret_cast< unsigned long long >( PsGetProcessId( process ) );
		auto name = PsGetProcessImageFileName( process );
		auto directory_table_base = process_directory_table_base( process );

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"process!%s:%llu",
			name ? name : "unknown",
			pid
		);

		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"pid=%llu eprocess=0x%llx dtb=0x%llx %s",
			pid,
			reinterpret_cast< unsigned long long >( process ),
			directory_table_base,
			reason ? reason : "cross_view"
		);

		report::add_memory_detection(
			state->m_command,
			target,
			type,
			detail,
			reinterpret_cast< unsigned long long >( process ),
			sizeof( void* )
		);

		state->m_hidden_detection_count++;
		state->m_detection_count++;
	}

	void report_hidden_thread_detection( scan_state_t* state, PETHREAD thread, PEPROCESS owner, unsigned long long tid ) {
		if ( !state || !state->m_command || !thread || state->m_hidden_detection_count >= m_max_hidden_reports )
			return;

		if ( is_whitelisted_session_process( owner ) )
			return;

		auto pid = owner ? reinterpret_cast< unsigned long long >( PsGetProcessId( owner ) ) : 0;
		auto name = owner ? PsGetProcessImageFileName( owner ) : nullptr;

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"thread!%s:%llu",
			name ? name : "unknown",
			tid
		);

		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"tid=%llu pid=%llu ethread=0x%llx owner=0x%llx cid_missing=1",
			tid,
			pid,
			reinterpret_cast< unsigned long long >( thread ),
			reinterpret_cast< unsigned long long >( owner )
		);

		report::add_memory_detection(
			state->m_command,
			target,
			report::m_thread_hidden_violation,
			detail,
			reinterpret_cast< unsigned long long >( thread ),
			sizeof( void* )
		);

		state->m_hidden_detection_count++;
		state->m_detection_count++;
	}

	void report_physical_window_slot( scan_state_t* state, PEPROCESS process, unsigned long pml4_index, unsigned long pages_1gb, unsigned long pages_2mb, unsigned long pages_4kb, unsigned long long first_va, unsigned long long first_pfn, unsigned long first_page_size, bool writable, bool executable ) {
		if ( !state || !state->m_command || !process || state->m_physical_window_count >= m_max_physical_window_reports )
			return;

		auto pid = reinterpret_cast< unsigned long long >( PsGetProcessId( process ) );
		auto name = PsGetProcessImageFileName( process );

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"process!%s:%llu",
			name ? name : "unknown",
			pid
		);

		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"pml4=%lu va=0x%llx pfn=0x%llx 1g=%lu 2m=%lu 4k=%lu rw=%u nx=%u",
			pml4_index,
			first_va,
			first_pfn,
			pages_1gb,
			pages_2mb,
			pages_4kb,
			static_cast< unsigned long >( writable ),
			static_cast< unsigned long >( !executable )
		);

		report::add_memory_detection(
			state->m_command,
			target,
			report::m_process_physical_window_violation,
			detail,
			first_va,
			first_page_size
		);

		state->m_physical_window_count++;
		state->m_detection_count++;
		state->m_large_page_window_count++;
	}

	void inspect_physical_window_slot( scan_state_t* state, PEPROCESS process, const pml4e& directory, unsigned long pml4_index ) {
		if ( !state || !process || !directory.hard.present || !directory.hard.user_supervisor )
			return;

		unsigned long pages_1gb = 0;
		unsigned long pages_2mb = 0;
		unsigned long pages_4kb = 0;
		unsigned long long first_va = 0;
		unsigned long long first_pfn = 0;
		unsigned long first_page_size = 0;
		bool first_writable = false;
		bool first_executable = false;

		for ( auto pdpt_index = 0ul; pdpt_index < 512; pdpt_index++ ) {
			pdpte entry{ };
			if ( !memory_scan::read_entry( directory.hard.pfn, pdpt_index, &entry ) || !entry.hard.present )
				continue;

			if ( !entry.hard.user_supervisor )
				continue;

			auto pdpt_va = memory_scan::make_va( pml4_index, pdpt_index, 0, 0 );
			auto pdpt_writable = directory.hard.read_write && entry.hard.read_write;
			auto pdpt_executable = !( directory.hard.no_execute || entry.hard.no_execute );

			if ( entry.hard.page_size ) {
				auto pfn = entry_pfn( entry );
				if ( !mapping_overlaps_physical_ranges( state, pfn, page_1gb_size ) )
					continue;

				pages_1gb++;
				if ( first_va )
					continue;

				first_va = pdpt_va;
				first_pfn = pfn;
				first_page_size = page_1gb_size;
				first_writable = pdpt_writable;
				first_executable = pdpt_executable;
				continue;
			}

			for ( auto pd_index = 0ul; pd_index < 512; pd_index++ ) {
				pde pd_entry{ };
				if ( !memory_scan::read_entry( entry.hard.pfn, pd_index, &pd_entry ) || !pd_entry.hard.present )
					continue;

				if ( !pd_entry.hard.user_supervisor )
					continue;

				auto pd_writable = pdpt_writable && pd_entry.hard.read_write;
				auto pd_executable = pdpt_executable && !pd_entry.hard.no_execute;

				if ( pd_entry.hard.page_size ) {
					auto pfn = entry_pfn( pd_entry );
					if ( !mapping_overlaps_physical_ranges( state, pfn, page_2mb_size ) )
						continue;

					pages_2mb++;
					if ( first_va )
						continue;

					first_va = memory_scan::make_va( pml4_index, pdpt_index, pd_index, 0 );
					first_pfn = pfn;
					first_page_size = page_2mb_size;
					first_writable = pd_writable;
					first_executable = pd_executable;
					continue;
				}

				for ( auto pt_index = 0ul; pt_index < 512; pt_index++ ) {
					pte pt_entry{ };
					if ( !memory_scan::read_entry( pd_entry.hard.pfn, pt_index, &pt_entry ) || !pt_entry.hard.present )
						continue;

					if ( !pt_entry.hard.user_supervisor )
						continue;

					auto pfn = entry_pfn( pt_entry );
					if ( !mapping_overlaps_physical_ranges( state, pfn, PAGE_SIZE ) )
						continue;

					pages_4kb++;
					if ( first_va )
						continue;

					first_va = memory_scan::make_va( pml4_index, pdpt_index, pd_index, pt_index );
					first_pfn = pfn;
					first_page_size = PAGE_SIZE;
					first_writable = pd_writable && pt_entry.hard.read_write;
					first_executable = pd_executable && !pt_entry.hard.no_execute;
				}
			}
		}

		if ( pages_1gb < m_min_physical_window_1gb_pages &&
			pages_2mb < m_min_physical_window_2mb_pages &&
			pages_4kb < m_min_physical_window_4kb_pages )
			return;

		report_physical_window_slot( state, process, pml4_index, pages_1gb, pages_2mb, pages_4kb, first_va, first_pfn, first_page_size, first_writable, first_executable );
	}

	void scan_physical_window_slots( scan_state_t* state, PEPROCESS process, unsigned long long directory_table_base ) {
		if ( !state || !process || !directory_table_base )
			return;

		for ( auto pml4_index = 1ul; pml4_index < 256 && state->m_physical_window_count < m_max_physical_window_reports; pml4_index++ ) {
			pml4e entry{ };
			if ( !paging::remap::read_physical(
				directory_table_base + pml4_index * sizeof( pml4e ),
				&entry,
				sizeof( entry )
			) || !entry.hard.present ) {
				continue;
			}

			inspect_physical_window_slot( state, process, entry, pml4_index );
		}
	}

	void inspect_user_mapping( scan_state_t* state, PEPROCESS process, unsigned long long va, unsigned long long pfn, unsigned long page_size, bool user, bool writable, bool executable ) {
		if ( !state || !process || !user || memory::is_canonical_kernel_address( va ) )
			return;

		state->m_leaf_count++;

		if ( page_size == page_1gb_size && mapping_overlaps_physical_ranges( state, pfn, page_size ) ) {
			report_physical_window_mapping( state, process, va, pfn, page_size, writable, executable );
			return;
		}

		if ( !pfn )
			return;

		if ( !writable )
			return;

		kernel_pfn_t owner{ };
		auto pages = page_size / PAGE_SIZE;
		if ( !find_kernel_pfn( state, pfn, static_cast< unsigned long >( pages ), &owner ) )
			return;

		report_kernel_page_mapping( state, process, va, pfn, page_size, writable, executable, owner );
	}

	void walk_pt( scan_state_t* state, PEPROCESS process, const pde& directory, unsigned long pml4_index, unsigned long pdpt_index, unsigned long pd_index, bool inherited_user, bool inherited_rw, bool inherited_nx ) {
		for ( auto pt_index = 0ul; pt_index < 512 && state->m_leaf_count < m_max_process_leaf_entries; pt_index++ ) {
			pte entry{ };
			if ( !memory_scan::read_entry( directory.hard.pfn, pt_index, &entry ) || !entry.hard.present )
				continue;

			auto va = memory_scan::make_va( pml4_index, pdpt_index, pd_index, pt_index );
			auto user = inherited_user && entry.hard.user_supervisor;
			auto writable = inherited_rw && entry.hard.read_write;
			auto executable = !( inherited_nx || entry.hard.no_execute );
			inspect_user_mapping( state, process, va, entry_pfn( entry ), PAGE_SIZE, user, writable, executable );
		}
	}

	void walk_pd( scan_state_t* state, PEPROCESS process, const pdpte& directory, unsigned long pml4_index, unsigned long pdpt_index, bool inherited_user, bool inherited_rw, bool inherited_nx ) {
		for ( auto pd_index = 0ul; pd_index < 512 && state->m_leaf_count < m_max_process_leaf_entries; pd_index++ ) {
			pde entry{ };
			if ( !memory_scan::read_entry( directory.hard.pfn, pd_index, &entry ) || !entry.hard.present )
				continue;

			auto va = memory_scan::make_va( pml4_index, pdpt_index, pd_index, 0 );
			auto user = inherited_user && entry.hard.user_supervisor;
			auto writable = inherited_rw && entry.hard.read_write;
			auto executable = !( inherited_nx || entry.hard.no_execute );

			if ( entry.hard.page_size ) {
				inspect_user_mapping( state, process, va, entry_pfn( entry ), page_2mb_size, user, writable, executable );
				continue;
			}

			walk_pt( state, process, entry, pml4_index, pdpt_index, pd_index, user, writable, !executable );
		}
	}

	void walk_pdpt( scan_state_t* state, PEPROCESS process, const pml4e& directory, unsigned long pml4_index ) {
		for ( auto pdpt_index = 0ul; pdpt_index < 512 && state->m_leaf_count < m_max_process_leaf_entries; pdpt_index++ ) {
			pdpte entry{ };
			if ( !memory_scan::read_entry( directory.hard.pfn, pdpt_index, &entry ) || !entry.hard.present )
				continue;

			auto va = memory_scan::make_va( pml4_index, pdpt_index, 0, 0 );
			auto user = directory.hard.user_supervisor && entry.hard.user_supervisor;
			auto writable = directory.hard.read_write && entry.hard.read_write;
			auto executable = !( directory.hard.no_execute || entry.hard.no_execute );

			if ( entry.hard.page_size ) {
				inspect_user_mapping( state, process, va, entry_pfn( entry ), page_1gb_size, user, writable, executable );
				continue;
			}

			walk_pd( state, process, entry, pml4_index, pdpt_index, user, writable, !executable );
		}
	}

	void scan_process( scan_state_t* state, PEPROCESS process ) {
		if ( !state || !process )
			return;

		auto directory_table_base = process_directory_table_base( process );
		if ( !directory_table_base )
			return;

		state->m_process_count++;
		scan_physical_window_slots( state, process, directory_table_base );

		for ( auto pml4_index = 0ul; pml4_index < 256 && state->m_leaf_count < m_max_process_leaf_entries; pml4_index++ ) {
			pml4e entry{ };
			if ( !paging::remap::read_physical(
				directory_table_base + pml4_index * sizeof( pml4e ),
				&entry,
				sizeof( entry )
			) || !entry.hard.present ) {
				continue;
			}

			walk_pdpt( state, process, entry, pml4_index );
		}
	}

	void collect_visible_process_entry( scan_state_t* state, const system_process_information_t* process_info ) {
		if ( !state || !process_info )
			return;

		auto pid = reinterpret_cast< unsigned long long >( process_info->m_process_id );
		if ( pid ) {
			append_unique_id( state->m_visible_pids, &state->m_visible_pid_count, m_max_visible_processes, pid );
			if ( pid > state->m_max_seen_cid )
				state->m_max_seen_cid = pid;
		}

		auto threads = reinterpret_cast< const system_thread_information_t* >(
			reinterpret_cast< const unsigned char* >( process_info ) + sizeof( system_process_information_t )
		);

		for ( auto index = 0ul; index < process_info->m_thread_count && index < 4096ul; index++ ) {
			auto tid = reinterpret_cast< unsigned long long >( threads[ index ].m_client_id.m_unique_thread );
			if ( !tid )
				continue;

			append_unique_id( state->m_visible_tids, &state->m_visible_tid_count, m_max_visible_threads, tid );
			if ( tid > state->m_max_seen_cid )
				state->m_max_seen_cid = tid;
		}
	}

	void scan_cid_processes( scan_state_t* state, const system_modules_t* modules ) {
		if ( !state || !state->m_command )
			return;

		auto limit = state->m_max_seen_cid + m_cid_probe_slack;
		if ( limit > m_cid_probe_hard_limit )
			limit = m_cid_probe_hard_limit;

		for ( auto pid = 4ull; pid <= limit && state->m_hidden_detection_count < m_max_hidden_reports; pid += 4ull ) {
			if ( contains_id( state->m_visible_pids, state->m_visible_pid_count, pid ) )
				continue;

			PEPROCESS process = nullptr;
			if ( PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( pid ), &process ) || !process )
				continue;

			if ( !is_active_process( process ) || is_whitelisted_session_process( process ) || query_contains_process_id( pid ) ) {
				ObDereferenceObject( process );
				continue;
			}

			report_hidden_process_detection( state, process, report::m_cid_process_missing_violation, "source=cid_query missing=system_process");

			if ( has_orphan_address_space( process, modules ) )
				report_hidden_process_detection( state, process, report::m_orphan_process_address_space_violation, "source=cid_query address_space=valid");

			ObDereferenceObject( process );
		}
	}

	void scan_cid_threads( scan_state_t* state ) {
		if ( !state || !state->m_command )
			return;

		auto limit = state->m_max_seen_cid + m_cid_probe_slack;
		if ( limit > m_cid_probe_hard_limit )
			limit = m_cid_probe_hard_limit;

		for ( auto tid = 4ull; tid <= limit && state->m_hidden_detection_count < m_max_hidden_reports; tid += 4ull ) {
			if ( contains_id( state->m_visible_tids, state->m_visible_tid_count, tid ) )
				continue;

			PETHREAD thread = nullptr;
			if ( PsLookupThreadByThreadId( reinterpret_cast< HANDLE >( tid ), &thread ) || !thread )
				continue;

			auto owner = PsGetThreadProcess( thread );
			auto owner_pid = owner ? reinterpret_cast< unsigned long long >( PsGetProcessId( owner ) ) : 0;

			if ( !contains_id( state->m_visible_pids, state->m_visible_pid_count, owner_pid ) &&
				is_active_process( owner ) &&
				!query_contains_process_id( owner_pid ) &&
				!is_whitelisted_session_process( owner ) ) {
				report_hidden_thread_detection( state, thread, owner, tid );
			}

			ObDereferenceObject( thread );
		}
	}

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		auto kernel_pfns = memory::allocate_pool< kernel_pfn_t* >( sizeof( kernel_pfn_t ) * m_max_kernel_pfns, 1 );
		if ( !kernel_pfns ) {
			command->m_error = STATUS_INSUFFICIENT_RESOURCES;
			return false;
		}

		auto visible_pids = memory::allocate_pool< unsigned long long* >( sizeof( unsigned long long ) * m_max_visible_processes, 1 );
		auto visible_tids = memory::allocate_pool< unsigned long long* >( sizeof( unsigned long long ) * m_max_visible_threads, 1 );
		if ( !visible_pids || !visible_tids ) {
			if ( visible_pids )
				memory::free_pool( visible_pids );

			if ( visible_tids )
				memory::free_pool( visible_tids );

			memory::free_pool( kernel_pfns );
			command->m_error = STATUS_INSUFFICIENT_RESOURCES;
			return false;
		}

		memset( kernel_pfns, 0, sizeof( kernel_pfn_t ) * m_max_kernel_pfns );
		memset( visible_pids, 0, sizeof( unsigned long long ) * m_max_visible_processes );
		memset( visible_tids, 0, sizeof( unsigned long long ) * m_max_visible_threads );

		scan_state_t state{ };
		state.m_command = command;
		state.m_kernel_pfns = kernel_pfns;
		state.m_physical_ranges = MmGetPhysicalMemoryRanges( );
		state.m_visible_pids = visible_pids;
		state.m_visible_tids = visible_tids;

		build_kernel_pfn_index( &state, modules );

		void* process_buffer = nullptr;
		if ( query_processes( &process_buffer ) ) {
			auto process_info = static_cast< system_process_information_t* >( process_buffer );
			while ( process_info && state.m_process_count < m_max_processes ) {
				collect_visible_process_entry( &state, process_info );

				if ( process_info->m_process_id ) {
					PEPROCESS process = nullptr;
					if ( !PsLookupProcessByProcessId( process_info->m_process_id, &process ) && process ) {
						scan_process( &state, process );
						ObDereferenceObject( process );
					}
				}

				if ( !process_info->m_next_entry_offset )
					break;

				process_info = reinterpret_cast< system_process_information_t* >(
					reinterpret_cast< unsigned char* >( process_info ) + process_info->m_next_entry_offset
				);
			}

			memory::free_pool( process_buffer );
		}

		scan_cid_processes( &state, modules );
		scan_cid_threads( &state );

		command->m_modules_scanned = state.m_process_count;
		command->m_sections_scanned = state.m_leaf_count;
		command->m_signature_candidates = state.m_kernel_pfn_count;
		command->m_signature_detections = state.m_detection_count;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;

		utility::print(
			"process integrity: processes=%lu user_leafs=%lu kernel_pfns=%lu detections=%lu\n",
			state.m_process_count,
			state.m_leaf_count,
			state.m_kernel_pfn_count,
			state.m_detection_count
		);

		if ( state.m_physical_ranges )
			ExFreePool( state.m_physical_ranges );

		memory::free_pool( kernel_pfns );
		memory::free_pool( visible_pids );
		memory::free_pool( visible_tids );
		return true;
	}
}
