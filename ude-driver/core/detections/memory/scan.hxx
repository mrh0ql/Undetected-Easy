#pragma once

namespace memory_scan::pml4 {
	bool is_expected_kernel_slot( unsigned long index ) {
		return index >= 256;
	}

	void inspect( scan_state_t* state, unsigned long index, const pml4e& entry ) {
		if ( !state || !state->m_command || !entry.hard.present )
			return;

		if ( !is_expected_kernel_slot( index ) )
			return;

		if ( !entry.hard.user_supervisor )
			return;

		auto va = make_va( index, 0, 0, 0 );
		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"slot=%lu pml4e=0x%llx pfn=0x%llx user=%u rw=%u nx=%u",
			index,
			entry.value,
			entry.hard.pfn,
			static_cast< unsigned long >( entry.hard.user_supervisor ),
			static_cast< unsigned long >( entry.hard.read_write ),
			static_cast< unsigned long >( entry.hard.no_execute )
		);

		report::add_memory_detection(
			state->m_command,
			"memory!pml4",
			report::m_suspicious_pml4_slot_violation,
			detail,
			va,
			PAGE_SIZE
		);
		state->m_pml4_detections++;
	}
}

namespace memory_scan {
	void report_page_table_issue( scan_state_t* state, const char* level, const char* reason, unsigned long long va, unsigned long long entry_value, unsigned long long pfn ) {
		if ( !state || !state->m_command )
			return;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"level=%s reason=%s va=0x%llx entry=0x%llx pfn=0x%llx",
			level ? level : "unknown",
			reason ? reason : "unknown",
			va,
			entry_value,
			pfn
		);

		report::add_memory_detection(
			state->m_command,
			"memory!paging",
			report::m_page_table_consistency_violation,
			detail,
			va,
			PAGE_SIZE
		);
		state->m_table_detections++;
	}

	void check_pte_consistency( scan_state_t* state, const pte& entry, unsigned long long va ) {
		UNREFERENCED_PARAMETER( state );
		UNREFERENCED_PARAMETER( entry );
		UNREFERENCED_PARAMETER( va );
	}

	void check_pde_consistency( scan_state_t* state, const pde& entry, unsigned long long va ) {
		if ( !entry.hard.present )
			return;

		if ( entry.hard.page_size && entry.hard.pfn != pde_page_pfn( entry ) )
			report_page_table_issue( state, "pde", "unaligned_large_page_pfn", va, entry.value, entry.hard.pfn );
	}

	void check_pdpte_consistency( scan_state_t* state, const pdpte& entry, unsigned long long va ) {
		if ( !entry.hard.present )
			return;

		if ( entry.hard.page_size && entry.hard.pfn != pdpte_page_pfn( entry ) )
			report_page_table_issue( state, "pdpte", "unaligned_large_page_pfn", va, entry.value, entry.hard.pfn );
	}

	void check_pml4e_consistency( scan_state_t* state, const pml4e& entry, unsigned long pml4_index ) {
		if ( !entry.hard.present )
			return;

		if ( entry.hard.large_page )
			report_page_table_issue( state, "pml4e", "reserved_large_page_bit", make_va( pml4_index, 0, 0, 0 ), entry.value, entry.hard.pfn );
	}

	void inspect_mapping( scan_state_t* state, const page_mapping_t& mapping ) {
		if ( !state )
			return;

		state->m_leaf_count++;
		permissions::inspect( state, mapping );
		aliases::inspect( state, mapping );
	}

	bool walk_pt( scan_state_t* state, const pde& directory, unsigned long pml4_index, unsigned long pdpt_index, unsigned long pd_index, bool inherited_user, bool inherited_rw, bool inherited_nx, bool inherited_cd, bool inherited_wt ) {
		for ( auto pt_index = 0ul; pt_index < 512 && state->m_leaf_count < m_max_leaf_entries; pt_index++ ) {
			pte entry{ };
			if ( !read_entry( directory.hard.pfn, pt_index, &entry ) )
				return false;

			if ( !entry.hard.present )
				continue;

			auto va = make_va( pml4_index, pdpt_index, pd_index, pt_index );
			check_pte_consistency( state, entry, va );
			page_mapping_t mapping{ };
			mapping.m_va = va;
			mapping.m_pfn = pte_page_pfn( entry );
			mapping.m_page_size = PAGE_SIZE;
			mapping.m_kernel = is_kernel_va( va );
			mapping.m_user = inherited_user && entry.hard.user_supervisor;
			mapping.m_writable = inherited_rw && entry.hard.read_write;
			mapping.m_executable = !( inherited_nx || entry.hard.no_execute );
			mapping.m_cache_disabled = inherited_cd || entry.hard.cached_disable;
			mapping.m_write_through = inherited_wt || entry.hard.page_write_through;
			inspect_mapping( state, mapping );
		}

		return true;
	}

	bool walk_pd( scan_state_t* state, const pdpte& directory, unsigned long pml4_index, unsigned long pdpt_index, bool inherited_user, bool inherited_rw, bool inherited_nx, bool inherited_cd, bool inherited_wt ) {
		for ( auto pd_index = 0ul; pd_index < 512 && state->m_leaf_count < m_max_leaf_entries; pd_index++ ) {
			pde entry{ };
			if ( !read_entry( directory.hard.pfn, pd_index, &entry ) )
				return false;

			if ( !entry.hard.present )
				continue;

			auto user = inherited_user && entry.hard.user_supervisor;
			auto writable = inherited_rw && entry.hard.read_write;
			auto nx = inherited_nx || entry.hard.no_execute;
			auto cache_disabled = inherited_cd || entry.hard.cached_disable;
			auto write_through = inherited_wt || entry.hard.page_write_through;
			auto va = make_va( pml4_index, pdpt_index, pd_index, 0 );
			check_pde_consistency( state, entry, va );

			if ( entry.hard.page_size ) {
				page_mapping_t mapping{ };
				mapping.m_va = va;
				mapping.m_pfn = pde_page_pfn( entry );
				mapping.m_page_size = page_2mb_size;
				mapping.m_kernel = is_kernel_va( va );
				mapping.m_user = user;
				mapping.m_writable = writable;
				mapping.m_executable = !nx;
				mapping.m_cache_disabled = cache_disabled;
				mapping.m_write_through = write_through;
				inspect_mapping( state, mapping );
				continue;
			}

			walk_pt( state, entry, pml4_index, pdpt_index, pd_index, user, writable, nx, cache_disabled, write_through );
		}

		return true;
	}

	bool walk_pdpt( scan_state_t* state, const pml4e& directory, unsigned long pml4_index ) {
		for ( auto pdpt_index = 0ul; pdpt_index < 512 && state->m_leaf_count < m_max_leaf_entries; pdpt_index++ ) {
			pdpte entry{ };
			if ( !read_entry( directory.hard.pfn, pdpt_index, &entry ) )
				return false;

			if ( !entry.hard.present )
				continue;

			auto user = directory.hard.user_supervisor && entry.hard.user_supervisor;
			auto writable = directory.hard.read_write && entry.hard.read_write;
			auto nx = directory.hard.no_execute || entry.hard.no_execute;
			auto cache_disabled = directory.hard.cached_disable || entry.hard.cached_disable;
			auto write_through = directory.hard.page_write_through || entry.hard.page_write_through;
			auto va = make_va( pml4_index, pdpt_index, 0, 0 );
			check_pdpte_consistency( state, entry, va );

			if ( entry.hard.page_size ) {
				page_mapping_t mapping{ };
				mapping.m_va = va;
				mapping.m_pfn = pdpte_page_pfn( entry );
				mapping.m_page_size = page_1gb_size;
				mapping.m_kernel = is_kernel_va( va );
				mapping.m_user = user;
				mapping.m_writable = writable;
				mapping.m_executable = !nx;
				mapping.m_cache_disabled = cache_disabled;
				mapping.m_write_through = write_through;
				inspect_mapping( state, mapping );
				continue;
			}

			walk_pd( state, entry, pml4_index, pdpt_index, user, writable, nx, cache_disabled, write_through );
		}

		return true;
	}

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		auto records = memory::allocate_pool< pfn_record_t* >( sizeof( pfn_record_t ) * m_max_pfn_records, 1 );
		if ( !records ) {
			command->m_error = STATUS_INSUFFICIENT_RESOURCES;
			return false;
		}

		memset( records, 0, sizeof( pfn_record_t ) * m_max_pfn_records );

		scan_state_t state{ };
		state.m_command = command;
		state.m_modules = modules;
		state.m_physical_ranges = MmGetPhysicalMemoryRanges( );
		state.m_records = records;

		if ( memory::is_canonical_kernel_address( m_entry.m_pdb.m_mm_pfn_database ) ) {
			size_t copied = 0;
			unsigned long long db_base = 0;
			if ( memory::copy_kernel_memory(
				reinterpret_cast< void* >( m_entry.m_pdb.m_mm_pfn_database ),
				sizeof( db_base ),
				&db_base,
				&copied ) && memory::is_canonical_kernel_address( db_base ) ) {
				state.m_pfn_db_base = db_base;
			}
		}

		auto cr3_pfn = ( paging::m_directory_table_base & ~0xfffull ) >> page_shift;
		for ( auto slot = 256ul; slot < 512ul; slot++ ) {
			pml4e self_entry{ };
			if ( paging::remap::read_physical(
				( paging::m_directory_table_base & ~0xfffull ) + slot * sizeof( pml4e ),
				&self_entry,
				sizeof( self_entry )
			) && self_entry.hard.present && self_entry.hard.pfn == cr3_pfn ) {
				state.m_self_ref_pml4_index = slot;
				state.m_has_self_ref_pml4 = true;
				break;
			}
		}

		// Memory Integrity classifies kernel mappings. Walking user slots first can
		// consume the leaf budget before the walker ever reaches the kernel half.
		for ( auto pml4_index = 256ul; pml4_index < 512 && state.m_leaf_count < m_max_leaf_entries; pml4_index++ ) {
			pml4e entry{ };
			if ( !paging::remap::read_physical(
				( paging::m_directory_table_base & ~0xf ) + pml4_index * sizeof( pml4e ),
				&entry,
				sizeof( entry )
			) ) {
				continue;
			}

			if ( !entry.hard.present )
				continue;

			check_pml4e_consistency( &state, entry, pml4_index );
			pml4::inspect( &state, pml4_index, entry );
			walk_pdpt( &state, entry, pml4_index );
		}

		permissions::flush_executable_region( &state );

		utility::print(
			"memory integrity: leaf_entries=%lu pfn_records=%lu backing_detections=%lu permission_detections=%lu alias_detections=%lu anonymous_detections=%lu table_detections=%lu pml4_detections=%lu pfn_db_detections=%lu wx_candidates=%lu suppressed=%lu detections=%lu\n",
			state.m_leaf_count,
			state.m_record_count,
			state.m_backing_detections,
			state.m_permission_detections,
			state.m_alias_detections,
			state.m_anonymous_detections,
			state.m_table_detections,
			state.m_pml4_detections,
			state.m_pfn_db_detections,
			state.m_wx_candidates,
			state.m_wx_suppressed,
			command->m_total_detection_count
		);

		command->m_sections_scanned = state.m_leaf_count;
		command->m_signature_candidates = state.m_record_count;
		command->m_signature_detections = state.m_backing_detections + state.m_permission_detections + state.m_alias_detections + state.m_anonymous_detections + state.m_table_detections + state.m_pml4_detections + state.m_pfn_db_detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;

		if ( state.m_physical_ranges )
			ExFreePool( state.m_physical_ranges );

		memory::free_pool( records );
		return true;
	}
}
