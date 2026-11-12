#pragma once

namespace memory_scan {
	constexpr auto m_max_pfn_records = 65536ul;
	constexpr auto m_max_leaf_entries = 2097152ul;

	struct page_mapping_t {
		unsigned long long m_va;
		unsigned long long m_pfn;
		unsigned long m_page_size;
		bool m_kernel;
		bool m_user;
		bool m_writable;
		bool m_executable;
		bool m_cache_disabled;
		bool m_write_through;
	};

	struct pfn_record_t {
		unsigned long long m_pfn;
		unsigned long long m_first_user_va;
		unsigned long long m_first_kernel_va;
		unsigned long long m_first_rw_va;
		unsigned long long m_first_rx_va;
		bool m_user;
		bool m_kernel;
		bool m_rw;
		bool m_rx;
		bool m_reported_user_kernel;
		bool m_reported_rw_rx;
	};

	struct scan_state_t {
		ioctl::command_t* m_command;
		const system_modules_t* m_modules;
		PPHYSICAL_MEMORY_RANGE m_physical_ranges;
		pfn_record_t* m_records;
		unsigned long m_record_count;
		unsigned long m_leaf_count;
		unsigned long m_permission_detections;
		unsigned long m_backing_detections;
		unsigned long m_alias_detections;
		unsigned long m_anonymous_detections;
		unsigned long m_table_detections;
		unsigned long m_pml4_detections;
		unsigned long m_wx_candidates;
		unsigned long m_wx_suppressed;
		unsigned long long m_executable_region_start;
		unsigned long long m_executable_region_end;
		unsigned long m_executable_region_pages;
		bool m_executable_region_has_executable;
		unsigned long long m_pfn_db_base;
		unsigned long m_self_ref_pml4_index;
		bool m_has_self_ref_pml4;
		unsigned long m_pfn_db_detections;
	};

	unsigned long long canonicalize_va( unsigned long long address ) {
		if ( address & ( 1ull << 47 ) )
			return address | 0xffff000000000000ull;

		return address;
	}

	unsigned long long make_va( unsigned long pml4_index, unsigned long pdpt_index, unsigned long pd_index, unsigned long pt_index ) {
		auto address =
			( static_cast< unsigned long long >( pml4_index ) << 39 ) |
			( static_cast< unsigned long long >( pdpt_index ) << 30 ) |
			( static_cast< unsigned long long >( pd_index ) << 21 ) |
			( static_cast< unsigned long long >( pt_index ) << 12 );

		return canonicalize_va( address );
	}

	bool is_kernel_va( unsigned long long address ) {
		return memory::is_canonical_kernel_address( address );
	}

	const char* owner_name( const system_modules_t* modules, unsigned long long address ) {
		auto owner = memory::lookup_address_owner( modules, address );
		return owner ? owner : "unknown";
	}

	bool is_module_backed( const system_modules_t* modules, unsigned long long address ) {
		return memory::lookup_address_owner( modules, address ) != nullptr;
	}

	bool is_device_like_mapping( const page_mapping_t& mapping ) {
		return mapping.m_cache_disabled || mapping.m_write_through;
	}

	bool is_low_mmio_physical_address( unsigned long long physical_address ) {
		return
			( physical_address >= 0xa0000ull && physical_address < 0x100000ull ) ||
			( physical_address >= 0xe0000000ull && physical_address < 0x100000000ull );
	}

	bool read_table( unsigned long long pfn, void* buffer, unsigned long bytes ) {
		return paging::remap::read_physical( pfn << page_shift, buffer, bytes );
	}

	template < typename entry_t >
	bool read_entry( unsigned long long pfn, unsigned long index, entry_t* entry ) {
		if ( !entry )
			return false;

		return paging::remap::read_physical(
			( pfn << page_shift ) + index * sizeof( entry_t ),
			entry,
			sizeof( entry_t )
		);
	}

	unsigned long long pte_page_pfn( const pte& entry ) {
		return entry.hard.pfn;
	}

	unsigned long long pde_page_pfn( const pde& entry ) {
		return entry.hard.pfn & ~( ( page_2mb_size / page_4kb_size ) - 1 );
	}

	unsigned long long pdpte_page_pfn( const pdpte& entry ) {
		return entry.hard.pfn & ~( ( page_1gb_size / page_4kb_size ) - 1 );
	}
}
