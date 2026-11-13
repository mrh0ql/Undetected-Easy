#pragma once

namespace memory_scan::permissions {
	constexpr auto m_max_unlisted_image_size = 64ul * 1024ul * 1024ul;
	constexpr auto m_max_image_sections = 96u;
	constexpr auto m_min_unwind_run = 2ul;
	constexpr auto m_min_import_run = 1ul;

	struct headerless_image_evidence_t {
		unsigned long m_pages;
		unsigned long m_private_4kb_pages;
		unsigned long m_executable_pages;
		unsigned long m_max_unwind_run;
		unsigned long m_max_import_run;
	};

	bool is_mapping_inside_physical_ranges( const scan_state_t* state, const page_mapping_t& mapping );

	bool copy_virtual( unsigned long long address, void* buffer, size_t size ) {
		size_t copied = 0;
		return buffer && size && memory::copy_kernel_memory(
			reinterpret_cast< void* >( address ), size, buffer, &copied );
	}

	bool validate_mapped_pe_image(
		unsigned long long image,
		unsigned long long region_end,
		unsigned long* image_size,
		unsigned long* entry_rva,
		unsigned long* executable_sections ) {
		if ( image_size )
			*image_size = 0;
		if ( entry_rva )
			*entry_rva = 0;
		if ( executable_sections )
			*executable_sections = 0;

		if ( !image || image >= region_end || region_end - image < sizeof( IMAGE_DOS_HEADER ) )
			return false;

		IMAGE_DOS_HEADER dos{ };
		if ( !copy_virtual( image, &dos, sizeof( dos ) ) ||
			dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
			static_cast< unsigned long >( dos.e_lfanew ) > 0x100000ul )
			return false;

		auto nt_address = image + static_cast< unsigned long >( dos.e_lfanew );
		if ( nt_address < image || nt_address > region_end - sizeof( IMAGE_NT_HEADERS64 ) )
			return false;

		IMAGE_NT_HEADERS64 nt{ };
		if ( !copy_virtual( nt_address, &nt, sizeof( nt ) ) ||
			nt.Signature != IMAGE_NT_SIGNATURE ||
			nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
			nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
			!nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections > m_max_image_sections )
			return false;

		auto mapped_size = nt.OptionalHeader.SizeOfImage;
		if ( mapped_size < PAGE_SIZE || mapped_size > m_max_unlisted_image_size || mapped_size > region_end - image )
			return false;

		if ( !nt.OptionalHeader.SizeOfHeaders || nt.OptionalHeader.SizeOfHeaders > mapped_size ||
			nt.OptionalHeader.AddressOfEntryPoint >= mapped_size )
			return false;

		auto section_table = nt_address +
			FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +
			nt.FileHeader.SizeOfOptionalHeader;
		auto section_bytes = static_cast< unsigned long long >( nt.FileHeader.NumberOfSections ) * sizeof( IMAGE_SECTION_HEADER );
		if ( section_table < nt_address || section_table > image + mapped_size ||
			section_bytes > image + mapped_size - section_table ||
			section_table > image + nt.OptionalHeader.SizeOfHeaders ||
			section_bytes > image + nt.OptionalHeader.SizeOfHeaders - section_table )
			return false;

		unsigned long executable_count = 0;
		bool entry_is_executable = false;
		for ( auto index = 0u; index < nt.FileHeader.NumberOfSections; index++ ) {
			IMAGE_SECTION_HEADER section{ };
			if ( !copy_virtual( section_table + index * sizeof( section ), &section, sizeof( section ) ) )
				return false;

			auto section_size = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
			if ( !section_size || section.VirtualAddress >= mapped_size || section_size > mapped_size - section.VirtualAddress )
				return false;

			if ( section.Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
				executable_count++;
				if ( nt.OptionalHeader.AddressOfEntryPoint >= section.VirtualAddress &&
					nt.OptionalHeader.AddressOfEntryPoint < section.VirtualAddress + section_size )
					entry_is_executable = true;
			}
		}

		if ( !executable_count || !entry_is_executable )
			return false;

		paging::pt_entries_t entry_mapping{ };
		if ( !paging::hyperspace_entries( entry_mapping, image + nt.OptionalHeader.AddressOfEntryPoint ) )
			return false;

		auto entry_executable = entry_mapping.m_pdpte.hard.page_size ? !entry_mapping.m_pdpte.hard.no_execute :
			entry_mapping.m_pde.hard.page_size ? !entry_mapping.m_pde.hard.no_execute :
			!entry_mapping.m_pte.hard.no_execute;
		if ( !entry_executable )
			return false;

		if ( image_size )
			*image_size = mapped_size;
		if ( entry_rva )
			*entry_rva = nt.OptionalHeader.AddressOfEntryPoint;
		if ( executable_sections )
			*executable_sections = executable_count;
		return true;
	}

	bool validate_resident_pe_header( unsigned long long image, unsigned long long available_end, unsigned long* image_size ) {
		if ( image_size )
			*image_size = 0;
		if ( !image || image >= available_end || available_end - image < PAGE_SIZE )
			return false;

		memory::scoped_page_t header{ };
		if ( !header || !copy_virtual( image, header.get( ), PAGE_SIZE ) )
			return false;

		auto nt = memory::validate_pe_image( header.get( ), PAGE_SIZE );
		if ( !nt || !nt->OptionalHeader.SizeOfImage ||
			nt->OptionalHeader.SizeOfImage > m_max_unlisted_image_size ||
			!nt->OptionalHeader.AddressOfEntryPoint )
			return false;

		auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( nt ) );
		bool entry_is_executable = false;
		for ( auto index = 0u; index < nt->FileHeader.NumberOfSections; index++ ) {
			auto section = &sections[ index ];
			auto size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
			if ( ( section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && size &&
				nt->OptionalHeader.AddressOfEntryPoint >= section->VirtualAddress &&
				nt->OptionalHeader.AddressOfEntryPoint < section->VirtualAddress + size ) {
				entry_is_executable = true;
				break;
			}
		}

		if ( !entry_is_executable )
			return false;

		if ( image_size )
			*image_size = nt->OptionalHeader.SizeOfImage;
		return true;
	}

	unsigned long unwind_run_at( const unsigned char* bytes, unsigned long size, unsigned long offset, unsigned long image_span ) {
		if ( !bytes || offset + 12 > size || !image_span )
			return 0;

		unsigned long run = 0;
		unsigned long previous_begin = 0;
		for ( auto cursor = offset; cursor + 12 <= size; cursor += 12 ) {
			unsigned long begin = 0;
			unsigned long end = 0;
			unsigned long unwind = 0;
			memcpy( &begin, bytes + cursor, sizeof( begin ) );
			memcpy( &end, bytes + cursor + 4, sizeof( end ) );
			memcpy( &unwind, bytes + cursor + 8, sizeof( unwind ) );

			auto unwind_rva = unwind & ~3ul;
			if ( !begin || begin >= end || end > image_span ||
				end - begin > 0x100000ul || !unwind_rva || unwind_rva >= image_span ||
				( run && begin < previous_begin ) )
				break;

			previous_begin = begin;
			run++;
		}

		return run;
	}

	headerless_image_evidence_t analyze_headerless_image_region(
		const system_modules_t* modules,
		unsigned long long start,
		unsigned long long end ) {
		headerless_image_evidence_t evidence{ };
		if ( !modules || !start || end <= start || end - start > m_max_unlisted_image_size )
			return evidence;

		memory::scoped_page_t bytes{ };
		if ( !bytes )
			return evidence;

		auto span = static_cast< unsigned long >( end - start );
		for ( auto page = start; page < end; page += PAGE_SIZE ) {
			paging::pt_entries_t entries{ };
			if ( paging::hyperspace_entries( entries, page ) ) {
				evidence.m_pages++;
				if ( !entries.m_pdpte.hard.page_size && !entries.m_pde.hard.page_size && entries.m_pte.hard.pfn )
					evidence.m_private_4kb_pages++;

				auto executable = entries.m_pdpte.hard.page_size ? !entries.m_pdpte.hard.no_execute :
					entries.m_pde.hard.page_size ? !entries.m_pde.hard.no_execute :
					!entries.m_pte.hard.no_execute;
				if ( executable )
					evidence.m_executable_pages++;
			}

			memset( bytes.get( ), 0, PAGE_SIZE );
			if ( !copy_virtual( page, bytes.get( ), PAGE_SIZE ) )
				continue;

			unsigned long import_run = 0;
			for ( auto offset = 0ul; offset + sizeof( unsigned long long ) <= PAGE_SIZE; offset += sizeof( unsigned long long ) ) {
				unsigned long long pointer = 0;
				memcpy( &pointer, bytes.get( ) + offset, sizeof( pointer ) );
				auto owner = module::disk::find_module_by_address( modules, pointer );
				if ( owner && module::disk::is_address_in_executable_section( owner, pointer, nullptr, 0 ) ) {
					import_run++;
					if ( import_run > evidence.m_max_import_run )
						evidence.m_max_import_run = import_run;
				}
				else
					import_run = 0;
			}

			for ( auto offset = 0ul; offset + 12 <= PAGE_SIZE; offset += 4 ) {
				auto run = unwind_run_at( bytes.get( ), PAGE_SIZE, offset, span + 0x10000ul );
				if ( run > evidence.m_max_unwind_run )
					evidence.m_max_unwind_run = run;
			}
		}

		return evidence;
	}

	bool range_overlaps_loaded_module( const system_modules_t* modules, unsigned long long start, unsigned long long end ) {
		if ( !modules || !start || end <= start )
			return false;

		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto module = &modules->m_modules[ index ];
			auto module_start = reinterpret_cast< unsigned long long >( module->m_image_base );
			auto module_end = module_start + module->m_image_size;

			if ( !module_start || !module->m_image_size || module_end <= module_start )
				continue;

			if ( start < module_end && end > module_start )
				return true;
		}

		return false;
	}

	void flush_executable_region( scan_state_t* state ) {
		if ( !state || !state->m_command || !state->m_executable_region_start ||
			state->m_executable_region_end <= state->m_executable_region_start ) {
			if ( state ) {
				state->m_executable_region_start = 0;
				state->m_executable_region_end = 0;
				state->m_executable_region_pages = 0;
				state->m_executable_region_has_executable = false;
			}
			return;
		}

		if ( range_overlaps_loaded_module(
			state->m_modules,
			state->m_executable_region_start,
			state->m_executable_region_end
		) ) {
			state->m_executable_region_start = 0;
			state->m_executable_region_end = 0;
			state->m_executable_region_pages = 0;
			state->m_executable_region_has_executable = false;
			return;
		}

		if ( !state->m_executable_region_has_executable ) {
			state->m_executable_region_start = 0;
			state->m_executable_region_end = 0;
			state->m_executable_region_pages = 0;
			return;
		}

		bool reported_image = false;
		auto cursor = state->m_executable_region_start;
		memory::scoped_page_t page_bytes{ };
		while ( page_bytes && cursor < state->m_executable_region_end ) {
			memset( page_bytes.get( ), 0, PAGE_SIZE );
			if ( !copy_virtual( cursor, page_bytes.get( ), PAGE_SIZE ) ) {
				cursor += PAGE_SIZE;
				continue;
			}

			bool found = false;
			unsigned long long image = 0;
			unsigned long image_size = 0;
			unsigned long entry_rva = 0;
			unsigned long executable_sections = 0;
			for ( auto offset = 0ul; offset + sizeof( unsigned short ) <= PAGE_SIZE; offset += 16 ) {
				if ( *reinterpret_cast< const unsigned short* >( page_bytes.get( ) + offset ) != IMAGE_DOS_SIGNATURE )
					continue;

				image = cursor + offset;
				found = validate_mapped_pe_image(
					image,
					state->m_executable_region_end,
					&image_size,
					&entry_rva,
					&executable_sections );
				if ( !found )
					found = validate_resident_pe_header( image, state->m_executable_region_end, &image_size );
				if ( found )
					break;
			}

			if ( !found ) {
				cursor += PAGE_SIZE;
				continue;
			}

			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"base=0x%llx size=0x%lx entry=0x%lx exec_sections=%lu region_pages=%lu",
				image,
				image_size,
				entry_rva,
				executable_sections,
				state->m_executable_region_pages
			);
			report::add_memory_detection(
				state->m_command,
				"memory!unlisted_image",
				report::m_executable_unlisted_image_violation,
				detail,
				image,
				image_size
			);
			state->m_anonymous_detections++;
			reported_image = true;

			auto advance = ( static_cast< unsigned long long >( image_size ) + PAGE_SIZE - 1 ) &
				~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 );
			cursor = ( image + ( advance ? advance : PAGE_SIZE ) + PAGE_SIZE - 1 ) &
				~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 );
		}

		if ( !reported_image ) {
			auto evidence = analyze_headerless_image_region(
				state->m_modules,
				state->m_executable_region_start,
				state->m_executable_region_end
			);
			if ( evidence.m_private_4kb_pages > 5 && evidence.m_executable_pages &&
				evidence.m_max_unwind_run >= m_min_unwind_run &&
				evidence.m_max_import_run >= m_min_import_run ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"base=0x%llx size=0x%llx private4k=%lu exec=%lu unwind_run=%lu import_run=%lu",
					state->m_executable_region_start,
					state->m_executable_region_end - state->m_executable_region_start,
					evidence.m_private_4kb_pages,
					evidence.m_executable_pages,
					evidence.m_max_unwind_run,
					evidence.m_max_import_run
				);
				report::add_memory_detection(
					state->m_command,
					"memory!headerless_image",
					report::m_headerless_unlisted_image_violation,
					detail,
					state->m_executable_region_start,
					static_cast< unsigned long >( state->m_executable_region_end - state->m_executable_region_start )
				);
				state->m_anonymous_detections++;
			}
		}

		state->m_executable_region_start = 0;
		state->m_executable_region_end = 0;
		state->m_executable_region_pages = 0;
		state->m_executable_region_has_executable = false;
	}

	void track_executable_region( scan_state_t* state, const page_mapping_t& mapping ) {
		if ( !state )
			return;

		auto candidate = mapping.m_kernel &&
			!range_overlaps_loaded_module(
				state->m_modules,
				mapping.m_va,
				mapping.m_va + mapping.m_page_size
			) &&
			!is_device_like_mapping( mapping ) &&
			is_mapping_inside_physical_ranges( state, mapping );
		if ( !candidate ) {
			flush_executable_region( state );
			return;
		}

		auto mapping_end = mapping.m_va + mapping.m_page_size;
		if ( mapping_end <= mapping.m_va ) {
			flush_executable_region( state );
			return;
		}

		if ( state->m_executable_region_start && state->m_executable_region_end != mapping.m_va )
			flush_executable_region( state );

		if ( !state->m_executable_region_start )
			state->m_executable_region_start = mapping.m_va;

		state->m_executable_region_end = mapping_end;
		state->m_executable_region_pages += mapping.m_page_size / PAGE_SIZE;
		state->m_executable_region_has_executable =
			state->m_executable_region_has_executable || mapping.m_executable;
	}

	bool is_mapping_inside_physical_ranges( const scan_state_t* state, const page_mapping_t& mapping ) {
		if ( !state || !state->m_physical_ranges || !mapping.m_pfn || !mapping.m_page_size )
			return true;

		auto mapping_start = mapping.m_pfn << page_shift;
		auto mapping_end = mapping_start + mapping.m_page_size;
		if ( mapping_end <= mapping_start )
			return false;

		for ( auto range = state->m_physical_ranges; range->NumberOfBytes.QuadPart; range++ ) {
			auto range_start = static_cast< unsigned long long >( range->BaseAddress.QuadPart );
			auto range_size = static_cast< unsigned long long >( range->NumberOfBytes.QuadPart );
			auto range_end = range_start + range_size;

			if ( range_end <= range_start )
				continue;

			if ( mapping_start >= range_start && mapping_end <= range_end )
				return true;
		}

		return false;
	}

	void report_pfn_outside_ranges( scan_state_t* state, const page_mapping_t& mapping ) {
		if ( !state || !state->m_command )
			return;

		if ( !mapping.m_kernel || !mapping.m_writable || !mapping.m_executable )
			return;

		if ( is_device_like_mapping( mapping ) )
			return;

		auto physical_address = mapping.m_pfn << page_shift;
		if ( is_low_mmio_physical_address( physical_address ) )
			return;

		if ( is_mapping_inside_physical_ranges( state, mapping ) )
			return;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"va=0x%llx pfn=0x%llx pa=0x%llx size=0x%x cd=%u wt=%u",
			mapping.m_va,
			mapping.m_pfn,
			physical_address,
			mapping.m_page_size,
			static_cast< unsigned long >( mapping.m_cache_disabled ),
			static_cast< unsigned long >( mapping.m_write_through )
		);

		report::add_memory_detection(
			state->m_command,
			"memory!pfn",
			report::m_pfn_outside_physical_ranges_violation,
			detail,
			mapping.m_va,
			mapping.m_page_size
		);
		state->m_backing_detections++;
	}

	void report_physical_address_disagreement( scan_state_t* state, const page_mapping_t& mapping ) {
		if ( !state || !state->m_command || !mapping.m_kernel || !mapping.m_executable || !mapping.m_pfn )
			return;

		auto manual_pa = ( mapping.m_pfn << page_shift ) | ( mapping.m_va & ( mapping.m_page_size - 1 ) );
		auto api_pa = MmGetPhysicalAddress( reinterpret_cast< void* >( mapping.m_va ) );
		auto api_pa_value = static_cast< unsigned long long >( api_pa.QuadPart );

		if ( !api_pa_value || manual_pa == api_pa_value )
			return;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"va=0x%llx walk_pa=0x%llx api_pa=0x%llx pfn=0x%llx size=0x%x",
			mapping.m_va,
			manual_pa,
			api_pa_value,
			mapping.m_pfn,
			mapping.m_page_size
		);

		report::add_memory_detection(
			state->m_command,
			"memory!pa",
			report::m_physical_address_disagreement_violation,
			detail,
			mapping.m_va,
			mapping.m_page_size
		);
		state->m_backing_detections++;
	}

	void report_kernel_user_page( scan_state_t* state, const page_mapping_t& mapping ) {
		if ( !state || !state->m_command || !mapping.m_kernel || !mapping.m_user )
			return;

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"%s!page",
			owner_name( state->m_modules, mapping.m_va )
		);

		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"va=0x%llx pfn=0x%llx size=0x%x rw=%u nx=%u user=1",
			mapping.m_va,
			mapping.m_pfn,
			mapping.m_page_size,
			static_cast< unsigned long >( mapping.m_writable ),
			static_cast< unsigned long >( !mapping.m_executable )
		);

		report::add_memory_detection(
			state->m_command,
			target,
			report::m_kernel_user_page_violation,
			detail,
			mapping.m_va,
			mapping.m_page_size
		);
		state->m_permission_detections++;
	}

	void report_executable_anonymous_page( scan_state_t* state, const page_mapping_t& mapping ) {
		if ( !state || !state->m_command || !mapping.m_kernel || !mapping.m_executable )
			return;

		if ( !mapping.m_writable )
			return;

		if ( is_module_backed( state->m_modules, mapping.m_va ) )
			return;

		if ( is_device_like_mapping( mapping ) )
			return;

		auto physical_address = mapping.m_pfn << page_shift;
		if ( is_low_mmio_physical_address( physical_address ) )
			return;

		if ( !is_mapping_inside_physical_ranges( state, mapping ) )
			return;

		paging::pt_entries_t pt_entries;
		if ( !paging::hyperspace_entries( pt_entries, mapping.m_va ) )
			return;

		if ( !pt_entries.m_pte.hard.no_execute && pt_entries.m_pte.hard.pfn ) {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"va=0x%llx pfn=0x%llx pa=0x%llx size=0x%x rw=%u evidence=pe_header",
				mapping.m_va,
				mapping.m_pfn,
				physical_address,
				mapping.m_page_size,
				static_cast< unsigned long >( mapping.m_writable )
			);

			report::add_memory_detection(
				state->m_command,
				"memory!anonymous",
				report::m_executable_anonymous_page_violation,
				detail,
				mapping.m_va,
				mapping.m_page_size
			);
			state->m_anonymous_detections++;
		}
	}

	void report_pfn_database_spoofing( scan_state_t* state, const page_mapping_t& mapping ) {
		if ( !state || !state->m_command || !state->m_pfn_db_base )
			return;

		if ( !mapping.m_kernel || !mapping.m_executable || mapping.m_page_size != PAGE_SIZE || !mapping.m_pfn )
			return;

		if ( is_device_like_mapping( mapping ) )
			return;

		auto physical_address = mapping.m_pfn << page_shift;
		if ( is_low_mmio_physical_address( physical_address ) || !is_mapping_inside_physical_ranges( state, mapping ) )
			return;

		if ( is_module_backed( state->m_modules, mapping.m_va ) )
			return;

		if ( m_entry.m_image_base && m_entry.m_image_size &&
			mapping.m_va >= m_entry.m_image_base &&
			mapping.m_va < m_entry.m_image_base + m_entry.m_image_size )
			return;

		auto mmpfn_size = m_entry.m_offsets.m_mmpfn_size ? m_entry.m_offsets.m_mmpfn_size : 0x30ull;
		auto pte_addr_off = m_entry.m_offsets.m_mmpfn_pte_address ? m_entry.m_offsets.m_mmpfn_pte_address : 0x10ull;
		if ( mmpfn_size < 0x28ull || mmpfn_size > 0x80ull || pte_addr_off + sizeof( unsigned long long ) > mmpfn_size )
			return;

		auto mmpfn_va = state->m_pfn_db_base + ( mapping.m_pfn * mmpfn_size );
		if ( !memory::is_canonical_kernel_address( mmpfn_va ) )
			return;

		unsigned char mmpfn_bytes[ 0x80 ]{ };
		if ( !copy_virtual( mmpfn_va, mmpfn_bytes, static_cast< size_t >( mmpfn_size ) ) )
			return;

		unsigned long long pfn_pte_va = 0;
		memcpy( &pfn_pte_va, mmpfn_bytes + pte_addr_off, sizeof( pfn_pte_va ) );

		auto expected_pte_va = state->m_has_self_ref_pml4
			? canonicalize_va(
				( static_cast< unsigned long long >( state->m_self_ref_pml4_index ) << 39 ) |
				( ( mapping.m_va & 0x0000fffffffff000ull ) >> 9 ) )
			: 0ull;

		const char* reason = nullptr;
		if ( pfn_pte_va == 0 ) {
			reason = "mmpfn_pte_address_wiped";
		}
		else if ( state->m_has_self_ref_pml4 &&
			memory::is_canonical_kernel_address( pfn_pte_va ) &&
			( ( pfn_pte_va >> 39 ) & 0x1ffull ) == state->m_self_ref_pml4_index &&
			pfn_pte_va != expected_pte_va ) {
			reason = "mmpfn_pte_mismatch";
		}
		else if ( m_entry.m_offsets.m_mmpfn_u4 &&
			m_entry.m_offsets.m_mmpfn_u4 + sizeof( unsigned char ) <= mmpfn_size ) {
			const auto page_location = mmpfn_bytes[ m_entry.m_offsets.m_mmpfn_u4 ] & 0x07u;
			if ( page_location == 7u )
				reason = "mmpfn_on_bad_page_list";
		}

		if ( !reason )
			return;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"reason=%s va=0x%llx pfn=0x%llx pfn_pte=0x%llx expected_pte=0x%llx",
			reason,
			mapping.m_va,
			mapping.m_pfn,
			pfn_pte_va,
			expected_pte_va
		);

		report::add_memory_detection(
			state->m_command,
			"memory!mmpfn",
			report::m_pfn_database_violation,
			detail,
			mapping.m_va,
			mapping.m_page_size
		);
		state->m_pfn_db_detections++;
	}

	void inspect( scan_state_t* state, const page_mapping_t& mapping ) {
		track_executable_region( state, mapping );
		report_pfn_outside_ranges( state, mapping );
		report_physical_address_disagreement( state, mapping );
		report_kernel_user_page( state, mapping );
		report_pfn_database_spoofing( state, mapping );
	}
}

namespace memory_scan::aliases {
	pfn_record_t* find_or_add( scan_state_t* state, unsigned long long pfn ) {
		if ( !state || !state->m_records || !pfn )
			return nullptr;

		for ( auto index = 0ul; index < state->m_record_count; index++ ) {
			if ( state->m_records[ index ].m_pfn == pfn )
				return &state->m_records[ index ];
		}

		if ( state->m_record_count >= m_max_pfn_records )
			return nullptr;

		auto record = &state->m_records[ state->m_record_count++ ];
		memset( record, 0, sizeof( *record ) );
		record->m_pfn = pfn;
		return record;
	}

	void report_alias( scan_state_t* state, const char* type, unsigned long long left, unsigned long long right, unsigned long long pfn ) {
		if ( !state || !state->m_command || !left || !right )
			return;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"pfn=0x%llx first=0x%llx second=0x%llx",
			pfn,
			left,
			right
		);

		report::add_memory_detection(
			state->m_command,
			"memory!pfn",
			type,
			detail,
			right,
			PAGE_SIZE
		);
		state->m_alias_detections++;
	}

	void inspect( scan_state_t* state, const page_mapping_t& mapping ) {
		auto record = find_or_add( state, mapping.m_pfn );
		if ( !record )
			return;

		if ( mapping.m_kernel ) {
			record->m_kernel = true;
			if ( !record->m_first_kernel_va )
				record->m_first_kernel_va = mapping.m_va;
		}
		else {
			record->m_user = true;
			if ( !record->m_first_user_va )
				record->m_first_user_va = mapping.m_va;
		}

		if ( mapping.m_writable ) {
			record->m_rw = true;
			if ( !record->m_first_rw_va )
				record->m_first_rw_va = mapping.m_va;
		}

		if ( mapping.m_executable ) {
			record->m_rx = true;
			if ( !record->m_first_rx_va )
				record->m_first_rx_va = mapping.m_va;
		}

		if ( record->m_user && record->m_kernel && !record->m_reported_user_kernel &&
			record->m_first_user_va != record->m_first_kernel_va &&
			record->m_first_kernel_va != 0xfffff78000000000ull ) {
			record->m_reported_user_kernel = true;
			report_alias(
				state,
				report::m_pfn_user_kernel_alias_violation,
				record->m_first_user_va,
				record->m_first_kernel_va,
				record->m_pfn
			);
		}

		if ( record->m_rw && record->m_rx && !record->m_reported_rw_rx &&
			record->m_first_rw_va != record->m_first_rx_va ) {
			record->m_reported_rw_rx = true;
			report_alias(
				state,
				report::m_pfn_rw_rx_alias_violation,
				record->m_first_rw_va,
				record->m_first_rx_va,
				record->m_pfn
			);
		}
	}
}
