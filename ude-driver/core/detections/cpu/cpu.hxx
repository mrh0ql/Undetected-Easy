#pragma once

namespace cpu_integrity {
#pragma pack( push, 1 )
	struct idtr_t {
		unsigned short m_limit;
		unsigned long long m_base;
	};

	struct idt_entry_t {
		unsigned short m_offset_low;
		unsigned short m_selector;
		unsigned short m_ist : 3;
		unsigned short m_reserved0 : 5;
		unsigned short m_type : 4;
		unsigned short m_zero : 1;
		unsigned short m_dpl : 2;
		unsigned short m_present : 1;
		unsigned short m_offset_middle;
		unsigned long m_offset_high;
		unsigned long m_reserved1;
	};
#pragma pack( pop )

	struct target_info_t {
		const system_module_t* m_module;
		const char* m_owner;
		char m_section[ 9 ];
		bool m_executable;
		bool m_bad_backing;
		unsigned long long m_pfn;
		unsigned long long m_walk_pa;
		unsigned long long m_api_pa;
	};

	unsigned long long idt_target( const idt_entry_t& entry ) {
		return
			static_cast< unsigned long long >( entry.m_offset_low ) |
			( static_cast< unsigned long long >( entry.m_offset_middle ) << 16 ) |
			( static_cast< unsigned long long >( entry.m_offset_high ) << 32 );
	}

	void query_target_info( const system_modules_t* modules, unsigned long long address, target_info_t* info ) {
		if ( !info )
			return;

		memset( info, 0, sizeof( *info ) );
		info->m_module = module::disk::find_module_by_address( modules, address );
		if ( info->m_module ) {
			info->m_owner = reinterpret_cast< const char* >( info->m_module->m_full_path_name ) + info->m_module->m_offset_to_file_name;
			info->m_executable = module::disk::is_address_in_executable_section( info->m_module, address, info->m_section, sizeof( info->m_section ) );
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

	unsigned long report_target( ioctl::command_t* command, const system_modules_t* modules, const char* target, const char* type, const char* name, unsigned long index, unsigned long long address ) {
		target_info_t info{ };
		query_target_info( modules, address, &info );
		if ( info.m_owner && info.m_executable && !info.m_bad_backing )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"%s=%lu address=0x%llx owner=%s section=%s pfn=0x%llx walk_pa=0x%llx api_pa=0x%llx",
			name ? name : "entry",
			index,
			address,
			info.m_owner ? info.m_owner : "unknown",
			info.m_section[ 0 ] ? info.m_section : "unknown",
			info.m_pfn,
			info.m_walk_pa,
			info.m_api_pa
		);

		report::add_memory_detection(
			command,
			target ? target : "cpu",
			type,
			detail,
			address,
			sizeof( void* )
		);
		return 1;
	}

	unsigned long scan_idt( ioctl::command_t* command, const system_modules_t* modules ) {
		idtr_t idtr{ };
		__sidt( &idtr );
		if ( !idtr.m_base || idtr.m_limit < sizeof( idt_entry_t ) )
			return 0;

		auto entries = reinterpret_cast< const idt_entry_t* >( idtr.m_base );
		auto count = ( idtr.m_limit + 1 ) / sizeof( idt_entry_t );
		if ( count > 256 )
			count = 256;

		unsigned long detections = 0;
		for ( auto index = 0ul; index < count; index++ ) {
			if ( !entries[ index ].m_present )
				continue;

			detections += report_target(
				command,
				modules,
				"cpu!idt",
				report::m_cpu_idt_target_violation,
				"vector",
				index,
				idt_target( entries[ index ] )
			);
		}

		command->m_sections_scanned = count;
		return detections;
	}

	unsigned long scan_msrs( ioctl::command_t* command, const system_modules_t* modules ) {
		constexpr unsigned long msrs[] = { 0xc0000082ul, 0xc0000083ul, 0x176ul };
		unsigned long detections = 0;
		for ( auto index = 0ul; index < ARRAYSIZE( msrs ); index++ ) {
			auto address = __readmsr( msrs[ index ] );
			if ( !address )
				continue;

			detections += report_target( command, modules, "cpu!msr", report::m_cpu_msr_target_violation, "msr", msrs[ index ], address );
		}

		return detections;
	}

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		auto idt_detections = scan_idt( command, modules );
		auto msr_detections = scan_msrs( command, modules );
		command->m_modules_scanned = modules->m_count;
		command->m_signature_detections = idt_detections + msr_detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;

		utility::print(
			"cpu integrity: idt_entries=%lu idt_detections=%lu msr_detections=%lu detections=%lu\n",
			command->m_sections_scanned,
			idt_detections,
			msr_detections,
			command->m_total_detection_count
		);
		return true;
	}
}
