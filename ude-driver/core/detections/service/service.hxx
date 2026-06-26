#pragma once

namespace service_integrity {
	struct target_info_t {
		const system_module_t* m_module;
		const char* m_owner;
		char m_section[ 9 ];
		bool m_executable;
		bool m_bad_backing;
		bool m_user;
		bool m_nx;
		unsigned long long m_pfn;
		unsigned long long m_walk_pa;
		unsigned long long m_api_pa;
	};

	bool is_service_export_name( const char* name ) {
		if ( !name || !name[ 0 ] || !name[ 1 ] )
			return false;

		return
			( name[ 0 ] == 'N' && name[ 1 ] == 't' ) ||
			( name[ 0 ] == 'Z' && name[ 1 ] == 'w' );
	}

	void query_target_info( const system_modules_t* modules, unsigned long long address, target_info_t* info ) {
		if ( !info )
			return;

		memset( info, 0, sizeof( *info ) );
		if ( !modules || !address )
			return;

		info->m_module = module::disk::find_module_by_address( modules, address );
		if ( info->m_module ) {
			info->m_owner = reinterpret_cast< const char* >( info->m_module->m_full_path_name ) + info->m_module->m_offset_to_file_name;
			info->m_executable = module::disk::is_address_in_executable_section( info->m_module, address, info->m_section, sizeof( info->m_section ) );
		}

		paging::pt_entries_t entries{ };
		if ( !paging::hyperspace_entries( entries, address ) )
			return;

		if ( entries.m_pdpte.hard.page_size ) {
			info->m_pfn = entries.m_pdpte.hard.pfn;
			info->m_user = entries.m_pdpte.hard.user_supervisor;
			info->m_nx = entries.m_pdpte.hard.no_execute;
		}
		else if ( entries.m_pde.hard.page_size ) {
			info->m_pfn = entries.m_pde.hard.pfn;
			info->m_user = entries.m_pde.hard.user_supervisor;
			info->m_nx = entries.m_pde.hard.no_execute;
		}
		else {
			info->m_pfn = entries.m_pte.hard.pfn;
			info->m_user = entries.m_pte.hard.user_supervisor;
			info->m_nx = entries.m_pte.hard.no_execute;
		}

		std::uint32_t page_size = 0;
		paging::translate_linear( address, &info->m_walk_pa, &page_size );
		auto api_pa = MmGetPhysicalAddress( reinterpret_cast< void* >( address ) );
		info->m_api_pa = static_cast< unsigned long long >( api_pa.QuadPart );
		info->m_bad_backing = ( info->m_walk_pa && info->m_api_pa && info->m_walk_pa != info->m_api_pa ) || info->m_user || info->m_nx;
	}
}

namespace service_integrity::msr {
	constexpr auto m_lstar = 0xc0000082ul;
	constexpr auto m_cstar = 0xc0000083ul;
	constexpr auto m_sysenter_eip = 0x176ul;

	unsigned long report_msr_target( ioctl::command_t* command, const system_modules_t* modules, const char* name, unsigned long msr ) {
		auto address = __readmsr( msr );
		if ( !address )
			return 0;

		target_info_t info{ };
		query_target_info( modules, address, &info );
		if ( info.m_owner && info.m_executable && !info.m_bad_backing )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"msr=%s value=0x%llx owner=%s section=%s pfn=0x%llx walk_pa=0x%llx api_pa=0x%llx",
			name ? name : "msr",
			address,
			info.m_owner ? info.m_owner : "unknown",
			info.m_section[ 0 ] ? info.m_section : "unknown",
			info.m_pfn,
			info.m_walk_pa,
			info.m_api_pa
		);

		report::add_memory_detection(
			command,
			"service!msr",
			report::m_syscall_msr_target_violation,
			detail,
			address,
			sizeof( void* )
		);
		return 1;
	}

	unsigned long scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return 0;

		unsigned long detections = 0;
		detections += report_msr_target( command, modules, "lstar", m_lstar );
		detections += report_msr_target( command, modules, "cstar", m_cstar );
		detections += report_msr_target( command, modules, "sysenter_eip", m_sysenter_eip );
		return detections;
	}
}

namespace service_integrity::routines {
	unsigned long scan_nt_exports( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* nt_module, const unsigned char* disk_image, unsigned long disk_image_size ) {
		if ( !command || !modules || !nt_module || !disk_image || !disk_image_size )
			return 0;

		auto nt_headers = module::disk::validate_pe_image( disk_image, disk_image_size );
		if ( !nt_headers )
			return 0;

		auto directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
		if ( !directory.VirtualAddress || directory.Size < sizeof( IMAGE_EXPORT_DIRECTORY ) )
			return 0;

		auto export_directory = reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >( module::disk::rva_to_raw_pointer(
			disk_image,
			disk_image_size,
			directory.VirtualAddress,
			sizeof( IMAGE_EXPORT_DIRECTORY )
		) );

		if ( !export_directory || !export_directory->NumberOfFunctions )
			return 0;

		auto functions = reinterpret_cast< const unsigned long* >( module::disk::rva_to_raw_pointer(
			disk_image,
			disk_image_size,
			export_directory->AddressOfFunctions,
			sizeof( unsigned long ) * export_directory->NumberOfFunctions
		) );

		if ( !functions )
			return 0;

		unsigned long scanned = 0;
		unsigned long detections = 0;
		auto module_base = reinterpret_cast< unsigned long long >( nt_module->m_image_base );

		for ( auto ordinal = 0ul; ordinal < export_directory->NumberOfFunctions; ordinal++ ) {
			char export_name[ 96 ]{ };
			if ( !module::disk::copy_export_name( disk_image, disk_image_size, export_directory, ordinal, export_name, sizeof( export_name ) ) )
				continue;

			if ( !is_service_export_name( export_name ) )
				continue;

			auto rva = functions[ ordinal ];
			if ( rva >= directory.VirtualAddress && rva < directory.VirtualAddress + directory.Size )
				continue;

			auto section = module::disk::find_section_by_rva( disk_image, disk_image_size, rva );
			if ( !section || !( section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
				continue;

			scanned++;
			auto address = module_base + rva;
			target_info_t info{ };
			query_target_info( modules, address, &info );
			if ( info.m_owner && info.m_executable && !info.m_bad_backing && info.m_module == nt_module )
				continue;

			char target[ ioctl::m_detection_target_size ]{ };
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA( target, sizeof( target ), "ntoskrnl.exe!%s", export_name );
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"export=%s target=0x%llx owner=%s section=%s pfn=0x%llx flags=%s%s",
				export_name,
				address,
				info.m_owner ? info.m_owner : "unknown",
				info.m_section[ 0 ] ? info.m_section : "unknown",
				info.m_pfn,
				info.m_bad_backing ? "bad_backing " : "",
				info.m_module != nt_module ? "wrong_owner" : ""
			);

			report::add_memory_detection(
				command,
				target,
				report::m_service_routine_target_violation,
				detail,
				address,
				sizeof( void* )
			);
			detections++;
		}

		command->m_signature_candidates += scanned;
		return detections;
	}
}

namespace service_integrity {
	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		auto nt_module = module::disk::find_module_by_file_name( modules, "ntoskrnl.exe" );
		if ( !nt_module ) {
			command->m_error = STATUS_NOT_FOUND;
			return false;
		}

		void* disk_image = nullptr;
		unsigned long disk_image_size = 0;
		auto status = module::disk::read_module_image_from_disk( *nt_module, &disk_image, &disk_image_size );
		if ( status ) {
			command->m_error = status;
			return false;
		}

		auto msr_detections = msr::scan( command, modules );
		auto routine_detections = routines::scan_nt_exports(
			command,
			modules,
			nt_module,
			static_cast< const unsigned char* >( disk_image ),
			disk_image_size
		);

		utility::print(
			"service integrity: modules=%lu service_exports=%lu msr_detections=%lu routine_detections=%lu detections=%lu\n",
			modules->m_count,
			command->m_signature_candidates,
			msr_detections,
			routine_detections,
			command->m_total_detection_count
		);

		memory::free_pool( disk_image );
		command->m_modules_scanned = modules->m_count;
		command->m_sections_scanned = 1;
		command->m_signature_detections = msr_detections + routine_detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		return true;
	}
}
