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

namespace service_integrity::hal {
	unsigned long scan_table(
		ioctl::command_t* command,
		const system_modules_t* modules,
		unsigned long long table_address,
		const char* table_name,
		unsigned long pointer_count ) {
		if ( !command || !modules || !table_address || !memory::is_canonical_kernel_address( table_address ) )
			return 0;

		unsigned long detections = 0;
		for ( auto index = 1ul; index < pointer_count; index++ ) {
			auto slot_address = table_address + index * sizeof( unsigned long long );
			unsigned long long routine = 0;
			size_t copied = 0;
			if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( slot_address ), sizeof( routine ), &routine, &copied ) || !routine )
				continue;

			if ( !memory::is_canonical_kernel_address( routine ) )
				continue;

			command->m_signature_candidates++;

			target_info_t info{ };
			query_target_info( modules, routine, &info );

			auto valid_owner = info.m_module && info.m_owner && info.m_executable && !info.m_bad_backing &&
				( device_surface::is_system_module_path( info.m_module ) ||
					module::disk::is_whitelisted_owner( info.m_owner ) );
			if ( valid_owner )
				continue;

			char target[ ioctl::m_detection_target_size ]{ };
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA( target, sizeof( target ), "%s[%lu]", table_name ? table_name : "HalDispatchTable", index );
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"slot=%lu slot_va=0x%llx target=0x%llx owner=%s section=%s pfn=0x%llx",
				index,
				slot_address,
				routine,
				info.m_owner ? info.m_owner : "unknown",
				info.m_section[ 0 ] ? info.m_section : "unknown",
				info.m_pfn
			);

			report::add_memory_detection(
				command,
				target,
				report::m_hal_dispatch_target_violation,
				detail,
				routine,
				sizeof( void* )
			);
			detections++;
		}

		return detections;
	}

	unsigned long scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return 0;

		unsigned long detections = 0;
		auto hal_dispatch = m_entry.m_pdb.m_hal_dispatch_table;
		if ( !hal_dispatch && HalDispatchTable )
			hal_dispatch = reinterpret_cast< unsigned long long >( HalDispatchTable );

		detections += scan_table( command, modules, hal_dispatch, "HalDispatchTable", 22 );
		detections += scan_table( command, modules, m_entry.m_pdb.m_hal_private_dispatch_table, "HalPrivateDispatchTable", 48 );
		return detections;
	}
}

namespace service_integrity::ssdt {
	struct kservice_table_descriptor_t {
		const long* m_service_table_base;
		const void* m_service_counter_table_base;
		unsigned long long m_number_of_services;
		const unsigned char* m_param_table_base;
	};

	unsigned long scan_descriptor(
		ioctl::command_t* command,
		const system_modules_t* modules,
		const system_module_t* expected_module,
		unsigned long long descriptor_va,
		const char* table_label ) {
		if ( !command || !modules || !expected_module || !descriptor_va || !memory::is_canonical_kernel_address( descriptor_va ) )
			return 0;

		kservice_table_descriptor_t descriptor{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( descriptor_va ), sizeof( descriptor ), &descriptor, &copied ) )
			return 0;

		auto table_base = reinterpret_cast< unsigned long long >( descriptor.m_service_table_base );
		auto count = static_cast< unsigned long >( descriptor.m_number_of_services );
		if ( !table_base || !memory::is_canonical_kernel_address( table_base ) || count < 64 || count > 2048 )
			return 0;

		auto offsets = memory::allocate_pool< long* >( count * sizeof( long ), 1 );
		if ( !offsets )
			return 0;

		memset( offsets, 0, count * sizeof( long ) );
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( table_base ), count * sizeof( long ), offsets, &copied ) ) {
			memory::free_pool( offsets );
			return 0;
		}

		unsigned long detections = 0;
		for ( auto index = 0ul; index < count; index++ ) {
			auto delta = static_cast< long long >( offsets[ index ] ) >> 4;
			auto routine = static_cast< unsigned long long >( static_cast< long long >( table_base ) + delta );
			if ( !memory::is_canonical_kernel_address( routine ) )
				continue;

			command->m_signature_candidates++;
			target_info_t info{ };
			query_target_info( modules, routine, &info );

			bool inline_hooked = false;
			unsigned long long hook_target = 0;
			unsigned char prologue[ 16 ]{ };
			if ( memory::copy_kernel_memory( reinterpret_cast< void* >( routine ), sizeof( prologue ), prologue, &copied ) ) {
				signatures::relative_branch_signature_t rel_sig{ };
				if ( ( prologue[ 0 ] == 0xE9 || prologue[ 0 ] == 0xEB ) &&
					signatures::match_relative_branch_signature( prologue, sizeof( prologue ), 0, routine, &rel_sig ) &&
					detections::is_suspicious_external_target( modules, expected_module, rel_sig.m_target ) ) {
					inline_hooked = true;
					hook_target = rel_sig.m_target;
				}
				else if ( prologue[ 0 ] == 0x48 && prologue[ 1 ] == 0xB8 && prologue[ 10 ] == 0xFF && prologue[ 11 ] == 0xE0 ) {
					memcpy( &hook_target, prologue + 2, sizeof( hook_target ) );
					if ( detections::is_suspicious_external_target( modules, expected_module, hook_target ) )
						inline_hooked = true;
				}
			}

			if ( info.m_module == expected_module && info.m_executable && !info.m_bad_backing && !inline_hooked )
				continue;

			char target[ ioctl::m_detection_target_size ]{ };
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA( target, sizeof( target ), "%s[%lu]", table_label ? table_label : "SSDT", index );
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"syscall=%lu target=0x%llx owner=%s section=%s hooked=%u hook_dst=0x%llx",
				index,
				routine,
				info.m_owner ? info.m_owner : "unknown",
				info.m_section[ 0 ] ? info.m_section : "unknown",
				inline_hooked ? 1ul : 0ul,
				hook_target
			);

			report::add_memory_detection(
				command,
				target,
				report::m_ssdt_target_violation,
				detail,
				routine,
				sizeof( void* )
			);
			detections++;
		}

		memory::free_pool( offsets );
		return detections;
	}

	unsigned long scan( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* nt_module ) {
		if ( !command || !modules || !nt_module )
			return 0;

		return scan_descriptor( command, modules, nt_module, m_entry.m_pdb.m_ke_service_descriptor_table, "KeServiceDescriptorTable" );
	}
}

namespace service_integrity::etw {
	unsigned long scan( ioctl::command_t* command ) {
		auto reg_handle_va = m_entry.m_pdb.m_etw_threat_int_prov_reg_handle;
		if ( !command || !reg_handle_va || !memory::is_canonical_kernel_address( reg_handle_va ) )
			return 0;

		unsigned long long reg_entry = 0;
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( reg_handle_va ), sizeof( reg_entry ), &reg_entry, &copied ) )
			return 0;

		command->m_signature_candidates++;
		if ( !reg_entry || !memory::is_canonical_kernel_address( reg_entry ) ) {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"EtwThreatIntProvRegHandle=0x%llx value=0x%llx reason=etw_ti_handle_blinded",
				reg_handle_va,
				reg_entry
			);
			report::add_memory_detection(
				command,
				"etw!ThreatIntProvider",
				report::m_etw_ti_tampered_violation,
				detail,
				reg_handle_va,
				sizeof( reg_entry )
			);
			return 1;
		}

		unsigned long long guid_entry = 0;
		if ( memory::copy_kernel_memory( reinterpret_cast< void* >( reg_entry + 0x20ull ), sizeof( guid_entry ), &guid_entry, &copied ) &&
			( !guid_entry || !memory::is_canonical_kernel_address( guid_entry ) ) ) {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"reg_entry=0x%llx guid_entry=0x%llx reason=etw_ti_guid_entry_corrupted",
				reg_entry,
				guid_entry
			);
			report::add_memory_detection(
				command,
				"etw!ThreatIntGuidEntry",
				report::m_etw_ti_tampered_violation,
				detail,
				reg_entry + 0x20ull,
				sizeof( guid_entry )
			);
			return 1;
		}

		return 0;
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
		auto hal_detections = hal::scan( command, modules );
		auto ssdt_detections = ssdt::scan( command, modules, nt_module );
		auto etw_detections = etw::scan( command );
		auto callback_detections = callback::scan_kernel_callbacks( command, modules );
		auto routine_detections = routines::scan_nt_exports(
			command,
			modules,
			nt_module,
			static_cast< const unsigned char* >( disk_image ),
			disk_image_size
		);

		utility::print(
			"service integrity: modules=%lu candidates=%lu msr=%lu hal=%lu ssdt=%lu etw=%lu callbacks=%lu routines=%lu detections=%lu\n",
			modules->m_count,
			command->m_signature_candidates,
			msr_detections,
			hal_detections,
			ssdt_detections,
			etw_detections,
			callback_detections,
			routine_detections,
			command->m_total_detection_count
		);

		memory::free_pool( disk_image );
		command->m_modules_scanned = modules->m_count;
		command->m_sections_scanned = 6;
		command->m_signature_detections = msr_detections + hal_detections + ssdt_detections + etw_detections + callback_detections + routine_detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		return true;
	}
}
