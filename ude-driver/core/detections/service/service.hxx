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

	bool is_win32k_family_module( const char* owner_name ) {
		if ( !owner_name )
			return false;

		return ascii_equal_insensitive( owner_name, "win32k.sys" ) ||
			ascii_equal_insensitive( owner_name, "win32kfull.sys" ) ||
			ascii_equal_insensitive( owner_name, "win32kbase.sys" );
	}

	unsigned long scan_win32k_shadow_descriptor(
		ioctl::command_t* command,
		const system_modules_t* modules,
		unsigned long long shadow_array_va,
		unsigned long long ntos_ssdt_va ) {
		if ( !command || !modules || !shadow_array_va || !memory::is_canonical_kernel_address( shadow_array_va ) )
			return 0;

		kservice_table_descriptor_t shadow[ 2 ]{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( shadow_array_va ), sizeof( shadow ), shadow, &copied ) )
			return 0;

		unsigned long detections = 0;
		if ( ntos_ssdt_va && memory::is_canonical_kernel_address( ntos_ssdt_va ) ) {
			kservice_table_descriptor_t primary{ };
			if ( memory::copy_kernel_memory( reinterpret_cast< void* >( ntos_ssdt_va ), sizeof( primary ), &primary, &copied ) ) {
				if ( primary.m_service_table_base != shadow[ 0 ].m_service_table_base ||
					primary.m_number_of_services != shadow[ 0 ].m_number_of_services ) {
					char detail[ ioctl::m_detection_text_size ]{ };
					RtlStringCbPrintfA(
						detail,
						sizeof( detail ),
						"ssdt_base=0x%llx shadow_base=0x%llx reason=ssdt_shadow_desync",
						reinterpret_cast< unsigned long long >( primary.m_service_table_base ),
						reinterpret_cast< unsigned long long >( shadow[ 0 ].m_service_table_base )
					);
					report::add_memory_detection(
						command,
						"KeServiceDescriptorTableShadow[0]",
						report::m_ssdt_target_violation,
						detail,
						shadow_array_va,
						sizeof( shadow[ 0 ] )
					);
					detections++;
				}
			}
		}

		auto w32_base = reinterpret_cast< unsigned long long >( shadow[ 1 ].m_service_table_base );
		auto w32_count = static_cast< unsigned long >( shadow[ 1 ].m_number_of_services );
		if ( !w32_base || !memory::is_canonical_kernel_address( w32_base ) || w32_count < 64 || w32_count > 2048 )
			return detections;

		auto offsets = memory::allocate_pool< long* >( w32_count * sizeof( long ), 1 );
		if ( !offsets )
			return detections;

		memset( offsets, 0, w32_count * sizeof( long ) );
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( w32_base ), w32_count * sizeof( long ), offsets, &copied ) ) {
			memory::free_pool( offsets );
			return detections;
		}

		for ( auto index = 0ul; index < w32_count; index++ ) {
			auto delta = static_cast< long long >( offsets[ index ] ) >> 4;
			auto routine = static_cast< unsigned long long >( static_cast< long long >( w32_base ) + delta );
			if ( !memory::is_canonical_kernel_address( routine ) )
				continue;

			command->m_signature_candidates++;
			target_info_t info{ };
			query_target_info( modules, routine, &info );

			bool inline_hooked = false;
			unsigned long long hook_target = 0;
			unsigned char prologue[ 16 ]{ };
			if ( info.m_module && memory::copy_kernel_memory( reinterpret_cast< void* >( routine ), sizeof( prologue ), prologue, &copied ) ) {
				signatures::relative_branch_signature_t rel_sig{ };
				if ( ( prologue[ 0 ] == 0xE9 || prologue[ 0 ] == 0xEB ) &&
					signatures::match_relative_branch_signature( prologue, sizeof( prologue ), 0, routine, &rel_sig ) ) {
					auto dst_owner = memory::lookup_address_owner( modules, rel_sig.m_target );
					if ( !is_win32k_family_module( dst_owner ) && !ascii_equal_insensitive( dst_owner, "ntoskrnl.exe" ) ) {
						inline_hooked = true;
						hook_target = rel_sig.m_target;
					}
				}
				else if ( prologue[ 0 ] == 0x48 && prologue[ 1 ] == 0xB8 && prologue[ 10 ] == 0xFF && prologue[ 11 ] == 0xE0 ) {
					memcpy( &hook_target, prologue + 2, sizeof( hook_target ) );
					auto dst_owner = memory::lookup_address_owner( modules, hook_target );
					if ( !is_win32k_family_module( dst_owner ) && !ascii_equal_insensitive( dst_owner, "ntoskrnl.exe" ) )
						inline_hooked = true;
				}
			}

			if ( is_win32k_family_module( info.m_owner ) && info.m_executable && !info.m_bad_backing && !inline_hooked )
				continue;

			char target[ ioctl::m_detection_target_size ]{ };
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA( target, sizeof( target ), "W32pServiceTable[%lu]", index );
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"syscall=0x%lx target=0x%llx owner=%s section=%s hooked=%u hook_dst=0x%llx",
				0x1000ul + index,
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

		auto detections = scan_descriptor( command, modules, nt_module, m_entry.m_pdb.m_ke_service_descriptor_table, "KeServiceDescriptorTable" );
		detections += scan_win32k_shadow_descriptor(
			command,
			modules,
			m_entry.m_pdb.m_ke_service_descriptor_table_shadow,
			m_entry.m_pdb.m_ke_service_descriptor_table
		);
		return detections;
	}
}

namespace service_integrity::etw {
	unsigned long scan_wmi_logger_contexts( ioctl::command_t* command, const system_modules_t* modules ) {
		auto array_ptr_va = m_entry.m_pdb.m_wmip_logger_context;
		auto clock_offset = m_entry.m_offsets.m_wmi_logger_get_cpu_clock;
		if ( !command || !modules || !array_ptr_va || !memory::is_canonical_kernel_address( array_ptr_va ) ||
			!clock_offset || clock_offset > 0x400 )
			return 0;

		unsigned long long array_va = 0;
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( array_ptr_va ), sizeof( array_va ), &array_va, &copied ) ||
			!array_va || !memory::is_canonical_kernel_address( array_va ) )
			return 0;

		unsigned long long contexts[ 64 ]{ };
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( array_va ), sizeof( contexts ), contexts, &copied ) )
			return 0;

		unsigned long detections = 0;
		for ( auto logger_id = 0ul; logger_id < 64ul; logger_id++ ) {
			auto ctx_va = contexts[ logger_id ];
			if ( !ctx_va || !memory::is_canonical_kernel_address( ctx_va ) )
				continue;

			unsigned long long get_cpu_clock = 0;
			if ( !memory::copy_kernel_memory(
				reinterpret_cast< void* >( ctx_va + clock_offset ),
				sizeof( get_cpu_clock ),
				&get_cpu_clock,
				&copied ) )
				continue;

			command->m_signature_candidates++;
			if ( get_cpu_clock <= 16ull )
				continue;

			target_info_t info{ };
			if ( memory::is_canonical_kernel_address( get_cpu_clock ) )
				query_target_info( modules, get_cpu_clock, &info );

			const bool trusted_clock = info.m_owner && info.m_executable && !info.m_bad_backing &&
				( ascii_equal_insensitive( info.m_owner, "ntoskrnl.exe" ) ||
					ascii_equal_insensitive( info.m_owner, "hal.dll" ) );
			if ( trusted_clock )
				continue;

			char target[ ioctl::m_detection_target_size ]{ };
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA( target, sizeof( target ), "WmipLoggerContext[%lu]!GetCpuClock", logger_id );
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"logger=%lu ctx=0x%llx get_cpu_clock=0x%llx owner=%s reason=infinityhook_cpu_clock",
				logger_id,
				ctx_va,
				get_cpu_clock,
				info.m_owner ? info.m_owner : "unknown"
			);
			report::add_memory_detection(
				command,
				target,
				report::m_infinity_hook_etw_violation,
				detail,
				ctx_va + clock_offset,
				sizeof( get_cpu_clock )
			);
			detections++;
		}

		return detections;
	}

	unsigned long scan( ioctl::command_t* command, const system_modules_t* modules ) {
		unsigned long detections = scan_wmi_logger_contexts( command, modules );
		auto reg_handle_va = m_entry.m_pdb.m_etw_threat_int_prov_reg_handle;
		if ( !command || !reg_handle_va || !memory::is_canonical_kernel_address( reg_handle_va ) )
			return detections;

		unsigned long long reg_entry = 0;
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( reg_handle_va ), sizeof( reg_entry ), &reg_entry, &copied ) )
			return detections;

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
			return detections + 1;
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
			return detections + 1;
		}

		return detections;
	}
}

namespace service_integrity::data_pointers {
	unsigned long check_nt_data_pointer(
		ioctl::command_t* command,
		const system_modules_t* modules,
		const system_module_t* nt_module,
		unsigned long long slot_va,
		const char* symbol_name,
		bool allow_ci_dll ) {
		if ( !command || !modules || !nt_module || !slot_va || !memory::is_canonical_kernel_address( slot_va ) )
			return 0;

		auto nt_start = reinterpret_cast< unsigned long long >( nt_module->m_image_base );
		auto nt_end = nt_start + nt_module->m_image_size;
		if ( slot_va < nt_start || slot_va + sizeof( unsigned long long ) > nt_end )
			return 0;

		if ( module::disk::is_address_in_executable_section( nt_module, slot_va, nullptr, 0 ) )
			return 0;

		unsigned long long target = 0;
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( slot_va ), sizeof( target ), &target, &copied ) || !target )
			return 0;

		command->m_signature_candidates++;
		target_info_t info{ };
		if ( memory::is_canonical_kernel_address( target ) )
			query_target_info( modules, target, &info );

		bool allowed_owner = info.m_owner &&
			( ascii_equal_insensitive( info.m_owner, "ntoskrnl.exe" ) ||
				ascii_equal_insensitive( info.m_owner, "hal.dll" ) ||
				ascii_equal_insensitive( info.m_owner, "kdcom.dll" ) ||
				ascii_equal_insensitive( info.m_owner, "kd.dll" ) ||
				ascii_equal_insensitive( info.m_owner, "kdnet.dll" ) ||
				( allow_ci_dll && ascii_equal_insensitive( info.m_owner, "CI.dll" ) ) );

		if ( allowed_owner && info.m_executable && !info.m_bad_backing )
			return 0;

		char target_name[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA( target_name, sizeof( target_name ), "ntoskrnl!%s", symbol_name ? symbol_name : "data_ptr" );
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"slot=0x%llx target=0x%llx owner=%s section=%s bad_pfn=%u",
			slot_va,
			target,
			info.m_owner ? info.m_owner : "unknown",
			info.m_section[ 0 ] ? info.m_section : "unknown",
			info.m_bad_backing ? 1ul : 0ul
		);
		report::add_memory_detection(
			command,
			target_name,
			report::m_kernel_data_pointer_violation,
			detail,
			slot_va,
			sizeof( target )
		);
		return 1;
	}

	unsigned long scan( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* nt_module ) {
		if ( !command || !modules || !nt_module )
			return 0;

		unsigned long detections = 0;
		detections += check_nt_data_pointer(
			command,
			modules,
			nt_module,
			m_entry.m_pdb.m_kd_enumerate_debugging_devices,
			"KdEnumerateDebuggingDevices",
			false
		);
		detections += check_nt_data_pointer(
			command,
			modules,
			nt_module,
			m_entry.m_pdb.m_se_validate_image_header,
			"SeValidateImageHeader",
			true
		);
		detections += check_nt_data_pointer(
			command,
			modules,
			nt_module,
			m_entry.m_pdb.m_se_validate_image_data,
			"SeValidateImageData",
			true
		);
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
		auto hal_detections = hal::scan( command, modules );
		auto ssdt_detections = ssdt::scan( command, modules, nt_module );
		auto etw_detections = etw::scan( command, modules );
		auto data_ptr_detections = data_pointers::scan( command, modules, nt_module );
		auto callback_detections = callback::scan_kernel_callbacks( command, modules );
		auto routine_detections = routines::scan_nt_exports(
			command,
			modules,
			nt_module,
			static_cast< const unsigned char* >( disk_image ),
			disk_image_size
		);

		utility::print(
			"service integrity: modules=%lu candidates=%lu msr=%lu hal=%lu ssdt=%lu etw=%lu data_ptrs=%lu callbacks=%lu routines=%lu detections=%lu\n",
			modules->m_count,
			command->m_signature_candidates,
			msr_detections,
			hal_detections,
			ssdt_detections,
			etw_detections,
			data_ptr_detections,
			callback_detections,
			routine_detections,
			command->m_total_detection_count
		);

		memory::free_pool( disk_image );
		command->m_modules_scanned = modules->m_count;
		command->m_sections_scanned = 7;
		command->m_signature_detections = msr_detections + hal_detections + ssdt_detections + etw_detections + data_ptr_detections + callback_detections + routine_detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		return true;
	}
}
