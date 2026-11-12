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

	unsigned long scan_all_processors( ioctl::command_t* command, const system_modules_t* modules, unsigned long* total_idt_entries ) {
		if ( total_idt_entries )
			*total_idt_entries = 0;

		if ( !command || !modules )
			return 0;

		auto processor_count = KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS );
		if ( !processor_count )
			processor_count = 1;

		unsigned long detections = 0;
		for ( auto proc_index = 0ul; proc_index < processor_count; proc_index++ ) {
			PROCESSOR_NUMBER proc_num{ };
			if ( NT_SUCCESS( KeGetProcessorNumberFromIndex( proc_index, &proc_num ) ) ) {
				GROUP_AFFINITY affinity{ };
				GROUP_AFFINITY previous_affinity{ };
				affinity.Group = proc_num.Group;
				affinity.Mask = 1ull << proc_num.Number;
				KeSetSystemGroupAffinityThread( &affinity, &previous_affinity );

				command->m_sections_scanned = 0;
				detections += scan_idt( command, modules );
				if ( total_idt_entries )
					*total_idt_entries += command->m_sections_scanned;
				detections += scan_msrs( command, modules );

				KeRevertToUserGroupAffinityThread( &previous_affinity );
			}
			else if ( proc_index == 0 ) {
				command->m_sections_scanned = 0;
				detections += scan_idt( command, modules );
				if ( total_idt_entries )
					*total_idt_entries += command->m_sections_scanned;
				detections += scan_msrs( command, modules );
			}
		}

		return detections;
	}

	unsigned long scan_patchguard_and_debugger_state( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return 0;

		unsigned long detections = 0;
		size_t copied = 0;

		unsigned char kd_not_present = 1;
		unsigned char kd_pitch = 1;
		bool read_not_present = false;
		bool read_pitch = false;

		if ( m_entry.m_pdb.m_kd_debugger_not_present &&
			memory::is_canonical_kernel_address( m_entry.m_pdb.m_kd_debugger_not_present ) ) {
			read_not_present = memory::copy_kernel_memory(
				reinterpret_cast< void* >( m_entry.m_pdb.m_kd_debugger_not_present ),
				sizeof( kd_not_present ),
				&kd_not_present,
				&copied
			);
		}

		if ( m_entry.m_pdb.m_kd_pitch_debugger &&
			memory::is_canonical_kernel_address( m_entry.m_pdb.m_kd_pitch_debugger ) ) {
			read_pitch = memory::copy_kernel_memory(
				reinterpret_cast< void* >( m_entry.m_pdb.m_kd_pitch_debugger ),
				sizeof( kd_pitch ),
				&kd_pitch,
				&copied
			);
		}

		const auto shared_kd_enabled = SharedUserData->KdDebuggerEnabled;
		if ( read_not_present && read_pitch ) {
			const auto state_contradiction =
				( shared_kd_enabled && kd_not_present != 0 && kd_pitch != 0 ) ||
				( !shared_kd_enabled && kd_not_present == 0 && kd_pitch != 0 );

			if ( state_contradiction ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"shared_kd=%u kd_not_present=%u kd_pitch=%u reason=kd_patchguard_bypass_spoof",
					static_cast< unsigned long >( shared_kd_enabled ),
					static_cast< unsigned long >( kd_not_present ),
					static_cast< unsigned long >( kd_pitch )
				);
				report::add_memory_detection(
					command,
					"patchguard!kd_state",
					report::m_patchguard_context_violation,
					detail,
					m_entry.m_pdb.m_kd_debugger_not_present,
					sizeof( unsigned char )
				);
				detections++;
			}
		}

		if ( m_entry.m_pdb.m_ki_wait_never && m_entry.m_pdb.m_ki_wait_always ) {
			unsigned long long wait_never = 0;
			unsigned long long wait_always = 0;
			if ( memory::copy_kernel_memory( reinterpret_cast< void* >( m_entry.m_pdb.m_ki_wait_never ), sizeof( wait_never ), &wait_never, &copied ) &&
				memory::copy_kernel_memory( reinterpret_cast< void* >( m_entry.m_pdb.m_ki_wait_always ), sizeof( wait_always ), &wait_always, &copied ) ) {
				if ( wait_never == 0 || wait_always == 0 ) {
					char detail[ ioctl::m_detection_text_size ]{ };
					RtlStringCbPrintfA(
						detail,
						sizeof( detail ),
						"KiWaitNever=0x%llx KiWaitAlways=0x%llx reason=timer_obfuscation_keys_zeroed",
						wait_never,
						wait_always
					);
					report::add_memory_detection(
						command,
						"patchguard!timer_keys",
						report::m_patchguard_context_violation,
						detail,
						m_entry.m_pdb.m_ki_wait_never,
						sizeof( unsigned long long )
					);
					detections++;
				}
			}
		}

		auto nt_module = module::disk::find_module_by_file_name( modules, "ntoskrnl.exe" );
		if ( nt_module ) {
			UNICODE_STRING bugcheck_name = RTL_CONSTANT_STRING( L"KeBugCheckEx" );
			auto bugcheck_addr = reinterpret_cast< unsigned long long >( MmGetSystemRoutineAddress( &bugcheck_name ) );
			if ( bugcheck_addr && memory::is_canonical_kernel_address( bugcheck_addr ) ) {
				unsigned char prologue[ 16 ]{ };
				if ( memory::copy_kernel_memory( reinterpret_cast< void* >( bugcheck_addr ), sizeof( prologue ), prologue, &copied ) ) {
					const auto patched_ret_or_jmp =
						prologue[ 0 ] == 0xC3 ||
						prologue[ 0 ] == 0xE9 ||
						prologue[ 0 ] == 0xEB ||
						( prologue[ 0 ] == 0xFF && prologue[ 1 ] == 0x25 ) ||
						( prologue[ 0 ] == 0x48 && prologue[ 1 ] == 0x31 && prologue[ 2 ] == 0xC0 && prologue[ 3 ] == 0xC3 );

					if ( patched_ret_or_jmp ) {
						char detail[ ioctl::m_detection_text_size ]{ };
						RtlStringCbPrintfA(
							detail,
							sizeof( detail ),
							"KeBugCheckEx=0x%llx bytes=%02x_%02x_%02x_%02x reason=patchguard_bugcheck_hooked",
							bugcheck_addr,
							prologue[ 0 ],
							prologue[ 1 ],
							prologue[ 2 ],
							prologue[ 3 ]
						);
						report::add_memory_detection(
							command,
							"patchguard!KeBugCheckEx",
							report::m_patchguard_context_violation,
							detail,
							bugcheck_addr,
							sizeof( prologue )
						);
						detections++;
					}
				}
			}
		}

		return detections;
	}

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		unsigned long total_idt_entries = 0;
		auto cpu_detections = scan_all_processors( command, modules, &total_idt_entries );
		auto pg_detections = scan_patchguard_and_debugger_state( command, modules );
		command->m_sections_scanned = total_idt_entries;
		command->m_modules_scanned = modules->m_count;
		command->m_signature_detections = cpu_detections + pg_detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;

		utility::print(
			"cpu & patchguard integrity: idt_entries=%lu cpu_detections=%lu pg_detections=%lu detections=%lu\n",
			command->m_sections_scanned,
			cpu_detections,
			pg_detections,
			command->m_total_detection_count
		);
		return true;
	}
}
