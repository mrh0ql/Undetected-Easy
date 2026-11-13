#pragma once

namespace report {
	constexpr auto m_text_chunk_size = 0x1000ul;

	struct text_scan_stats_t {
		unsigned long m_dirty_chunks;
		unsigned long m_raw_ranges;
		unsigned long m_ignored_ranges;
		unsigned long m_generic_detections;
		unsigned long m_pph_candidates;
		unsigned long m_pph_detections;
		unsigned long m_mov_candidates;
		unsigned long m_mov_detections;
		unsigned long m_push_candidates;
		unsigned long m_push_detections;
		unsigned long m_rip_indirect_candidates;
		unsigned long m_rip_indirect_detections;
		unsigned long m_relative_branch_candidates;
		unsigned long m_relative_branch_detections;
		unsigned long m_rip_register_candidates;
		unsigned long m_rip_register_detections;
	};

	struct diff_summary_t {
		unsigned long m_first_offset;
		unsigned long m_nonzero_live_bytes;
		unsigned long m_nonzero_live_pages;
		unsigned long m_zero_live_bytes;
		unsigned long m_zero_live_pages;
		unsigned char m_disk_byte;
		unsigned char m_live_byte;
	};

	constexpr const char* m_absolute_code_redirect_violation = "absolute redirect in code section";
	constexpr const char* m_code_section_modified_violation = "code section modified";
	constexpr const char* m_export_table_modified_violation = "export address table modified";
	constexpr const char* m_import_table_modified_violation = "import address table modified";
	constexpr const char* m_indirect_call_redirect_violation = "indirect call redirect in code section";
	constexpr const char* m_indirect_jump_redirect_violation = "indirect jump redirect in code section";
	constexpr const char* m_push_ret_redirect_violation = "push ret redirect in code section";
	constexpr const char* m_suspicious_code_page_pfn_violation = "trusted code page backed by suspicious pfn";
	constexpr const char* m_suspicious_code_page_flags_violation = "trusted code page has suspicious pte flags";
	constexpr const char* m_image_page_private_cow_violation = "image page replaced by private COW page";
	constexpr const char* m_stack_frame_outside_kernel_violation = "kernel stack frame outside ntoskrnl";
	constexpr const char* m_execution_unknown_va_violation = "execution from unknown kernel va";
	constexpr const char* m_execution_non_code_section_violation = "execution from non-code section";
	constexpr const char* m_execution_bad_pfn_violation = "execution backed by suspicious pfn";
	constexpr const char* m_return_outside_code_violation = "return address outside executable section";
	constexpr const char* m_return_bad_pfn_violation = "return address backed by suspicious pfn";
	constexpr const char* m_stack_owner_chain_violation = "suspicious stack owner chain";
	constexpr const char* m_stack_pivot_violation = "stack pointer outside kernel stack bounds";
	constexpr const char* m_thread_start_violation = "suspicious thread start address";
	constexpr const char* m_kernel_user_page_violation = "kernel page mapped user accessible";
	constexpr const char* m_pfn_outside_physical_ranges_violation = "page pfn outside physical memory ranges";
	constexpr const char* m_physical_address_disagreement_violation = "page walk disagrees with physical address";
	constexpr const char* m_pfn_user_kernel_alias_violation = "same pfn mapped user and kernel";
	constexpr const char* m_pfn_rw_rx_alias_violation = "same pfn mapped writable and executable";
	constexpr const char* m_writable_executable_page_violation = "writable executable page outside module";
	constexpr const char* m_executable_anonymous_page_violation = "executable anonymous kernel page";
	constexpr const char* m_executable_unlisted_image_violation = "executable PE image outside loaded module list";
	constexpr const char* m_headerless_unlisted_image_violation = "headerless executable image outside loaded module list";
	constexpr const char* m_page_table_consistency_violation = "page table self consistency violation";
	constexpr const char* m_suspicious_pml4_slot_violation = "suspicious present pml4 slot";
	constexpr const char* m_repeated_cave_execution_violation = "repeated execution from small code region";
	constexpr const char* m_writable_code_section_violation = "writable executable code section";
	constexpr const char* m_executable_non_code_page_violation = "executable page in non-executable image section";
	constexpr const char* m_user_accessible_image_page_violation = "kernel image page is user accessible";
	constexpr const char* m_non_executable_code_page_violation = "executable image section mapped non-executable";
	constexpr const char* m_driver_object_mismatch_violation = "driver object does not match loaded module";
	constexpr const char* m_loaded_module_list_entry_violation = "suspicious loaded module list entry";
	constexpr const char* m_device_object_chain_violation = "suspicious device object chain";
	constexpr const char* m_ioctl_dispatch_surface_violation = "suspicious broad ioctl dispatch surface";
	constexpr const char* m_dispatch_outside_owner_violation = "dispatch target outside owning module code";
	constexpr const char* m_dispatch_unknown_target_violation = "dispatch target points to unknown memory";
	constexpr const char* m_dispatch_bad_pfn_violation = "dispatch target backed by suspicious pfn";
	constexpr const char* m_dispatch_writable_executable_violation = "dispatch target is writable executable";
	constexpr const char* m_syscall_msr_target_violation = "syscall msr target outside kernel code";
	constexpr const char* m_service_routine_target_violation = "service routine target outside kernel code";
	constexpr const char* m_cpu_idt_target_violation = "idt handler outside trusted code";
	constexpr const char* m_cpu_msr_target_violation = "processor msr target outside trusted code";
	constexpr const char* m_suspicious_driver_object_violation = "suspicious driver object without loaded module";
	constexpr const char* m_hidden_driver_device_violation = "device owned by hidden or unloaded driver";
	constexpr const char* m_world_writable_section_violation = "world-writable named section";
	constexpr const char* m_dpc_target_violation = "dpc target outside trusted code";
	constexpr const char* m_dpc_flags_violation = "suspicious dpc object flags";
	constexpr const char* m_executable_pool_violation = "executable nonpaged pool allocation";
	constexpr const char* m_pool_pe_header_violation = "pool allocation contains pe header";
	constexpr const char* m_pool_code_pattern_violation = "pool allocation contains code pattern";
	constexpr const char* m_process_kernel_page_violation = "kernel page mapped into process";
	constexpr const char* m_process_physical_window_violation = "user physical memory window in process";
	constexpr const char* m_cid_process_missing_violation = "cid table process missing from system query";
	constexpr const char* m_thread_hidden_violation = "thread hidden from system query";
	constexpr const char* m_orphan_process_address_space_violation = "orphan process address space";
	constexpr const char* m_vulnerable_driver_blocklist_violation = "vulnerable driver on microsoft blocklist";
	constexpr const char* m_piddb_cache_entry_violation = "suspicious piddbcachetable driver entry";
	constexpr const char* m_mm_unloaded_driver_violation = "suspicious mmunloadeddrivers entry";
	constexpr const char* m_hal_dispatch_target_violation = "hal dispatch table target outside trusted code";
	constexpr const char* m_patchguard_context_violation = "patchguard or kernel debug state tampered";
	constexpr const char* m_timer_dpc_target_violation = "kernel timer dpc target outside trusted code";
	constexpr const char* m_kernel_callback_target_violation = "kernel notify or object callback outside trusted code";
	constexpr const char* m_ci_hash_bucket_violation = "suspicious ci.dll kernelhashbucketlist entry";
	constexpr const char* m_ssdt_target_violation = "ssdt service target outside kernel code or hooked";
	constexpr const char* m_etw_ti_tampered_violation = "etw threat intelligence provider tampered";
	constexpr const char* m_hypervisor_timing_violation = "stealth hypervisor vm-exit timing or tsc discrepancy";
	constexpr const char* m_cpu_security_cr_violation = "processor security control register bit disabled";
	constexpr const char* m_debug_register_violation = "active kernel hardware debug breakpoint";
	constexpr const char* m_pfn_database_violation = "executable page pfn database metadata spoofed";
	constexpr const char* m_physical_memory_section_violation = "suspicious physicalmemory section dacl or kuser mapping";
	constexpr const char* m_thread_anomaly_violation = "kernel thread spoofed start address or debug state";
	constexpr const char* m_filter_callback_violation = "filesystem or ndis filter handler outside trusted code";
	constexpr const char* m_dse_ci_options_violation = "code integrity g_cioptions dse state tampered";
	constexpr const char* m_nmi_callback_violation = "registered nmi callback routine outside trusted code";
	constexpr const char* m_bugcheck_callback_violation = "bugcheck callback routine outside trusted code";
	constexpr const char* m_infinity_hook_etw_violation = "etw wmi logger getcpuclock syscall hook tampered";
	constexpr const char* m_kernel_data_pointer_violation = "kernel .data function pointer redirected";
	constexpr const char* m_object_type_hook_violation = "object type initializer procedure hooked";
	constexpr const char* m_hwid_spoofer_hook_violation = "storage or network hwid dispatch routine hooked";
	constexpr const char* m_tss_ist_stack_violation = "processor ktss64 rsp0 or ist stack pointer tampered";
	constexpr bool m_report_generic_code_changes = false;

	const char* violation_name_for_branch_signature( const char* signature_type ) {
		if ( ascii_equal_insensitive( signature_type, "mov_reg_imm64_jmp_reg" ) )
			return m_indirect_jump_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "mov_reg_imm64_call_reg" ) )
			return m_indirect_call_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "mov_reg_imm64_jmp_mem_reg" ) )
			return m_indirect_jump_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "mov_reg_imm64_call_mem_reg" ) )
			return m_indirect_call_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "push_imm32_ret" ) ||
			ascii_equal_insensitive( signature_type, "push_imm64_split_ret" ) ||
			ascii_equal_insensitive( signature_type, "mov_reg_imm64_push_reg_ret" ) ||
			ascii_equal_insensitive( signature_type, "mov_reg_imm64_write_rsp_ret" ) ||
			ascii_equal_insensitive( signature_type, "mov_reg_imm64_xchg_rsp_ret" ) ||
			ascii_equal_insensitive( signature_type, "sub_rsp_mov_qword_rsp_imm32_ret" ) ||
			ascii_equal_insensitive( signature_type, "sub_rsp_mov_reg_imm64_write_rsp_ret" ) )
			return m_push_ret_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "jmp_rip_indirect" ) )
			return m_indirect_jump_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "call_rip_indirect" ) )
			return m_indirect_call_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "jmp_rel32" ) ||
			ascii_equal_insensitive( signature_type, "jmp_rel8" ) )
			return m_indirect_jump_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "call_rel32" ) )
			return m_indirect_call_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "lea_rip_jmp_reg" ) ||
			ascii_equal_insensitive( signature_type, "mov_rip_jmp_reg" ) )
			return m_indirect_jump_redirect_violation;

		if ( ascii_equal_insensitive( signature_type, "lea_rip_call_reg" ) ||
			ascii_equal_insensitive( signature_type, "mov_rip_call_reg" ) )
			return m_indirect_call_redirect_violation;

		return signature_type;
	}

	diff_summary_t summarize_differences( const unsigned char* disk_bytes, const unsigned char* live_bytes, unsigned long size ) {
		diff_summary_t summary{ };
		summary.m_first_offset = size;

		unsigned long last_nonzero_live_page = MAXULONG;
		unsigned long last_zero_live_page = MAXULONG;

		for ( auto offset = 0ul; offset < size; offset++ ) {
			if ( disk_bytes[ offset ] == live_bytes[ offset ] )
				continue;

			auto page = offset >> PAGE_SHIFT;

			if ( live_bytes[ offset ] == 0 ) {
				if ( page != last_zero_live_page ) {
					summary.m_zero_live_pages++;
					last_zero_live_page = page;
				}

				summary.m_zero_live_bytes++;
				continue;
			}

			if ( summary.m_first_offset == size ) {
				summary.m_first_offset = offset;
				summary.m_disk_byte = disk_bytes[ offset ];
				summary.m_live_byte = live_bytes[ offset ];
			}

			if ( page != last_nonzero_live_page ) {
				summary.m_nonzero_live_pages++;
				last_nonzero_live_page = page;
			}

			summary.m_nonzero_live_bytes++;
		}

		return summary;
	}

	void add_writable_text_detection( ioctl::command_t* command, const char* module_name, unsigned long long address, const pte& pte ) {
		if ( !command )
			return;

		for ( auto index = 0ul; index < command->m_detection_count; index++ ) {
			auto detection = &command->m_detections[ index ];
			if ( detection->m_address != address )
				continue;

			if ( !ascii_equal_insensitive( detection->m_type, m_writable_code_section_violation ) )
				continue;

			return;
		}

		char target[ ioctl::m_detection_target_size ]{ };
		char method[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"%s!.text",
			module_name
		);

		RtlStringCbPrintfA(
			method,
			sizeof( method ),
			"pte writable pte=0x%llx pfn=0x%llx nx=%u user=%u",
			pte.value,
			pte.hard.pfn,
			static_cast< unsigned long >( pte.hard.no_execute ),
			static_cast< unsigned long >( pte.hard.user_supervisor )
		);

		ioctl::add_detection(
			command,
			target,
			m_writable_code_section_violation,
			method,
			address,
			PAGE_SIZE,
			STATUS_SUCCESS
		);
	}

	void add_section_permission_detection(
		ioctl::command_t* command,
		const char* module_name,
		const char* section_name,
		const char* violation,
		unsigned long long address,
		unsigned long long leaf_value,
		unsigned long mapping_size,
		bool writable,
		bool executable,
		bool user_accessible ) {
		if ( !command || !module_name || !violation )
			return;

		for ( auto index = 0ul; index < command->m_detection_count; index++ ) {
			auto detection = &command->m_detections[ index ];
			if ( detection->m_address == address &&
				ascii_equal_insensitive( detection->m_type, violation ) )
				return;
		}

		char target[ ioctl::m_detection_target_size ]{ };
		char method[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"%s!%s",
			module_name,
			section_name && section_name[ 0 ] ? section_name : "section"
		);
		RtlStringCbPrintfA(
			method,
			sizeof( method ),
			"section permission mismatch leaf=0x%llx page=0x%lx rw=%u nx=%u user=%u",
			leaf_value,
			mapping_size,
			static_cast< unsigned long >( writable ),
			static_cast< unsigned long >( !executable ),
			static_cast< unsigned long >( user_accessible )
		);

		ioctl::add_detection(
			command,
			target,
			violation,
			method,
			address,
			mapping_size ? mapping_size : PAGE_SIZE,
			STATUS_SUCCESS
		);
	}

	void add_text_detection( ioctl::command_t* command, const char* module_name, const char* section_name, const char* type, unsigned long rva, unsigned long long address, unsigned long size, const char* extra ) {
		char target[ ioctl::m_detection_target_size ]{ };
		char method[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"%s!%s",
			module_name,
			section_name ? section_name : "code"
		);

		if ( extra ) {
			RtlStringCbPrintfA(
				method,
				sizeof( method ),
				"raw diff rva=0x%x %s",
				rva,
				extra
			);
		}
		else {
			RtlStringCbPrintfA(
				method,
				sizeof( method ),
				"raw diff rva=0x%x",
				rva
			);
		}

		if ( command ) {
			for ( auto index = 0ul; index < command->m_detection_count; index++ ) {
				auto detection = &command->m_detections[ index ];
				if ( detection->m_address != address )
					continue;

				if ( !ascii_equal_insensitive( detection->m_type, type ) )
					continue;

				return;
			}
		}

		ioctl::add_detection(
			command,
			target,
			type,
			method,
			address,
			size,
			STATUS_SUCCESS
		);
	}

	void add_import_detection( ioctl::command_t* command, const char* module_name, const char* import_module, unsigned long ordinal, unsigned long long slot_address, unsigned long long target, const char* owner ) {
		char target_text[ ioctl::m_detection_target_size ]{ };
		char method[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target_text,
			sizeof( target_text ),
			"%s!iat[%s]",
			module_name,
			import_module ? import_module : "unknown"
		);

		RtlStringCbPrintfA(
			method,
			sizeof( method ),
			"iat slot ordinal=%lu target=0x%llx owner=%s",
			ordinal,
			target,
			owner ? owner : "unknown"
		);

		ioctl::add_detection(
			command,
			target_text,
			m_import_table_modified_violation,
			method,
			slot_address,
			sizeof( target ),
			STATUS_SUCCESS
		);
	}

	void add_pfn_backing_detection( ioctl::command_t* command, const char* module_name, const char* section_name, unsigned long long page, const pte& pte, const char* reason ) {
		if ( !command )
			return;

		for ( auto index = 0ul; index < command->m_detection_count; index++ ) {
			auto detection = &command->m_detections[ index ];
			if ( detection->m_address != page )
				continue;

			if ( !ascii_equal_insensitive( detection->m_type, m_suspicious_code_page_pfn_violation ) &&
				!ascii_equal_insensitive( detection->m_type, m_suspicious_code_page_flags_violation ) )
				continue;

			return;
		}

		char target[ ioctl::m_detection_target_size ]{ };
		char method[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"%s!%s",
			module_name,
			section_name ? section_name : ".text"
		);

		RtlStringCbPrintfA(
			method,
			sizeof( method ),
			"%s pte=0x%llx pfn=0x%llx rw=%u nx=%u user=%u global=%u dirty=%u",
			reason ? reason : "suspicious pfn",
			pte.value,
			pte.hard.pfn,
			static_cast< unsigned long >( pte.hard.read_write ),
			static_cast< unsigned long >( pte.hard.no_execute ),
			static_cast< unsigned long >( pte.hard.user_supervisor ),
			static_cast< unsigned long >( pte.hard.global ),
			static_cast< unsigned long >( pte.hard.dirty )
		);

		ioctl::add_detection(
			command,
			target,
			reason && ascii_equal_insensitive( reason, "suspicious pte flags" ) ? m_suspicious_code_page_flags_violation : m_suspicious_code_page_pfn_violation,
			method,
			page,
			PAGE_SIZE,
			STATUS_SUCCESS
		);
	}

	void add_stack_frame_detection( ioctl::command_t* command, const char* module_name, unsigned long index, unsigned long long frame, const char* owner ) {
		char target[ ioctl::m_detection_target_size ]{ };
		char method[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"%s!stack",
			module_name
		);

		RtlStringCbPrintfA(
			method,
			sizeof( method ),
			"frame=%lu address=0x%llx owner=%s",
			index,
			frame,
			owner ? owner : "unknown"
		);

		ioctl::add_detection(
			command,
			target,
			m_stack_frame_outside_kernel_violation,
			method,
			frame,
			sizeof( void* ),
			STATUS_SUCCESS
		);
	}

	void add_execution_detection( ioctl::command_t* command, const char* target_name, const char* type, const char* detail, unsigned long long address, unsigned long size ) {
		if ( !command || !type )
			return;

		for ( auto index = 0ul; index < command->m_detection_count; index++ ) {
			auto detection = &command->m_detections[ index ];
			if ( detection->m_address != address )
				continue;

			if ( !ascii_equal_insensitive( detection->m_type, type ) )
				continue;

			return;
		}

		char target[ ioctl::m_detection_target_size ]{ };
		char method[ ioctl::m_detection_text_size ]{ };

		RtlStringCbPrintfA(
			target,
			sizeof( target ),
			"%s",
			target_name ? target_name : "execution"
		);

		RtlStringCbPrintfA(
			method,
			sizeof( method ),
			"%s",
			detail ? detail : "execution sample"
		);

		ioctl::add_detection(
			command,
			target,
			type,
			method,
			address,
			size,
			STATUS_SUCCESS
		);
	}

	void add_memory_detection( ioctl::command_t* command, const char* target_name, const char* type, const char* detail, unsigned long long address, unsigned long size ) {
		add_execution_detection( command, target_name, type, detail, address, size );
	}

	void add_export_detection( ioctl::command_t* command, const char* module_name, const char* export_name, unsigned long ordinal, unsigned long disk_rva, unsigned long live_rva, unsigned long long slot_address ) {
		char target[ ioctl::m_detection_target_size ]{ };
		char method[ ioctl::m_detection_text_size ]{ };

		if ( export_name && export_name[ 0 ] ) {
			RtlStringCbPrintfA(
				target,
				sizeof( target ),
				"%s!%s",
				module_name,
				export_name
			);
		}
		else {
			RtlStringCbPrintfA(
				target,
				sizeof( target ),
				"%s!#%lu",
				module_name,
				ordinal
			);
		}

		RtlStringCbPrintfA(
			method,
			sizeof( method ),
			"eat slot changed disk=0x%x live=0x%x",
			disk_rva,
			live_rva
		);

		ioctl::add_detection(
			command,
			target,
			m_export_table_modified_violation,
			method,
			slot_address,
			sizeof( unsigned long ),
			STATUS_SUCCESS
		);
	}

	unsigned long report_export_differences( ioctl::command_t* command, const unsigned char* disk_image, unsigned long disk_image_size, const system_module_t* module, const char* module_name ) {
		if ( !command || !disk_image || !module || !module_name )
			return 0;

		auto nt_headers = memory::validate_pe_image( disk_image, disk_image_size );
		if ( !nt_headers )
			return 0;

		auto directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
		if ( !directory.VirtualAddress || !directory.Size )
			return 0;

		auto export_directory = reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >( memory::rva_to_raw_pointer(
			disk_image,
			disk_image_size,
			directory.VirtualAddress,
			sizeof( IMAGE_EXPORT_DIRECTORY )
		) );

		if ( !export_directory || !export_directory->AddressOfFunctions || !export_directory->NumberOfFunctions )
			return 0;

		auto disk_functions = reinterpret_cast< const unsigned long* >( memory::rva_to_raw_pointer(
			disk_image,
			disk_image_size,
			export_directory->AddressOfFunctions,
			sizeof( unsigned long ) * export_directory->NumberOfFunctions
		) );

		if ( !disk_functions )
			return 0;

		auto live_functions_size = sizeof( unsigned long ) * export_directory->NumberOfFunctions;
		auto live_functions = memory::allocate_pool< unsigned long* >( live_functions_size, 1 );
		if ( !live_functions )
			return 0;

		memset( live_functions, 0, live_functions_size );

		auto live_functions_address = reinterpret_cast< unsigned char* >( module->m_image_base ) + export_directory->AddressOfFunctions;
		size_t bytes_copied = 0;
		auto copied_functions = memory::copy_kernel_memory( live_functions_address, live_functions_size, live_functions, &bytes_copied );
		if ( !copied_functions ) {
			memory::free_pool( live_functions );
			return 0;
		}

		unsigned long detections = 0;
		for ( auto ordinal = 0ul; ordinal < export_directory->NumberOfFunctions; ordinal++ ) {
			if ( disk_functions[ ordinal ] == live_functions[ ordinal ] )
				continue;

			char export_name[ 64 ]{ };
			memory::copy_export_name( disk_image, disk_image_size, export_directory, ordinal, export_name, sizeof( export_name ) );

			add_export_detection(
				command,
				module_name,
				export_name,
				ordinal,
				disk_functions[ ordinal ],
				live_functions[ ordinal ],
				reinterpret_cast< unsigned long long >( live_functions_address ) + ordinal * sizeof( unsigned long )
			);

			detections++;
		}

		memory::free_pool( live_functions );
		return detections;
	}

	unsigned long report_import_differences( ioctl::command_t* command, const system_modules_t* modules, const unsigned char* disk_image, unsigned long disk_image_size, const system_module_t* module, const char* module_name ) {
		if ( !command || !modules || !disk_image || !module || !module_name )
			return 0;

		auto nt_headers = memory::validate_pe_image( disk_image, disk_image_size );
		if ( !nt_headers )
			return 0;

		auto directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
		if ( !directory.VirtualAddress || directory.Size < sizeof( IMAGE_IMPORT_DESCRIPTOR ) )
			return 0;

		auto imports = reinterpret_cast< const IMAGE_IMPORT_DESCRIPTOR* >( memory::rva_to_raw_pointer(
			disk_image,
			disk_image_size,
			directory.VirtualAddress,
			sizeof( IMAGE_IMPORT_DESCRIPTOR )
		) );

		if ( !imports )
			return 0;

		unsigned long detections = 0;
		auto descriptor_count = directory.Size / sizeof( IMAGE_IMPORT_DESCRIPTOR );
		for ( auto descriptor_index = 0ul; descriptor_index < descriptor_count; descriptor_index++ ) {
			auto descriptor = &imports[ descriptor_index ];
			if ( !descriptor->Name || !descriptor->FirstThunk )
				break;

			auto import_module = reinterpret_cast< const char* >( memory::rva_to_raw_pointer( disk_image, disk_image_size, descriptor->Name, 1 ) );
			if ( !import_module || !import_module[ 0 ] )
				continue;

			if ( ascii_starts_with_insensitive( import_module, "api-" ) || ascii_starts_with_insensitive( import_module, "ext-" ) )
				continue;

			auto thunk_rva = descriptor->FirstThunk;
			for ( auto ordinal = 0ul; ; ordinal++ ) {
				auto thunk_disk = memory::rva_to_raw_pointer(
					disk_image,
					disk_image_size,
					thunk_rva + ordinal * sizeof( unsigned long long ),
					sizeof( unsigned long long )
				);

				if ( !thunk_disk )
					break;

				unsigned long long disk_value = 0;
				memcpy( &disk_value, thunk_disk, sizeof( disk_value ) );
				if ( !disk_value )
					break;

				auto slot_address = reinterpret_cast< unsigned long long >( module->m_image_base ) + thunk_rva + ordinal * sizeof( unsigned long long );
				unsigned long long live_target = 0;
				size_t bytes_copied = 0;
				if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( slot_address ), sizeof( live_target ), &live_target, &bytes_copied ) || !live_target )
					continue;

				auto owner = memory::lookup_address_owner( modules, live_target );
				if ( owner && ascii_equal_insensitive( owner, import_module ) )
					continue;

				if ( ascii_equal_insensitive( import_module, "kdcom.dll" ) &&
					owner && ascii_equal_insensitive( owner, "kd.dll" ) )
					continue;

				if ( ascii_equal_insensitive( import_module, "kdcom.dll" ) &&
					owner && ascii_equal_insensitive( owner, "kdnet.dll" ) )
					continue;

				add_import_detection(
					command,
					module_name,
					import_module,
					ordinal,
					slot_address,
					live_target,
					owner
				);
				detections++;
			}
		}

		return detections;
	}

	void report_text_differences_in_chunk( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* module, const char* module_name, const char* section_name, const unsigned char* disk_bytes, const unsigned char* live_bytes, unsigned long text_rva, unsigned long long live_address, unsigned long chunk_start, unsigned long chunk_size, unsigned long total_size, text_scan_stats_t* stats ) {
		if ( !command || !module || !disk_bytes || !live_bytes )
			return;

		auto chunk_end = chunk_start + chunk_size;

		for ( auto offset = chunk_start; offset < chunk_end; ) {
			if ( disk_bytes[ offset ] == live_bytes[ offset ] || live_bytes[ offset ] == 0 ) {
				offset++;
				continue;
			}

			auto range_start = offset;
			while ( offset < chunk_end && disk_bytes[ offset ] != live_bytes[ offset ] && live_bytes[ offset ] != 0 )
				offset++;

			auto range_size = offset - range_start;
			auto range_rva = text_rva + range_start;
			auto range_address = live_address + range_start;

			if ( stats )
				stats->m_raw_ranges++;

			auto page_address = range_address & ~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 );
			//paging::pt_entries_t pt_entries{ };
			//if ( paging::hyperspace_entries( pt_entries, page_address ) ) {
			//	if ( !pt_entries.m_pde.hard.page_size && pt_entries.m_pte.value != 0 ) {
			//		add_pfn_backing_detection( command, module_name, section_name, page_address, pt_entries.m_pte, "split trusted large page code" );
			//	}
			//}

			auto scan_start = range_start > 15 ? range_start - 15 : 0;
			bool reported_detection = false;
			for ( auto test_offset = scan_start; test_offset < offset; test_offset++ ) {
				signatures::relative_branch_signature_t signature{ };
				if ( !signatures::match_relative_branch_signature( live_bytes, total_size, test_offset, live_address + test_offset, &signature ) )
					continue;

				if ( test_offset != range_start && ( range_start <= test_offset || range_start >= test_offset + signature.m_size ) )
					continue;

				if ( stats )
					stats->m_relative_branch_candidates++;

				signatures::relative_branch_signature_t disk_signature{ };
				auto disk_has_relative_branch = signatures::match_relative_branch_signature(
					disk_bytes, total_size, test_offset, live_address + test_offset, &disk_signature );

				auto live_owner = memory::lookup_address_owner( modules, signature.m_target );
				auto disk_owner = disk_has_relative_branch ? memory::lookup_address_owner( modules, disk_signature.m_target ) : nullptr;

				if ( disk_has_relative_branch &&
					ascii_equal_insensitive( disk_signature.m_type, signature.m_type ) &&
					disk_signature.m_target == signature.m_target )
					continue;

				utility::print(
					"rel_branch: rva=0x%x type=%s live_target=0x%llx live_owner=%s disk_has_branch=%d disk_target=0x%llx disk_owner=%s\n",
					text_rva + test_offset,
					signature.m_type,
					signature.m_target,
					live_owner ? live_owner : "unknown",
					disk_has_relative_branch ? 1 : 0,
					disk_has_relative_branch ? disk_signature.m_target : 0,
					disk_owner ? disk_owner : "unknown"
				);

				if ( !detections::is_suspicious_external_target( modules, module, signature.m_target ) )
					continue;

				char extra[ 64 ]{ };
				RtlStringCbPrintfA(
					extra,
					sizeof( extra ),
					"target=0x%llx owner=%s",
					signature.m_target,
					live_owner ? live_owner : "unknown"
				);

				add_text_detection(
					command,
					module_name,
					section_name,
					violation_name_for_branch_signature( signature.m_type ),
					text_rva + test_offset,
					live_address + test_offset,
					signature.m_size,
					extra
				);
				reported_detection = true;

				if ( stats )
					stats->m_relative_branch_detections++;
			}

			for ( auto test_offset = scan_start; test_offset < offset; test_offset++ ) {
				signatures::rip_register_branch_signature_t signature{ };
				if ( !signatures::match_rip_register_branch_signature( live_bytes, total_size, test_offset, &signature ) )
					continue;

				if ( stats )
					stats->m_rip_register_candidates++;

				signatures::rip_register_branch_signature_t disk_signature{ };
				auto pointer_address = live_address + test_offset + 7 + signature.m_displacement;
				auto target = pointer_address;
				if ( signature.m_dereference ) {
					size_t bytes_copied = 0;
					auto copied_target = memory::copy_kernel_memory( reinterpret_cast< void* >( pointer_address ), sizeof( target ), &target, &bytes_copied );
					if ( !copied_target )
						continue;
				}

				auto disk_has_same_rip_register_branch = signatures::match_rip_register_branch_signature( disk_bytes, total_size, test_offset, &disk_signature ) &&
					ascii_equal_insensitive( disk_signature.m_type, signature.m_type ) &&
					disk_signature.m_displacement == signature.m_displacement &&
					disk_signature.m_dereference == signature.m_dereference;

				if ( disk_has_same_rip_register_branch ) {
					if ( !signature.m_dereference )
						continue;

					auto pointer_offset = pointer_address - live_address;
					unsigned long long disk_target = 0;
					if ( pointer_offset <= total_size && sizeof( disk_target ) <= total_size - static_cast< unsigned long >( pointer_offset ) ) {
						memcpy( &disk_target, disk_bytes + pointer_offset, sizeof( disk_target ) );
						if ( disk_target == target )
							continue;
					}
					else {
						continue;
					}
				}

				auto owner = memory::lookup_address_owner( modules, target );
				if ( !detections::is_suspicious_external_target( modules, module, target ) )
					continue;

				char extra[ 64 ]{ };

				if ( signature.m_dereference ) {
					RtlStringCbPrintfA(
						extra,
						sizeof( extra ),
						"ptr=0x%llx target=0x%llx owner=%s",
						pointer_address,
						target,
						owner ? owner : "unknown"
					);
				}
				else {
					RtlStringCbPrintfA(
						extra,
						sizeof( extra ),
						"target=0x%llx owner=%s",
						target,
						owner ? owner : "unknown"
					);
				}

				add_text_detection(
					command,
					module_name,
					section_name,
					violation_name_for_branch_signature( signature.m_type ),
					text_rva + test_offset,
					live_address + test_offset,
					signature.m_size,
					extra
				);
				reported_detection = true;

				if ( stats )
					stats->m_rip_register_detections++;
			}

			for ( auto test_offset = scan_start; test_offset < offset; test_offset++ ) {
				signatures::rip_indirect_branch_signature_t signature{ };
				if ( !signatures::match_rip_indirect_branch_signature( live_bytes, total_size, test_offset, &signature ) )
					continue;

				if ( stats )
					stats->m_rip_indirect_candidates++;

				signatures::rip_indirect_branch_signature_t disk_signature{ };
				auto pointer_address = live_address + test_offset + signature.m_size + signature.m_displacement;
				unsigned long long target = 0;
				size_t bytes_copied = 0;
				auto copied_target = memory::copy_kernel_memory( reinterpret_cast< void* >( pointer_address ), sizeof( target ), &target, &bytes_copied );
				if ( !copied_target )
					continue;

				auto disk_has_same_indirect_branch = signatures::match_rip_indirect_branch_signature( disk_bytes, total_size, test_offset, &disk_signature ) && ascii_equal_insensitive( disk_signature.m_type, signature.m_type );
				if ( disk_has_same_indirect_branch ) {
					auto pointer_offset = pointer_address - live_address;
					unsigned long long disk_target = 0;
					if ( pointer_offset <= total_size && sizeof( disk_target ) <= total_size - static_cast< unsigned long >( pointer_offset ) ) {
						memcpy( &disk_target, disk_bytes + pointer_offset, sizeof( disk_target ) );
						if ( disk_target == target )
							continue;
					}
					else {
						continue;
					}
				}

				auto owner = memory::lookup_address_owner( modules, target );
				if ( !detections::is_suspicious_external_target( modules, module, target ) )
					continue;

				char extra[ 64 ]{ };

				RtlStringCbPrintfA(
					extra,
					sizeof( extra ),
					"ptr=0x%llx target=0x%llx owner=%s",
					pointer_address,
					target,
					owner ? owner : "unknown"
				);

				add_text_detection(
					command,
					module_name,
					section_name,
					violation_name_for_branch_signature( signature.m_type ),
					text_rva + test_offset,
					live_address + test_offset,
					signature.m_size,
					extra
				);
				reported_detection = true;

				if ( stats )
					stats->m_rip_indirect_detections++;
			}

			for ( auto test_offset = scan_start; test_offset < offset; test_offset++ ) {
				signatures::pph_signature_t signature{ };
				if ( !signatures::match_pph_signature( live_bytes, total_size, test_offset, &signature ) )
					continue;

				if ( stats )
					stats->m_pph_candidates++;

				signatures::pph_signature_t disk_signature{ };
				if ( signatures::match_pph_signature( disk_bytes, total_size, test_offset, &disk_signature ) && disk_signature.m_target == signature.m_target )
					continue;

				auto owner = memory::lookup_address_owner( modules, signature.m_target );
				if ( !detections::is_suspicious_external_target( modules, module, signature.m_target ) )
					continue;

				char extra[ 64 ]{ };

				RtlStringCbPrintfA(
					extra,
					sizeof( extra ),
					"pph abs jmp=0x%llx owner=%s",
					signature.m_target,
					owner ? owner : "unknown"
				);

				add_text_detection(
					command,
					module_name,
					section_name,
					m_absolute_code_redirect_violation,
					text_rva + test_offset,
					live_address + test_offset,
					14,
					extra
				);
				reported_detection = true;

				if ( stats )
					stats->m_pph_detections++;
			}

			for ( auto test_offset = scan_start; test_offset < offset; test_offset++ ) {
				signatures::mov_branch_signature_t signature{ };
				if ( !signatures::match_mov_branch_signature( live_bytes, total_size, test_offset, &signature ) )
					continue;

				if ( stats )
					stats->m_mov_candidates++;

				signatures::mov_branch_signature_t disk_signature{ };
				if ( signatures::match_mov_branch_signature( disk_bytes, total_size, test_offset, &disk_signature ) &&
					ascii_equal_insensitive( disk_signature.m_type, signature.m_type ) &&
					disk_signature.m_target == signature.m_target )
					continue;

				auto target = signature.m_target;
				auto pointer_address = signature.m_target;
				auto dereferenced = ascii_equal_insensitive( signature.m_type, "mov_reg_imm64_jmp_mem_reg" ) ||
					ascii_equal_insensitive( signature.m_type, "mov_reg_imm64_call_mem_reg" );

				if ( dereferenced ) {
					size_t bytes_copied = 0;
					auto copied_target = memory::copy_kernel_memory( reinterpret_cast< void* >( pointer_address ), sizeof( target ), &target, &bytes_copied );
					if ( !copied_target )
						continue;
				}

				auto owner = memory::lookup_address_owner( modules, target );
				if ( !detections::is_suspicious_external_target( modules, module, target ) )
					continue;

				char extra[ 64 ]{ };

				if ( dereferenced ) {
					RtlStringCbPrintfA(
						extra,
						sizeof( extra ),
						"ptr=0x%llx target=0x%llx owner=%s",
						pointer_address,
						target,
						owner ? owner : "unknown"
					);
				}
				else {
					RtlStringCbPrintfA(
						extra,
						sizeof( extra ),
						"target=0x%llx owner=%s",
						target,
						owner ? owner : "unknown"
					);
				}

				add_text_detection(
					command,
					module_name,
					section_name,
					violation_name_for_branch_signature( signature.m_type ),
					text_rva + test_offset,
					live_address + test_offset,
					signature.m_size,
					extra
				);
				reported_detection = true;

				if ( stats )
					stats->m_mov_detections++;
			}

			for ( auto test_offset = scan_start; test_offset < offset; test_offset++ ) {
				signatures::push_ret_signature_t signature{ };
				if ( !signatures::match_push_ret_signature( live_bytes, total_size, test_offset, &signature ) )
					continue;

				if ( stats )
					stats->m_push_candidates++;

				signatures::push_ret_signature_t disk_signature{ };
				if ( signatures::match_push_ret_signature( disk_bytes, total_size, test_offset, &disk_signature ) &&
					ascii_equal_insensitive( disk_signature.m_type, signature.m_type ) &&
					disk_signature.m_target == signature.m_target )
					continue;

				auto owner = memory::lookup_address_owner( modules, signature.m_target );
				if ( !detections::is_suspicious_external_target( modules, module, signature.m_target ) )
					continue;

				char extra[ 64 ]{ };

				RtlStringCbPrintfA(
					extra,
					sizeof( extra ),
					"target=0x%llx owner=%s",
					signature.m_target,
					owner ? owner : "unknown"
				);

				add_text_detection(
					command,
					module_name,
					section_name,
					violation_name_for_branch_signature( signature.m_type ),
					text_rva + test_offset,
					live_address + test_offset,
					signature.m_size,
					extra
				);
				reported_detection = true;

				if ( stats )
					stats->m_push_detections++;
			}

			if ( reported_detection )
				continue;

			if constexpr ( m_report_generic_code_changes ) {
				char extra[ 64 ]{ };
				RtlStringCbPrintfA(
					extra,
					sizeof( extra ),
					"changed bytes size=0x%x",
					range_size
				);

				add_text_detection(
					command,
					module_name,
					section_name,
					m_code_section_modified_violation,
					range_rva,
					range_address,
					range_size,
					extra
				);

				if ( stats )
					stats->m_generic_detections++;
			}
			else if ( stats ) {
				stats->m_ignored_ranges++;
			}
		}
	}

	text_scan_stats_t report_text_differences( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* module, const char* module_name, const char* section_name, const unsigned char* disk_bytes, const unsigned char* live_bytes, unsigned long text_rva, unsigned long long live_address, unsigned long size ) {
		text_scan_stats_t stats{ };

		if ( !command || !module || !disk_bytes || !live_bytes )
			return stats;

		for ( auto chunk_start = 0ul; chunk_start < size; ) {
			auto remaining_size = size - chunk_start;
			auto chunk_size = remaining_size > m_text_chunk_size ? m_text_chunk_size : remaining_size;
			auto equal_bytes = RtlCompareMemory( disk_bytes + chunk_start, live_bytes + chunk_start, chunk_size );

			if ( equal_bytes != chunk_size ) {
				stats.m_dirty_chunks++;

				report_text_differences_in_chunk(
					command,
					modules,
					module,
					module_name,
					section_name,
					disk_bytes,
					live_bytes,
					text_rva,
					live_address,
					chunk_start,
					chunk_size,
					size,
					&stats
				);
			}

			chunk_start += chunk_size;
		}

		return stats;
	}

	bool scan_executable_section( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* module, const char* module_name, const unsigned char* disk_image, unsigned long disk_image_size, const IMAGE_SECTION_HEADER* section, unsigned long* sections_scanned ) {
		if ( !command || !modules || !module || !module_name || !disk_image || !section )
			return false;

		if ( !( section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
			return true;

		char section_name[ 9 ]{ };
		memory::copy_section_name( section, section_name, sizeof( section_name ) );

		if ( !ascii_equal_insensitive( section_name, ".text" ) )
			return true;

		if ( section->PointerToRawData >= disk_image_size || section->VirtualAddress >= module->m_image_size )
			return true;

		auto compare_size = section->SizeOfRawData;
		auto raw_available = disk_image_size - section->PointerToRawData;
		auto live_available = module->m_image_size - section->VirtualAddress;

		if ( compare_size > raw_available )
			compare_size = raw_available;

		if ( section->Misc.VirtualSize && compare_size > section->Misc.VirtualSize )
			compare_size = section->Misc.VirtualSize;

		if ( compare_size > live_available )
			compare_size = live_available;

		if ( !compare_size )
			return true;

		auto live_snapshot = memory::allocate_pool( compare_size, 1 );
		auto disk_snapshot = memory::allocate_pool( compare_size, 1 );
		if ( !live_snapshot || !disk_snapshot ) {
			if ( live_snapshot )
				memory::free_pool( live_snapshot );

			if ( disk_snapshot )
				memory::free_pool( disk_snapshot );

			command->m_error = STATUS_INSUFFICIENT_RESOURCES;
			return false;
		}

		memset( live_snapshot, 0, compare_size );
		memset( disk_snapshot, 0, compare_size );

		auto live_address = static_cast< unsigned char* >( module->m_image_base ) + section->VirtualAddress;
		size_t any_copied = 0;
		for ( auto offset = 0ul; offset < compare_size; ) {
			auto page_rem = PAGE_SIZE - ( ( reinterpret_cast< unsigned long long >( live_address + offset ) ) & ( PAGE_SIZE - 1 ) );
			auto chunk = compare_size - offset;
			if ( chunk > page_rem )
				chunk = static_cast< unsigned long >( page_rem );

			size_t page_copied = 0;
			if ( memory::copy_kernel_memory( live_address + offset, chunk, static_cast< unsigned char* >( live_snapshot ) + offset, &page_copied ) )
				any_copied += page_copied;

			offset += chunk;
		}

		if ( !any_copied ) {
			command->m_error = STATUS_PARTIAL_COPY;
			memory::free_pool( disk_snapshot );
			memory::free_pool( live_snapshot );
			return false;
		}

		if ( sections_scanned )
			( *sections_scanned )++;
		command->m_sections_scanned++;

		auto disk_section_bytes = disk_image + section->PointerToRawData;
		auto live_section_bytes = static_cast< const unsigned char* >( live_snapshot );
		auto normalized_disk_bytes = static_cast< unsigned char* >( disk_snapshot );
		memcpy( normalized_disk_bytes, disk_section_bytes, compare_size );

		auto relocated_bytes = memory::normalize_relocated_bytes(
			disk_image,
			disk_image_size,
			section->VirtualAddress,
			compare_size,
			live_section_bytes,
			normalized_disk_bytes
		);
		command->m_relocated_bytes += relocated_bytes;

		auto memory_hash = c_sha1::hash_buffer( live_section_bytes, compare_size );
		auto normalized_disk_hash = c_sha1::hash_buffer( normalized_disk_bytes, compare_size );

		if ( !equal_digest( normalized_disk_hash, memory_hash ) ) {
			auto summary = summarize_differences( normalized_disk_bytes, live_section_bytes, compare_size );
			command->m_nonzero_live_bytes += summary.m_nonzero_live_bytes;

			if ( summary.m_nonzero_live_bytes ) {
				auto stats = report_text_differences(
					command,
					modules,
					module,
					module_name,
					section_name,
					normalized_disk_bytes,
					live_section_bytes,
					section->VirtualAddress,
					reinterpret_cast< unsigned long long >( live_address ),
					compare_size
				);

				auto signature_candidates =
					stats.m_pph_candidates +
					stats.m_mov_candidates +
					stats.m_push_candidates +
					stats.m_rip_indirect_candidates +
					stats.m_relative_branch_candidates +
					stats.m_rip_register_candidates;
				auto signature_detections =
					stats.m_pph_detections +
					stats.m_mov_detections +
					stats.m_push_detections +
					stats.m_rip_indirect_detections +
					stats.m_relative_branch_detections +
					stats.m_rip_register_detections;

				command->m_dirty_chunks += stats.m_dirty_chunks;
				command->m_raw_ranges += stats.m_raw_ranges;
				command->m_ignored_ranges += stats.m_ignored_ranges;
				command->m_signature_candidates += signature_candidates;
				command->m_signature_detections += signature_detections;
			}
		}

		memory::free_pool( disk_snapshot );
		memory::free_pool( live_snapshot );
		return true;
	}
}
