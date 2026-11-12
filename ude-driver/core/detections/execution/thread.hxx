#pragma once

namespace execution::thread {
	constexpr auto m_system_process_information = 5ul;

	struct system_thread_information_t {
		LARGE_INTEGER m_reserved1[ 3 ];
		unsigned long m_reserved2;
		void* m_start_address;
		CLIENT_ID m_client_id;
		KPRIORITY m_priority;
		long m_base_priority;
		unsigned long m_reserved3;
		unsigned long m_thread_state;
		unsigned long m_wait_reason;
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

	bool has_bad_backing( unsigned long long address, unsigned long long* pfn, unsigned long long* walk_pa, unsigned long long* api_pa, bool* bad_flags ) {
		if ( pfn )
			*pfn = 0;

		if ( walk_pa )
			*walk_pa = 0;

		if ( api_pa )
			*api_pa = 0;

		if ( bad_flags )
			*bad_flags = false;

		paging::pt_entries_t entries{ };
		if ( !paging::hyperspace_entries( entries, address ) )
			return false;

		unsigned long long backing_pfn = 0;
		bool flags = false;
		if ( entries.m_pdpte.hard.page_size ) {
			backing_pfn = entries.m_pdpte.hard.pfn;
			flags = entries.m_pdpte.hard.user_supervisor || entries.m_pdpte.hard.no_execute;
		}
		else if ( entries.m_pde.hard.page_size ) {
			backing_pfn = entries.m_pde.hard.pfn;
			flags = entries.m_pde.hard.user_supervisor || entries.m_pde.hard.no_execute;
		}
		else {
			backing_pfn = entries.m_pte.hard.pfn;
			flags = entries.m_pte.hard.user_supervisor || entries.m_pte.hard.no_execute;
		}

		if ( pfn )
			*pfn = backing_pfn;

		if ( bad_flags )
			*bad_flags = flags;

		std::uint32_t page_size = 0;
		unsigned long long translated = 0;
		paging::translate_linear( address, &translated, &page_size );

		auto physical = MmGetPhysicalAddress( reinterpret_cast< void* >( address ) );
		auto api_physical = static_cast< unsigned long long >( physical.QuadPart );

		if ( walk_pa )
			*walk_pa = translated;

		if ( api_pa )
			*api_pa = api_physical;

		return ( translated && api_physical && translated != api_physical ) || flags;
	}

	unsigned long inspect_ethread_anomalies(
		ioctl::command_t* command,
		const system_modules_t* modules,
		HANDLE pid,
		HANDLE tid,
		unsigned long long query_start ) {
		if ( !command || !modules || !tid )
			return 0;

		PETHREAD ethread = nullptr;
		if ( !NT_SUCCESS( PsLookupThreadByThreadId( tid, &ethread ) ) || !ethread )
			return 0;

		unsigned long detections = 0;
		const auto thread_va = reinterpret_cast< unsigned long long >( ethread );
		const auto is_system_thread = PsIsSystemThread( ethread ) != FALSE;

		unsigned char dispatcher_header[ 4 ]{ };
		size_t copied = 0;
		if ( is_system_thread &&
			memory::copy_kernel_memory( ethread, sizeof( dispatcher_header ), dispatcher_header, &copied ) &&
			( dispatcher_header[ 3 ] & 0x01u ) != 0 &&
			!SharedUserData->KdDebuggerEnabled ) {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"pid=0x%llx tid=0x%llx ethread=0x%llx debug_active=0x%x reason=system_thread_active_dr7",
				reinterpret_cast< unsigned long long >( pid ),
				reinterpret_cast< unsigned long long >( tid ),
				thread_va,
				static_cast< unsigned long >( dispatcher_header[ 3 ] )
			);
			auto before = command->m_total_detection_count;
			report::add_execution_detection(
				command,
				"thread!debug_active",
				report::m_debug_register_violation,
				detail,
				thread_va,
				sizeof( void* )
			);
			if ( command->m_total_detection_count != before )
				detections++;
		}

		if ( is_system_thread && m_entry.m_offsets.m_kthread_start_address && m_entry.m_offsets.m_kthread_start_address < 0x1000 ) {
			unsigned long long internal_start = 0;
			if ( memory::copy_kernel_memory(
				reinterpret_cast< void* >( thread_va + m_entry.m_offsets.m_kthread_start_address ),
				sizeof( internal_start ),
				&internal_start,
				&copied ) &&
				internal_start && memory::is_canonical_kernel_address( internal_start ) ) {
				char section[ 9 ]{ };
				auto owner_module = module::disk::find_module_by_address( modules, internal_start );
				auto executable = owner_module && module::disk::is_address_in_executable_section( owner_module, internal_start, section, sizeof( section ) );
				if ( !owner_module || !executable ) {
					char detail[ ioctl::m_detection_text_size ]{ };
					RtlStringCbPrintfA(
						detail,
						sizeof( detail ),
						"pid=0x%llx tid=0x%llx ethread_start=0x%llx query_start=0x%llx reason=unbacked_ethread_start",
						reinterpret_cast< unsigned long long >( pid ),
						reinterpret_cast< unsigned long long >( tid ),
						internal_start,
						query_start
					);
					auto before = command->m_total_detection_count;
					report::add_execution_detection(
						command,
						"thread!start_address",
						report::m_thread_anomaly_violation,
						detail,
						internal_start,
						sizeof( void* )
					);
					if ( command->m_total_detection_count != before )
						detections++;
				}
			}
		}

		ObDereferenceObject( ethread );
		return detections;
	}

	unsigned long scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return 0;

		void* buffer = nullptr;
		if ( !query_processes( &buffer ) )
			return 0;

		unsigned long detections = 0;
		auto process = static_cast< system_process_information_t* >( buffer );

		while ( process ) {
			auto threads = reinterpret_cast< system_thread_information_t* >( process + 1 );
			for ( auto index = 0ul; index < process->m_thread_count; index++ ) {
				auto start = reinterpret_cast< unsigned long long >( threads[ index ].m_start_address );
				detections += inspect_ethread_anomalies(
					command,
					modules,
					process->m_process_id,
					threads[ index ].m_client_id.UniqueThread,
					start
				);

				if ( !start || !memory::is_canonical_kernel_address( start ) )
					continue;

				char section[ 9 ]{ };
				auto owner_module = module::disk::find_module_by_address( modules, start );
				auto owner = owner_module ?
					reinterpret_cast< const char* >( owner_module->m_full_path_name ) + owner_module->m_offset_to_file_name :
					nullptr;
				auto executable = owner_module && module::disk::is_address_in_executable_section( owner_module, start, section, sizeof( section ) );
				unsigned long long pfn = 0;
				unsigned long long walk_pa = 0;
				unsigned long long api_pa = 0;
				bool bad_flags = false;
				auto bad_backing = has_bad_backing( start, &pfn, &walk_pa, &api_pa, &bad_flags );

				if ( owner_module && executable && !bad_backing )
					continue;

				auto reason = "unknown_owner";
				if ( owner_module && !executable )
					reason = "non_executable_section";
				else if ( owner_module && executable && bad_backing )
					reason = "bad_backing";

				char target[ ioctl::m_detection_target_size ]{ };
				char detail[ ioctl::m_detection_text_size ]{ };

				RtlStringCbPrintfA(
					target,
					sizeof( target ),
					"%s!thread",
					owner ? owner : "unknown"
				);

				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"pid=0x%llx tid=0x%llx start=0x%llx reason=%s section=%s pfn=0x%llx flags=%s%s",
					reinterpret_cast< unsigned long long >( process->m_process_id ),
					reinterpret_cast< unsigned long long >( threads[ index ].m_client_id.UniqueThread ),
					start,
					reason,
					section[ 0 ] ? section : "unknown",
					pfn,
					bad_backing ? "bad_backing " : "",
					bad_flags ? "bad_pte" : ""
				);

				auto before = command->m_total_detection_count;
				report::add_execution_detection(
					command,
					target,
					report::m_thread_start_violation,
					detail,
					start,
					sizeof( void* )
				);

				if ( command->m_total_detection_count != before )
					detections++;
			}

			if ( !process->m_next_entry_offset )
				break;

			process = reinterpret_cast< system_process_information_t* >(
				reinterpret_cast< unsigned char* >( process ) + process->m_next_entry_offset
			);
		}

		memory::free_pool( buffer );
		return detections;
	}
}
