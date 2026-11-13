#pragma once

namespace execution::processor {
	constexpr auto m_max_processor_samples = 256ul;
	constexpr auto m_max_stack_frames = 64ul;
	constexpr auto m_repeated_region_size = 0x40ull;
	constexpr auto m_nmi_wait_attempts = 50ul;
	constexpr auto m_nmi_wait_microseconds = 1000ul;

	enum class sample_source_t : unsigned long {
		none = 0,
		nmi_callback = 1,
		ipi_callback = 2
	};

	constexpr auto m_max_sample_frames = 16ul;

	struct kaffinity_ex_t {
		USHORT m_count;
		USHORT m_size;
		ULONG m_reserved;
		ULONG_PTR m_bitmap[ 64 ];
	};

	using ke_initialize_affinity_ex_t = void( NTAPI* )( kaffinity_ex_t* affinity );
	using ke_add_processor_affinity_ex_t = void( NTAPI* )( kaffinity_ex_t* affinity, ULONG processor_index );
	using hal_send_nmi_t = void( NTAPI* )( kaffinity_ex_t* affinity );

	struct processor_sample_t {
		bool m_valid;
		bool m_interrupted_context;
		unsigned long m_processor;
		unsigned long long m_rip;
		unsigned long long m_rsp;
		unsigned long m_frame_count;
		unsigned long long m_frames[ m_max_sample_frames ];
		sample_source_t m_source;
	};

	struct sample_context_t {
		volatile long m_pending_nmi[ m_max_processor_samples ];
		processor_sample_t m_samples[ m_max_processor_samples ];
	};

	struct address_info_t {
		const system_module_t* m_module;
		const char* m_owner;
		char m_section[ 9 ];
		bool m_executable;
		bool m_whitelisted;
		bool m_pte_valid;
		bool m_bad_pfn;
		bool m_bad_flags;
		unsigned long long m_pfn;
		unsigned long long m_pa_from_walk;
		unsigned long long m_pa_from_api;
		paging::pt_entries_t m_entries;
	};

	const char* sample_source_name( sample_source_t source ) {
		switch ( source ) {
		case sample_source_t::nmi_callback:
			return "nmi_callback";
		case sample_source_t::ipi_callback:
			return "ipi_callback";
		default:
			return "none";
		}
	}

	void scan_resident_stack_page( unsigned long long start_rsp, processor_sample_t* sample, bool look_for_iretq ) {
		if ( !sample || !memory::is_canonical_kernel_address( start_rsp ) ||
			!MmIsAddressValid( reinterpret_cast< void* >( start_rsp ) ) )
			return;

		auto aligned_rsp = ( start_rsp + 7ull ) & ~7ull;
		auto page_end = ( start_rsp & ~0xfffull ) + PAGE_SIZE;
		if ( !MmIsAddressValid( reinterpret_cast< void* >( page_end - sizeof( unsigned long long ) ) ) )
			return;

		if ( look_for_iretq ) {
			for ( auto cursor = aligned_rsp; cursor + 5 * sizeof( unsigned long long ) <= page_end; cursor += sizeof( unsigned long long ) ) {
				const auto frame = reinterpret_cast< const unsigned long long* >( cursor );
				const auto candidate_rip = frame[ 0 ];
				const auto candidate_cs = frame[ 1 ];
				const auto candidate_rflags = frame[ 2 ];
				const auto candidate_rsp = frame[ 3 ];
				const auto candidate_ss = frame[ 4 ];

				if ( candidate_cs == 0x10ull &&
					candidate_ss == 0x18ull &&
					( candidate_rflags & 0x2ull ) != 0 &&
					memory::is_canonical_kernel_address( candidate_rip ) &&
					memory::is_canonical_kernel_address( candidate_rsp ) &&
					( candidate_rsp & 0x7ull ) == 0 ) {
					sample->m_rip = candidate_rip;
					sample->m_rsp = candidate_rsp;
					sample->m_interrupted_context = true;
					break;
				}
			}
		}

		for ( auto cursor = aligned_rsp;
			cursor + sizeof( unsigned long long ) <= page_end && sample->m_frame_count < m_max_sample_frames;
			cursor += sizeof( unsigned long long ) ) {
			auto value = *reinterpret_cast< const unsigned long long* >( cursor );
			if ( !memory::is_canonical_kernel_address( value ) )
				continue;

			bool duplicate = false;
			for ( auto i = 0ul; i < sample->m_frame_count; i++ ) {
				if ( sample->m_frames[ i ] == value ) {
					duplicate = true;
					break;
				}
			}
			if ( !duplicate )
				sample->m_frames[ sample->m_frame_count++ ] = value;
		}
	}

	void capture_processor_sample( sample_context_t* samples, sample_source_t source, bool interrupted_context ) {
		if ( !samples )
			return;

		auto processor = KeGetCurrentProcessorNumberEx( nullptr );
		if ( processor >= m_max_processor_samples )
			return;

		auto sample = &samples->m_samples[ processor ];
		sample->m_processor = processor;
		sample->m_rip = reinterpret_cast< unsigned long long >( _ReturnAddress( ) );
		sample->m_rsp = reinterpret_cast< unsigned long long >( _AddressOfReturnAddress( ) );
		sample->m_interrupted_context = interrupted_context;
		sample->m_frame_count = 0;
		sample->m_source = source;

		scan_resident_stack_page( sample->m_rsp, sample, source == sample_source_t::nmi_callback );
		sample->m_valid = true;
	}

	BOOLEAN nmi_sample_callback( void* context, BOOLEAN handled ) {
		auto samples = reinterpret_cast< sample_context_t* >( context );
		if ( !samples )
			return handled;

		auto processor = KeGetCurrentProcessorNumberEx( nullptr );
		capture_processor_sample( samples, sample_source_t::nmi_callback, false );

		if ( processor < m_max_processor_samples &&
			InterlockedCompareExchange( &samples->m_pending_nmi[ processor ], 0, 1 ) == 1 )
			return TRUE;

		return handled;
	}

	ULONG_PTR ipi_callback_sample_callback( ULONG_PTR context ) {
		auto samples = reinterpret_cast< sample_context_t* >( context );
		if ( !samples )
			return 0;

		auto processor = KeGetCurrentProcessorNumberEx( nullptr );
		if ( processor < m_max_processor_samples && !samples->m_samples[ processor ].m_valid )
			capture_processor_sample( samples, sample_source_t::ipi_callback, false );

		return 0;
	}

	unsigned long count_samples( const sample_context_t& samples ) {
		unsigned long count = 0;
		for ( auto index = 0ul; index < m_max_processor_samples; index++ )
			if ( samples.m_samples[ index ].m_valid )
				count++;

		return count;
	}

	unsigned long count_samples_by_source( const sample_context_t& samples, sample_source_t source ) {
		unsigned long count = 0;
		for ( auto index = 0ul; index < m_max_processor_samples; index++ ) {
			auto sample = &samples.m_samples[ index ];
			if ( sample->m_valid && sample->m_source == source )
				count++;
		}

		return count;
	}

	unsigned long count_interrupted_context_samples( const sample_context_t& samples ) {
		unsigned long count = 0;
		for ( auto index = 0ul; index < m_max_processor_samples; index++ ) {
			auto sample = &samples.m_samples[ index ];
			if ( sample->m_valid && sample->m_interrupted_context )
				count++;
		}

		return count;
	}

	unsigned long collect_processor_samples( sample_context_t* samples ) {
		if ( !samples )
			return 0;

		UNICODE_STRING init_affinity_name = RTL_CONSTANT_STRING( L"KeInitializeAffinityEx" );
		UNICODE_STRING add_affinity_name = RTL_CONSTANT_STRING( L"KeAddProcessorAffinityEx" );
		UNICODE_STRING hal_send_nmi_name = RTL_CONSTANT_STRING( L"HalSendNMI" );

		auto ke_init_affinity = reinterpret_cast< ke_initialize_affinity_ex_t >( MmGetSystemRoutineAddress( &init_affinity_name ) );
		auto ke_add_affinity = reinterpret_cast< ke_add_processor_affinity_ex_t >( MmGetSystemRoutineAddress( &add_affinity_name ) );
		auto hal_send_nmi = reinterpret_cast< hal_send_nmi_t >( MmGetSystemRoutineAddress( &hal_send_nmi_name ) );

		auto processor_count = KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS );
		if ( processor_count > m_max_processor_samples )
			processor_count = m_max_processor_samples;

		auto nmi_handle = KeRegisterNmiCallback( nmi_sample_callback, samples );
		if ( nmi_handle ) {
			if ( ke_init_affinity && ke_add_affinity && hal_send_nmi && processor_count > 0 ) {
				auto caller_cpu = KeGetCurrentProcessorNumberEx( nullptr );
				for ( auto cpu = 0ul; cpu < processor_count; cpu++ ) {
					if ( cpu == caller_cpu )
						continue;

					kaffinity_ex_t affinity{ };
					ke_init_affinity( &affinity );
					ke_add_affinity( &affinity, cpu );

					InterlockedExchange( &samples->m_pending_nmi[ cpu ], 1 );
					hal_send_nmi( &affinity );

					for ( auto wait = 0ul; wait < 20ul; wait++ ) {
						if ( InterlockedCompareExchange( &samples->m_pending_nmi[ cpu ], 0, 0 ) == 0 )
							break;
						KeStallExecutionProcessor( 100 );
					}
					InterlockedExchange( &samples->m_pending_nmi[ cpu ], 0 );
				}

				KeStallExecutionProcessor( 500 );
			}
			else {
				for ( auto attempt = 0ul; attempt < m_nmi_wait_attempts; attempt++ ) {
					if ( count_samples( *samples ) )
						break;

					KeStallExecutionProcessor( m_nmi_wait_microseconds );
				}
			}

			KeDeregisterNmiCallback( nmi_handle );
		}

		if ( count_samples( *samples ) < processor_count )
			KeIpiGenericCall( ipi_callback_sample_callback, reinterpret_cast< ULONG_PTR >( samples ) );

		return count_samples( *samples );
	}

	const char* owner_name_or_unknown( const char* owner ) {
		return owner ? owner : "unknown";
	}

	bool query_address_info( const system_modules_t* modules, unsigned long long address, address_info_t* info ) {
		if ( !info )
			return false;

		memset( info, 0, sizeof( *info ) );
		if ( !modules || !address )
			return false;

		info->m_module = module::disk::find_module_by_address( modules, address );
		if ( info->m_module ) {
			info->m_owner = reinterpret_cast< const char* >( info->m_module->m_full_path_name ) + info->m_module->m_offset_to_file_name;
			info->m_executable = module::disk::is_address_in_executable_section( info->m_module, address, info->m_section, sizeof( info->m_section ) );
			info->m_whitelisted = module::disk::is_whitelisted_owner( info->m_owner );
		}

		info->m_pte_valid = paging::hyperspace_entries( info->m_entries, address );
		if ( !info->m_pte_valid )
			return true;

		if ( info->m_entries.m_pdpte.hard.page_size ) {
			info->m_pfn = info->m_entries.m_pdpte.hard.pfn;
			info->m_bad_flags = info->m_entries.m_pdpte.hard.user_supervisor || info->m_entries.m_pdpte.hard.no_execute;
		}
		else if ( info->m_entries.m_pde.hard.page_size ) {
			info->m_pfn = info->m_entries.m_pde.hard.pfn;
			info->m_bad_flags = info->m_entries.m_pde.hard.user_supervisor || info->m_entries.m_pde.hard.no_execute;
		}
		else {
			info->m_pfn = info->m_entries.m_pte.hard.pfn;
			info->m_bad_flags = info->m_entries.m_pte.hard.user_supervisor || info->m_entries.m_pte.hard.no_execute;
		}

		std::uint32_t page_size = 0;
		paging::translate_linear( address, &info->m_pa_from_walk, &page_size );

		auto api_pa = MmGetPhysicalAddress( reinterpret_cast< void* >( address ) );
		info->m_pa_from_api = static_cast< unsigned long long >( api_pa.QuadPart );
		info->m_bad_pfn = info->m_pa_from_walk && info->m_pa_from_api && info->m_pa_from_walk != info->m_pa_from_api;
		return true;
	}

	bool should_track_repeated_region( const address_info_t& info ) {
		return !info.m_owner || !info.m_executable || info.m_bad_pfn || info.m_bad_flags;
	}

	const char* stack_chain_label( unsigned long long address, const address_info_t& info ) {
		if ( info.m_owner )
			return info.m_owner;

		if ( address && memory::is_canonical_kernel_address( address ) && info.m_pte_valid )
			return "pool";

		return "unknown";
	}

	void add_address_classification_detection( ioctl::command_t* command, const char* scope, unsigned long index, unsigned long long address, const address_info_t& info, bool return_address ) {
		if ( !command || !address )
			return;

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };

		if ( info.m_owner ) {
			RtlStringCbPrintfA(
				target,
				sizeof( target ),
				"%s!%s",
				info.m_owner,
				info.m_section[ 0 ] ? info.m_section : "unknown"
			);
		}
		else {
			RtlStringCbPrintfA(
				target,
				sizeof( target ),
				"%s",
				scope ? scope : "execution"
			);
		}

		if ( !info.m_owner ) {
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"%s=%lu owner=unknown pfn=0x%llx walk_pa=0x%llx api_pa=0x%llx",
				scope ? scope : "sample",
				index,
				info.m_pfn,
				info.m_pa_from_walk,
				info.m_pa_from_api
			);

			report::add_execution_detection(
				command,
				target,
				return_address ? report::m_return_outside_code_violation : report::m_execution_unknown_va_violation,
				detail,
				address,
				sizeof( void* )
			);
			return;
		}

		if ( !info.m_executable ) {
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"%s=%lu owner=%s section=%s pfn=0x%llx",
				scope ? scope : "sample",
				index,
				owner_name_or_unknown( info.m_owner ),
				info.m_section[ 0 ] ? info.m_section : "unknown",
				info.m_pfn
			);

			report::add_execution_detection(
				command,
				target,
				return_address ? report::m_return_outside_code_violation : report::m_execution_non_code_section_violation,
				detail,
				address,
				sizeof( void* )
			);
		}

		if ( info.m_executable && ( info.m_bad_pfn || info.m_bad_flags ) ) {
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"%s=%lu owner=%s pfn=0x%llx walk_pa=0x%llx api_pa=0x%llx flags=%s%s",
				scope ? scope : "sample",
				index,
				owner_name_or_unknown( info.m_owner ),
				info.m_pfn,
				info.m_pa_from_walk,
				info.m_pa_from_api,
				info.m_bad_pfn ? "pfn_mismatch " : "",
				info.m_bad_flags ? "pte_flags" : ""
			);

			report::add_execution_detection(
				command,
				target,
				return_address ? report::m_return_bad_pfn_violation : report::m_execution_bad_pfn_violation,
				detail,
				address & ~( static_cast< unsigned long long >( PAGE_SIZE ) - 1 ),
				PAGE_SIZE
			);
		}
	}

	void record_region( unsigned long long* regions, unsigned long* counts, unsigned long capacity, unsigned long long address ) {
		if ( !regions || !counts || !address )
			return;

		auto region = address & ~( m_repeated_region_size - 1 );
		for ( auto index = 0ul; index < capacity; index++ ) {
			if ( regions[ index ] == region ) {
				counts[ index ]++;
				return;
			}

			if ( !regions[ index ] ) {
				regions[ index ] = region;
				counts[ index ] = 1;
				return;
			}
		}
	}

	unsigned long scan_stack_frames( ioctl::command_t* command, const system_modules_t* modules, unsigned long long* repeated_regions, unsigned long* repeated_counts, unsigned long repeated_capacity ) {
		void* frames[ m_max_stack_frames ]{ };
		auto frame_count = RtlWalkFrameChain( frames, ARRAYSIZE( frames ), 0 );
		unsigned long detections = 0;
		const char* chain[ 8 ]{ };
		unsigned long chain_count = 0;
		unsigned long suspicious_frames = 0;
		unsigned long first_suspicious_index = MAXULONG;
		unsigned long long first_suspicious_frame = 0;

		for ( auto index = 0ul; index < frame_count; index++ ) {
			auto frame = reinterpret_cast< unsigned long long >( frames[ index ] );
			if ( !frame )
				continue;

			address_info_t info{ };
			query_address_info( modules, frame, &info );
			auto suspicious = should_track_repeated_region( info );
			if ( chain_count < ARRAYSIZE( chain ) )
				chain[ chain_count++ ] = stack_chain_label( frame, info );

			if ( suspicious ) {
				record_region( repeated_regions, repeated_counts, repeated_capacity, frame );
				suspicious_frames++;
				if ( first_suspicious_index == MAXULONG ) {
					first_suspicious_index = index;
					first_suspicious_frame = frame;
				}
			}

			auto before = command->m_total_detection_count;
			add_address_classification_detection( command, "return", index, frame, info, true );
			if ( command->m_total_detection_count != before )
				detections++;
		}

		if ( suspicious_frames && chain_count ) {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"frames=%lu suspicious=%lu first_bad=%lu chain=%s -> %s -> %s -> %s -> %s -> %s -> %s -> %s",
				frame_count,
				suspicious_frames,
				first_suspicious_index,
				chain[ 0 ] ? chain[ 0 ] : "-",
				chain[ 1 ] ? chain[ 1 ] : "-",
				chain[ 2 ] ? chain[ 2 ] : "-",
				chain[ 3 ] ? chain[ 3 ] : "-",
				chain[ 4 ] ? chain[ 4 ] : "-",
				chain[ 5 ] ? chain[ 5 ] : "-",
				chain[ 6 ] ? chain[ 6 ] : "-",
				chain[ 7 ] ? chain[ 7 ] : "-"
			);

			auto before = command->m_total_detection_count;
			report::add_execution_detection(
				command,
				"execution!stack",
				report::m_stack_owner_chain_violation,
				detail,
				first_suspicious_frame ? first_suspicious_frame : reinterpret_cast< unsigned long long >( frames[ 0 ] ),
				sizeof( void* )
			);

			if ( command->m_total_detection_count != before )
				detections++;
		}

		return detections;
	}

	unsigned long scan_stack_bounds( ioctl::command_t* command ) {
		ULONG_PTR low = 0;
		ULONG_PTR high = 0;
		IoGetStackLimits( &low, &high );

		auto rsp = reinterpret_cast< unsigned long long >( _AddressOfReturnAddress( ) );
		if ( rsp >= low && rsp < high )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"rsp=0x%llx low=0x%llx high=0x%llx",
			rsp,
			static_cast< unsigned long long >( low ),
			static_cast< unsigned long long >( high )
		);

		report::add_execution_detection(
			command,
			"execution!stack",
			report::m_stack_pivot_violation,
			detail,
			rsp,
			sizeof( void* )
		);
		return 1;
	}

	unsigned long report_repeated_regions( ioctl::command_t* command, const unsigned long long* regions, const unsigned long* counts, unsigned long capacity ) {
		unsigned long detections = 0;

		for ( auto index = 0ul; index < capacity; index++ ) {
			if ( !regions[ index ] || counts[ index ] < 2 )
				continue;

			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"region=0x%llx count=%lu window=0x%llx",
				regions[ index ],
				counts[ index ],
				m_repeated_region_size
			);

			report::add_execution_detection(
				command,
				"execution!region",
				report::m_repeated_cave_execution_violation,
				detail,
				regions[ index ],
				static_cast< unsigned long >( m_repeated_region_size )
			);
			detections++;
		}

		return detections;
	}

	bool is_probable_return_site( unsigned long long address, const address_info_t& info ) {
		if ( !info.m_pte_valid )
			return false;

		const auto page_executable = info.m_entries.m_pdpte.hard.page_size ? !info.m_entries.m_pdpte.hard.no_execute :
			info.m_entries.m_pde.hard.page_size ? !info.m_entries.m_pde.hard.no_execute :
			!info.m_entries.m_pte.hard.no_execute;
		if ( !page_executable || address < 8 )
			return false;

		unsigned char pre_bytes[ 7 ]{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( address - 7 ), sizeof( pre_bytes ), pre_bytes, &copied ) )
			return false;

		if ( pre_bytes[ 2 ] == 0xE8 )
			return true;
		if ( pre_bytes[ 1 ] == 0xFF && ( pre_bytes[ 2 ] & 0x38 ) == 0x10 )
			return true;
		if ( pre_bytes[ 5 ] == 0xFF && ( pre_bytes[ 6 ] & 0xF8 ) == 0xD0 )
			return true;
		if ( ( pre_bytes[ 4 ] & 0xF0 ) == 0x40 && pre_bytes[ 5 ] == 0xFF && ( pre_bytes[ 6 ] & 0xF8 ) == 0xD0 )
			return true;

		return false;
	}

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		constexpr auto repeated_capacity = 128ul;
		auto samples = memory::allocate_pool< sample_context_t* >( sizeof( sample_context_t ), 1 );
		auto repeated_regions = memory::allocate_pool< unsigned long long* >( sizeof( unsigned long long ) * repeated_capacity, 1 );
		auto repeated_counts = memory::allocate_pool< unsigned long* >( sizeof( unsigned long ) * repeated_capacity, 1 );
		if ( !samples || !repeated_regions || !repeated_counts ) {
			if ( repeated_counts )
				memory::free_pool( repeated_counts );
			if ( repeated_regions )
				memory::free_pool( repeated_regions );
			if ( samples )
				memory::free_pool( samples );
			command->m_error = STATUS_INSUFFICIENT_RESOURCES;
			return false;
		}

		memset( samples, 0, sizeof( sample_context_t ) );
		memset( repeated_regions, 0, sizeof( unsigned long long ) * repeated_capacity );
		memset( repeated_counts, 0, sizeof( unsigned long ) * repeated_capacity );

		collect_processor_samples( samples );

		unsigned long sampled_processors = 0;
		unsigned long sample_detections = 0;
		auto nmi_samples = count_samples_by_source( *samples, sample_source_t::nmi_callback );
		auto ipi_samples = count_samples_by_source( *samples, sample_source_t::ipi_callback );
		auto interrupted_samples = count_interrupted_context_samples( *samples );

		for ( auto index = 0ul; index < m_max_processor_samples; index++ ) {
			auto sample = &samples->m_samples[ index ];
			if ( !sample->m_valid )
				continue;

			sampled_processors++;

			address_info_t info{ };
			query_address_info( modules, sample->m_rip, &info );
			if ( should_track_repeated_region( info ) )
				record_region( repeated_regions, repeated_counts, repeated_capacity, sample->m_rip );

			auto before = command->m_total_detection_count;
			add_address_classification_detection( command, sample_source_name( sample->m_source ), sample->m_processor, sample->m_rip, info, false );
			if ( command->m_total_detection_count != before )
				sample_detections++;

			for ( auto frame_idx = 0ul; frame_idx < sample->m_frame_count; frame_idx++ ) {
				auto candidate = sample->m_frames[ frame_idx ];
				if ( !candidate || candidate == sample->m_rip )
					continue;

				address_info_t frame_info{ };
				query_address_info( modules, candidate, &frame_info );
				if ( !is_probable_return_site( candidate, frame_info ) )
					continue;

				if ( should_track_repeated_region( frame_info ) )
					record_region( repeated_regions, repeated_counts, repeated_capacity, candidate );

				before = command->m_total_detection_count;
				add_address_classification_detection( command, "nmi_stack_frame", sample->m_processor, candidate, frame_info, true );
				if ( command->m_total_detection_count != before )
					sample_detections++;
			}
		}

		auto stack_detections = scan_stack_frames(
			command,
			modules,
			repeated_regions,
			repeated_counts,
			repeated_capacity
		);

		auto pivot_detections = scan_stack_bounds( command );
		auto thread_start_detections = execution::thread::scan( command, modules );
		auto repeated_detections = report_repeated_regions( command, repeated_regions, repeated_counts, repeated_capacity );

		memory::free_pool( repeated_counts );
		memory::free_pool( repeated_regions );
		memory::free_pool( samples );

		utility::print(
			"execution integrity: cpu_samples=%lu nmi_callback=%lu ipi_callback=%lu interrupted_context=%lu sample_detections=%lu stack_detections=%lu pivot_detections=%lu thread_start_detections=%lu repeated_detections=%lu detections=%lu\n",
			sampled_processors,
			nmi_samples,
			ipi_samples,
			interrupted_samples,
			sample_detections,
			stack_detections,
			pivot_detections,
			thread_start_detections,
			repeated_detections,
			command->m_total_detection_count
		);

		command->m_modules_scanned = modules->m_count;
		command->m_sections_scanned = sampled_processors;
		command->m_signature_detections = sample_detections + stack_detections + pivot_detections + thread_start_detections + repeated_detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		return true;
	}
}
