#pragma once
#include <includes.h>

struct scan_result_t {
	const char* m_name;
	driver::command_t m_command;
	std::vector< driver::detection_t > m_detections;
};

struct scan_entry_t {
	const char* m_name;
	const char* m_error;
	bool m_selected;
	bool ( driver::c_driver::* m_scan )( driver::command_t* );
};

bool contains_insensitive( const char* text, const char* pattern ) {
	if ( !text || !pattern )
		return false;

	for ( auto text_index = 0ul; text[ text_index ]; text_index++ ) {
		auto matched = true;
		for ( auto pattern_index = 0ul; pattern[ pattern_index ]; pattern_index++ ) {
			auto text_char = text[ text_index + pattern_index ];
			auto pattern_char = pattern[ pattern_index ];
			if ( !text_char ) {
				matched = false;
				break;
			}

			if ( text_char >= 'A' && text_char <= 'Z' )
				text_char += 'a' - 'A';

			if ( pattern_char >= 'A' && pattern_char <= 'Z' )
				pattern_char += 'a' - 'A';

			if ( text_char != pattern_char ) {
				matched = false;
				break;
			}
		}

		if ( matched )
			return true;
	}

	return false;
}

bool is_known_false_positive( const driver::detection_t& detection ) {
	if ( !contains_insensitive( detection.m_type, "world-writable named section" ) )
		return false;

	constexpr const char* benign_sections[] = {
		"section!FSyncSharedMemory",
		"section!{52813408-3561-4705-820a-2b3b78be92ba}",
		"section!EEU Memory Map",
		"section!242C35CFE1974E5AB3C65625F6B417DD"
	};
	for ( const auto section : benign_sections ) {
		if ( contains_insensitive( detection.m_target, section ) )
			return true;
	}

	return false;
}

const char* source_fix_for_detection( const driver::detection_t& detection ) {
	auto type = detection.m_type;

	if ( contains_insensitive( type, ".data function pointer" ) )
		return obf( "we detected a swapped kernel .data function pointer (KdEnumerateDebuggingDevices / SeValidateImageHeader / SeValidateImageData); restore original ntoskrnl/CI.dll pointers." );

	if ( contains_insensitive( type, "redirect" ) || contains_insensitive( type, "code section modified" ) )
		return obf( "your hooks shellcode was visible; use a rop chain or shadow paging to hide your shellcode." );

	if ( contains_insensitive( type, "export address table" ) || contains_insensitive( type, "import address table" ) )
		return obf( "we detected your modification to address tables; the rva was different from disk; use a inline hook." );

	if ( contains_insensitive( type, "writable executable" ) || contains_insensitive( type, "writable executable code" ) )
		return obf( "we detected writable executable code in code sections; avoid mapping executable memory into code sections or fix the permissions." );

	if ( contains_insensitive( type, "executable page in non-executable" ) )
		return obf( "we detected executable memory in a data-only image section; restore the section's NX permission." );

	if ( contains_insensitive( type, "image page is user accessible" ) )
		return obf( "we detected a kernel image page exposed to user mode; restore supervisor-only page permissions." );

	if ( contains_insensitive( type, "section mapped non-executable" ) )
		return obf( "we detected a code section with execution disabled; restore the image section's expected execute permission." );

	if ( contains_insensitive( type, "suspicious pfn" ) || contains_insensitive( type, "wrong pfn" ) || contains_insensitive( type, "backed by suspicious pfn" ) )
		return obf( "we detected a physical page with bad backing; avoid remapping or backing code with manual pages." );

	if ( contains_insensitive( type, "execution from unknown" ) || contains_insensitive( type, "unknown memory" ) || contains_insensitive( type, "anonymous kernel" ) )
		return obf( "we detected memory execution from unknown memory; do not execute from pools, indepedent pages, or any memory outside of loaded modules." );

	if ( contains_insensitive( type, "non-code section" ) || contains_insensitive( type, "outside executable section" ) )
		return obf( "we detected memory execution from code sections; do not execute from outside executable sections." );

	if ( contains_insensitive( type, "ktss64" ) )
		return obf( "we detected a tampered per-core KTSS64 Rsp0 or IST1-7 interrupt stack pointer; keep hardware TSS stack pointers in resident supervisor-only NX kernel memory." );

	if ( contains_insensitive( type, "stack pointer" ) || contains_insensitive( type, "stack owner chain" ) || contains_insensitive( type, "stack frame" ) )
		return obf( "we detected stack pivots and synthetic frames; keep normal call flow and unwindable frames inside trusted executable code." );

	if ( contains_insensitive( type, "spoofed start address" ) )
		return obf( "we detected a system thread with a spoofed _ETHREAD.StartAddress, cleared SystemThread DKOM flag, or active DR7 state; do not tamper ETHREAD fields." );

	if ( contains_insensitive( type, "thread start" ) )
		return obf( "we detected bad system threads; do not execute from outside executable sections or any memory outside of loaded modules." );

	if ( contains_insensitive( type, "physicalmemory section" ) || contains_insensitive( type, "kuser mapping" ) )
		return obf( "we detected a permissive \\Device\\PhysicalMemory DACL or writable/executable KUSER_SHARED_DATA PTE; restore default kernel security descriptors and read-only NX mappings." );

	if ( contains_insensitive( type, "kernel page mapped user" ) || contains_insensitive( type, "mapped into process" ) || contains_insensitive( type, "physical memory window" ) )
		return obf( "we detected kernel or physical memory mapped into user processes; keep kernel or physical memory outside of the process." );

	if ( contains_insensitive( type, "pfn database metadata" ) )
		return obf( "we detected spoofed MmPfnDatabase metadata (wiped _MMPFN.PteAddress, MiMakePageBad, or shadow PTE mismatch); do not wipe PFN entries or alias unbacked executable pages." );

	if ( contains_insensitive( type, "same pfn" ) || contains_insensitive( type, "page pfn" ) || contains_insensitive( type, "page walk" ) || contains_insensitive( type, "pml4" ) || contains_insensitive( type, "page table" ) )
		return obf( "we detected modified page tables; keep physical mappings consistent." );

	if ( contains_insensitive( type, "broad ioctl dispatch" ) )
		return obf( "we detected an IOCTL surface shaped like a memory-control driver; use minimal dispatch slots, a correct device type, and strict access checks." );

	if ( contains_insensitive( type, "world-writable named section" ) )
		return obf( "we detected a named section granting full access to everyone; use a restrictive DACL and grant only the section rights each client requires." );

	if ( contains_insensitive( type, "loaded module list entry" ) )
		return obf( "we detected a loaded-module entry that does not line up with a normal driver image/object; load the driver through the normal service path." );

	if ( contains_insensitive( type, "g_cioptions" ) )
		return obf( "we detected CI.dll!g_CiOptions DSE state tampering (disabled DSE or runtime-injected testsigning bit); restore original g_CiOptions immediately after driver load." );

	if ( contains_insensitive( type, "kernelhashbucketlist" ) )
		return obf( "we detected a blocked or tampered driver entry in CI.dll!g_KernelHashBucketList; clear vulnerable driver load traces without leaving zeroed hash buckets." );

	if ( contains_insensitive( type, "blocklist" ) || contains_insensitive( type, "vulnerable driver" ) )
		return obf( "we detected a vulnerable driver on Microsoft's blocklist; unload it and clear its traces from PiDDBCacheTable, MmUnloadedDrivers, and CI.dll!g_KernelHashBucketList." );

	if ( contains_insensitive( type, "piddbcachetable" ) || contains_insensitive( type, "mmunloadeddrivers" ) )
		return obf( "we detected driver load history traces or malformed entries in PiDDBCacheTable / MmUnloadedDrivers; sanitize the entry while preserving valid list links and timestamps." );

	if ( contains_insensitive( type, "registered nmi callback" ) )
		return obf( "we detected a rogue or anti-NMI blocker callback in KiNmiCallbackListHead; deregister unauthorized KeRegisterNmiCallback handlers." );

	if ( contains_insensitive( type, "bugcheck callback" ) )
		return obf( "we detected an unbacked KeBugCheckCallbackListHead or KeBugCheckReasonCallbackListHead routine; deregister unauthorized bugcheck callbacks." );

	if ( contains_insensitive( type, "object type initializer" ) )
		return obf( "we detected a hooked _OBJECT_TYPE_INITIALIZER procedure in ObTypeIndexTable (Open/Close/Delete/ParseProcedure); restore unmodified object type procedures." );

	if ( contains_insensitive( type, "kernel notify" ) || contains_insensitive( type, "object callback" ) )
		return obf( "we detected a process/thread/image notify routine, registry callback, or ObRegisterCallbacks handler pointing outside signed modules; register callbacks only inside backed driver code." );

	if ( contains_insensitive( type, "hwid dispatch" ) )
		return obf( "we detected a redirected or inline-hooked storage, SMBIOS, or network HWID dispatch handler (disk/partmgr/mountmgr/stornvme/nsiproxy); restore clean MajorFunction routines." );

	if ( contains_insensitive( type, "filter handler" ) )
		return obf( "we detected an unbacked FLTMGR minifilter, filesystem, PCI, or NDIS filter handler attached to a kernel stack; detach unauthorized filters and restore backed callbacks." );

	if ( contains_insensitive( type, "wmi logger getcpuclock" ) )
		return obf( "we detected an InfinityHook-style _WMI_LOGGER_CONTEXT.GetCpuClock function pointer swap in WmipLoggerContext; restore the default ETW clock routine." );

	if ( contains_insensitive( type, "etw threat intelligence" ) )
		return obf( "we detected tampering or blinding on EtwThreatIntProvRegHandle; restore the intact ETW Threat Intelligence registration state." );

	if ( contains_insensitive( type, "ssdt" ) )
		return obf( "we detected a KeServiceDescriptorTable or Win32k W32pServiceTable SSDT entry pointing outside system modules or patched with an inline hook; restore clean service tables." );

	if ( contains_insensitive( type, "hal dispatch" ) )
		return obf( "we detected a modified HalDispatchTable or HalPrivateDispatchTable pointer; restore all HAL dispatch pointers to trusted system modules." );

	if ( contains_insensitive( type, "patchguard" ) || contains_insensitive( type, "kernel debug" ) )
		return obf( "we detected PatchGuard or kernel debugger state tampering (KdDebuggerNotPresent / KeBugCheckEx / timer keys); restore unmodified kernel state." );

	if ( contains_insensitive( type, "security control register" ) )
		return obf( "we detected disabled CPU security bits (CR0.WP, CR4.SMEP, or IA32_EFER.NXE); keep hardware write-protect, SMEP, and NX protections enabled across all cores." );

	if ( contains_insensitive( type, "hardware debug breakpoint" ) )
		return obf( "we detected active kernel hardware debug registers (DR0-DR3 / DR7); clear hardware breakpoints on all logical processors." );

	if ( contains_insensitive( type, "hypervisor" ) || contains_insensitive( type, "tsc discrepancy" ) )
		return obf( "we detected stealth hypervisor VM-exit timing, ALU-vs-CPUID TSC_OFFSET over-subtraction, leaked CPUID 0x40000000 leaf, or unshadowed CR4.VMXE / EFER.SVME bits." );

	if ( contains_insensitive( type, "dispatch" ) || contains_insensitive( type, "device object" ) || contains_insensitive( type, "driver object" ) )
		return obf( "we detected modified driver/device objects; keep dispatch pointers inside the owning driver's executable sections." );

	if ( contains_insensitive( type, "syscall" ) || contains_insensitive( type, "service routine" ) || contains_insensitive( type, "idt handler" ) || contains_insensitive( type, "processor msr" ) )
		return obf( "we detected modified service tables; keep the service pointers inside of ntoskrnl's executable sections." );

	if ( contains_insensitive( type, "dpc" ) || contains_insensitive( type, "timer" ) )
		return obf( "we detected a DPC or KTIMER routine pointing outside trusted code; avoid queuing DPCs or periodic timers into unbacked memory." );

	if ( contains_insensitive( type, "pool" ) )
		return obf( "we detected allocated pools; avoid allocating executable pools." );

	if ( contains_insensitive( type, "cid table" ) || contains_insensitive( type, "thread hidden" ) || contains_insensitive( type, "orphan process" ) )
		return obf( "we detected unlinked process/thread objects; don't tamper threads or processes." );

	return obf( "" );
}

bool unload_handler( std::uint32_t signal ) {
	g_driver->close( );
	g_service->unload( );
	g_overlay->stop( );
	return true;
}

int wmain( int argc, wchar_t** argv ) {
    utility::enable_utf8( );
    utility::print( obf( "[ + ]" ), obf( "downloading Microsoft vulnerable-driver blocklist" ) );
    std::string blocklist_error;
    if ( !blocklist::download_and_parse( blocklist::g_policy, &blocklist_error ) ) {
        utility::print(
            obf( "[ - ]" ),
            obf( "failed to initialize vulnerable-driver blocklist: %s" ),
            blocklist_error.c_str( )
        );
    }
    else {
        utility::print(
            obf( "[ + ]" ),
            obf( "parsed %zu blocked-driver rules (policy %s)" ),
            blocklist::g_policy.rules.size( ),
            blocklist::g_policy.version.c_str( )
        );
    }
	std::wstring driver_path;
	if ( argc >= 2 && argv[ 1 ] && argv[ 1 ][ 0 ] ) {
		wchar_t full_path[ MAX_PATH ]{};
		if ( GetFullPathNameW( argv[ 1 ], MAX_PATH, full_path, nullptr ) )
			driver_path = full_path;
		else
			driver_path = argv[ 1 ];
	}
	else {
		wchar_t exe_file[ MAX_PATH ]{};
		if ( GetModuleFileNameW( nullptr, exe_file, MAX_PATH ) ) {
			std::wstring candidate( exe_file );
			const auto sep = candidate.find_last_of( L"\\/" );
			if ( sep != std::wstring::npos )
				candidate.resize( sep + 1 );
			candidate += L"ude-driver.sys";
			if ( GetFileAttributesW( candidate.c_str( ) ) != INVALID_FILE_ATTRIBUTES )
				driver_path = std::move( candidate );
		}
	}
	render::widgets::stages::set_dashboard_driver_path( driver_path );

	if ( !g_overlay->start( render::draw_callback ) ) {
		utility::print( obf( "[ - ]" ), obf( "failed to initialize renderer\n" ) );
		return std::getchar( );
	}

	SetConsoleTitleA( obf( "undetected-easy" ) );
	SetConsoleCtrlHandler(
		reinterpret_cast< PHANDLER_ROUTINE >( unload_handler ),
		true
	);

	using setup_state = render::widgets::stages::dashboard_setup_state;
	for ( ;; ) {
		if ( !g_overlay->running( ) )
			return 0;

		const auto state = render::widgets::stages::g_dashboard_setup_state.load( );
		if ( state == setup_state::success )
			break;

		std::this_thread::sleep_for( std::chrono::milliseconds( 16 ) );
	}

	std::thread( [ ] {
		auto previous_count = static_cast< std::size_t >( -1 );
		std::unordered_set< std::string > printed_names;
		while ( g_overlay->running( ) ) {
			std::vector< std::string > blocked_drivers;
			if ( g_driver->query_blocked_drivers( blocked_drivers ) &&
				blocked_drivers.size( ) != previous_count ) {
				utility::print(
					obf( "[ ! ]" ),
					obf( "blocked drivers loaded: %zu" ),
					blocked_drivers.size( )
				);
				for ( const auto& name : blocked_drivers ) {
					if ( printed_names.insert( name ).second )
						utility::print( obf( "[ ! ]" ), obf( "blocked driver: %s" ), name.c_str( ) );
				}
				previous_count = blocked_drivers.size( );
			}
			std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
		}
	} ).detach( );

	auto print_detection = [ ]( const driver::detection_t& detection ) {
		utility::print( obf( "[ ! ]" ), obf( "target: %s" ), detection.m_target );
		utility::print( obf( "[ ! ]" ), obf( "type: %s" ), detection.m_type );
		utility::print( obf( "[ ! ]" ), obf( "method: %s" ), detection.m_method );
		utility::print(
			obf( "[ ! ]" ),
			obf( "address: 0x%llx size: 0x%x status: 0x%lx\n" ),
			detection.m_address,
			detection.m_size,
			detection.m_error
		);
		};

	auto collect_detection_snapshot = [ & ]( driver::command_t& command, std::vector< driver::detection_t >& detections, const std::function< void( unsigned long, unsigned long ) >& update_progress ) {
		auto fetched_count = command.m_detection_count;
		for ( auto index = 0ul; index < command.m_detection_count; index++ ) {
			if ( !is_known_false_positive( command.m_detections[ index ] ) )
				detections.push_back( command.m_detections[ index ] );
		}

		update_progress( fetched_count, command.m_total_detection_count );

		auto next_offset = command.m_detection_offset + command.m_detection_count;
		while ( command.m_has_more_detections && next_offset < command.m_total_detection_count ) {
			auto page_command = std::make_unique< driver::command_t >( );
			if ( !page_command || !g_driver->fetch_detections( page_command.get( ), next_offset, command.m_detection_session ) ) {
				printf( "\n" );
				utility::print( obf( "[ - ]" ), obf( "failed to fetch detection page at %lu" ), next_offset );
				return false;
			}

			for ( auto index = 0ul; index < page_command->m_detection_count; index++ ) {
				if ( !is_known_false_positive( page_command->m_detections[ index ] ) )
					detections.push_back( page_command->m_detections[ index ] );
			}
			fetched_count += page_command->m_detection_count;

			update_progress( fetched_count, command.m_total_detection_count );

			next_offset = page_command->m_detection_offset + page_command->m_detection_count;
			command.m_has_more_detections = page_command->m_has_more_detections;
		}

		return true;
		};

	scan_entry_t scans[ ] = {
		{ obf( "module integrity" ), obf( "failed to run module integrity check" ), true, &driver::c_driver::module_integrity },
		{ obf( "execution integrity" ), obf( "failed to run execution integrity check" ), true, &driver::c_driver::execution_integrity },
		{ obf( "memory integrity" ), obf( "failed to run memory integrity check" ), true, &driver::c_driver::memory_integrity },
		{ obf( "process integrity" ), obf( "failed to run process integrity check" ), true, &driver::c_driver::process_integrity },
		{ obf( "pool integrity" ), obf( "failed to run pool integrity check" ), true, &driver::c_driver::pool_integrity },
		{ obf( "device surface" ), obf( "failed to run device surface check" ), true, &driver::c_driver::device_surface },
		{ obf( "service integrity" ), obf( "failed to run service integrity check" ), true, &driver::c_driver::service_integrity },
		{ obf( "cpu integrity" ), obf( "failed to run cpu integrity check" ), true, &driver::c_driver::cpu_integrity },
		{ obf( "object integrity" ), obf( "failed to run object integrity check" ), true, &driver::c_driver::object_integrity },
		{ obf( "dpc integrity" ), obf( "failed to run dpc integrity check" ), true, &driver::c_driver::dpc_integrity }
	};

	constexpr auto scan_count = sizeof( scans ) / sizeof( scans[ 0 ] );

	auto selected_count = [ & ]( ) {
		auto count = 0ul;
		for ( auto index = 0ul; index < scan_count; index++ ) {
			if ( scans[ index ].m_selected )
				count++;
		}

		return count;
		};

	while ( g_overlay->running( ) &&
		!render::widgets::stages::g_dashboard_scan_selection_submitted.load( ) )
		std::this_thread::sleep_for( std::chrono::milliseconds( 16 ) );

	if ( !g_overlay->running( ) ) {
		g_driver->close( );
		g_service->unload( );
		return 0;
	}

	for ( auto index = 0ul; index < scan_count; ++index )
		scans[ index ].m_selected =
			render::widgets::stages::g_dashboard_scan_selected[ index ].load( );
	render::widgets::stages::g_dashboard_scan_progress.store( 0.0f );
	render::widgets::stages::g_dashboard_detection_count.store( 0 );
	render::widgets::stages::g_dashboard_scan_complete.store( false );
	render::widgets::stages::g_dashboard_scan_started_ms.store(
		std::chrono::duration_cast< std::chrono::milliseconds >(
			std::chrono::steady_clock::now( ).time_since_epoch( )
		).count( )
	);

	auto cleanup = [ ]( ) {
		g_driver->close( );
		g_service->unload( );
		};

	std::vector< scan_result_t > scan_results;
	auto selected_total = selected_count( );
	auto completed_scans = 0ul;
	auto detections_found = 0ul;

	utility::print_line(
		obf( "[ + ]" ),
		obf( "searching for detections... %.1f%% done" ),
		0.0f
	);

	for ( auto index = 0ul; index < scan_count; index++ ) {
		if ( !scans[ index ].m_selected )
			continue;

		driver::command_t command{ };
		std::atomic_bool scan_finished = false;
		auto scan_succeeded = false;
		auto scan_start = std::chrono::steady_clock::now( );
		std::thread scan_thread( [ & ]( ) {
			scan_succeeded = ( g_driver.get( )->*scans[ index ].m_scan )( &command );
			scan_finished.store( true );
			} );

		auto scan_base = ( static_cast< float >( completed_scans ) * 100.0f ) / static_cast< float >( selected_total );
		auto scan_span = 100.0f / static_cast< float >( selected_total );

		while ( !scan_finished.load( ) ) {
			auto elapsed = std::chrono::duration_cast< std::chrono::milliseconds >( std::chrono::steady_clock::now( ) - scan_start ).count( );
			auto elapsed_progress = static_cast< float >( elapsed ) / ( static_cast< float >( elapsed ) + 10000.0f );
			auto scan_progress = elapsed_progress * 0.99f;

			const auto overall_progress = scan_base + ( scan_span * scan_progress );
			render::widgets::stages::g_dashboard_scan_progress.store( overall_progress );
			utility::print_line(
				obf( "[ + ]" ),
				obf( "searching for detections... %.1f%% done" ),
				overall_progress
			);

			std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
		}

		scan_thread.join( );

		if ( !scan_succeeded ) {
			printf( "\n" );
			utility::print( obf( "[ - ]" ), scans[ index ].m_error );
			cleanup( );
			return false;
		}

		scan_result_t result{ };
		result.m_name = scans[ index ].m_name;
		result.m_command = command;
		render::widgets::stages::g_dashboard_detection_count.store( detections_found );

		auto update_fetch_progress = [ & ]( unsigned long current, unsigned long maximum ) {
			auto detection_progress = 1.0f;
			if ( maximum )
				detection_progress = static_cast< float >( current ) / static_cast< float >( maximum );

			if ( detection_progress > 1.0f )
				detection_progress = 1.0f;

			const auto overall_progress =
				scan_base + ( scan_span * ( 0.99f + ( detection_progress * 0.01f ) ) );
			render::widgets::stages::g_dashboard_scan_progress.store( overall_progress );
			render::widgets::stages::g_dashboard_detection_count.store(
				detections_found + static_cast< unsigned long >( result.m_detections.size( ) )
			);
			utility::print_line(
				obf( "[ + ]" ),
				obf( "searching for detections... %.1f%% done" ),
				overall_progress
			);
			};

		if ( !collect_detection_snapshot( command, result.m_detections, update_fetch_progress ) ) {
			cleanup( );
			return false;
		}
		command.m_total_detection_count = static_cast< unsigned long >( result.m_detections.size( ) );
		result.m_command.m_total_detection_count = command.m_total_detection_count;
		result.m_command.m_detection_count = ( std::min )(
			result.m_command.m_detection_count,
			result.m_command.m_total_detection_count
		);

		completed_scans++;
		detections_found += command.m_total_detection_count;
		const auto completed_progress =
			( static_cast< float >( completed_scans ) * 100.0f ) / static_cast< float >( selected_total );
		render::widgets::stages::g_dashboard_scan_progress.store( completed_progress );
		render::widgets::stages::g_dashboard_detection_count.store( detections_found );
		utility::print_line(
			obf( "[ + ]" ),
			obf( "searching for detections... %.1f%% done" ),
			completed_progress
		);

		scan_results.push_back( std::move( result ) );
	}

	utility::print_line(
		obf( "[ + ]" ),
		obf( "searching for detections... %.1f%% done!\n\n" ),
		100.0f
	);
	render::widgets::stages::g_dashboard_scan_progress.store( 100.0f );
	render::widgets::stages::g_dashboard_detection_count.store( detections_found );
	std::vector< render::widgets::stages::dashboard_detection_result > dashboard_results;
	auto widen_ascii = [ ]( const char* value ) {
		std::wstring result;
		if ( value ) {
			while ( *value )
				result.push_back( static_cast< unsigned char >( *value++ ) );
		}
		return result;
	};
	for ( const auto& result : scan_results ) {
		auto title = widen_ascii( result.m_name );
		if ( !title.empty( ) && title.front( ) >= L'a' && title.front( ) <= L'z' )
			title.front( ) -= L'a' - L'A';
		std::vector< std::wstring > reasons;
		for ( const auto& detection : result.m_detections ) {
			const auto fix = source_fix_for_detection( detection );
			if ( fix && fix[ 0 ] ) {
				auto reason = title;
				reason += L": ";
				reason += widen_ascii( fix );
				if ( std::find( reasons.begin( ), reasons.end( ), reason ) == reasons.end( ) )
					reasons.push_back( std::move( reason ) );
			}
		}
		const auto detected = result.m_command.m_total_detection_count != 0;
		if ( detected && reasons.empty( ) )
			reasons.push_back(
				title + L": Review the reported detection details and correct the affected integrity check."
			);
		dashboard_results.push_back( { std::move( title ), detected, std::move( reasons ) } );
	}
	wchar_t module_path[ MAX_PATH ]{ };
	const auto module_length = GetModuleFileNameW( nullptr, module_path, MAX_PATH );
	std::wstring detection_log_path( module_path, module_length );
	const auto path_separator = detection_log_path.find_last_of( L"\\/" );
	if ( path_separator != std::wstring::npos )
		detection_log_path.resize( path_separator + 1 );
	detection_log_path += L"ude-log.txt";
	FILE* detection_log = nullptr;
	if ( _wfopen_s( &detection_log, detection_log_path.c_str( ), L"at, ccs=UTF-8" ) == 0 && detection_log ) {
		fwprintf( detection_log, L"\n\n[Scan results]\nDetections found: %lu\n", detections_found );
		for ( const auto& result : scan_results ) {
			if ( !result.m_command.m_total_detection_count )
				continue;
			fwprintf(
				detection_log,
				L"\n[%hs] total=%lu dropped=%lu\n",
				result.m_name,
				result.m_command.m_total_detection_count,
				result.m_command.m_detection_dropped_count
			);
			for ( const auto& detection : result.m_detections ) {
				fwprintf(
					detection_log,
					L"type=%hs | method=%hs | address=0x%llx | size=0x%x | status=0x%lx\n",
					detection.m_type,
					detection.m_method,
					detection.m_address,
					detection.m_size,
					detection.m_error
				);
				const auto fix = source_fix_for_detection( detection );
				if ( fix && fix[ 0 ] )
					fwprintf( detection_log, L"fix=%hs\n", fix );
			}
		}
		fclose( detection_log );
	}
	render::widgets::stages::set_dashboard_results( std::move( dashboard_results ) );
	render::widgets::stages::g_dashboard_scan_complete.store( true );

	auto total_detections = 0ul;
	auto total_dropped = 0ul;
	auto detected_scans = 0ul;
	auto capped_scans = 0ul;

	for ( auto& result : scan_results ) {
		total_detections += result.m_command.m_total_detection_count;
		total_dropped += result.m_command.m_detection_dropped_count;

		if ( result.m_command.m_total_detection_count )
			detected_scans++;

		if ( result.m_command.m_total_detection_count >= scan_count || result.m_command.m_detection_dropped_count )
			capped_scans++;
	}

	auto maximum_detections = selected_total * scan_count;
	auto total_detection_ratio = maximum_detections > 0
		? static_cast< float >( total_detections ) / static_cast< float >( maximum_detections )
		: 0.0f;

	auto status = obf( "undetected" );
	auto status_prefix = obf( "[ + ]" );

	if ( total_detections > 0 ) {
		auto fully_detected = ( capped_scans >= selected_total )
			|| ( total_detection_ratio >= 0.65f && total_dropped > 0 );

		if ( fully_detected ) {
			status = obf( "fully-detected" );
			status_prefix = obf( "[ ! ]" );
		}
		else {
			status = obf( "detected" );
			status_prefix = obf( "[ ! ]" );
		}
	}

	utility::print(
		status_prefix,
		obf( "your project is %s." ),
		status
	);

	if ( detected_scans ) {
		utility::print(
			status_prefix,
			obf( "we caught %lu/%lu detections from your project:" ),
			detected_scans,
			scan_count
		);

		std::vector< const char* > printed_fixes;

		auto index = 1ul;
		for ( auto& result : scan_results ) {
			for ( auto& detection : result.m_detections ) {
				auto fix = source_fix_for_detection( detection );

				if ( !fix || !fix[ 0 ] )
					continue;

				auto already_printed = false;
				for ( auto& printed : printed_fixes ) {
					if ( strcmp( printed, fix ) == 0 ) {
						already_printed = true;
						break;
					}
				}

				if ( already_printed )
					continue;

				printed_fixes.push_back( fix );
				utility::debug_status(
					obf( "[ * ]" ),
					obf( "%lu. %s" ),
					index++,
					fix
				);
			}
		}

		printf( obf( "\n" ) );
		utility::print( status_prefix, obf( "detection dump:" ) );

		for ( auto& result : scan_results ) {
			for ( auto& detection : result.m_detections )
				print_detection( detection );
		}
	}

	g_driver->close( );
	g_service->unload( );
	utility::print( obf( "[ - ]" ), obf( "unloaded service" ) );
	return std::getchar( );
}
