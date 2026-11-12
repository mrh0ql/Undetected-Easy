#pragma once

namespace device_surface::dispatch {
	const char* major_name( unsigned long index ) {
		switch ( index ) {
		case IRP_MJ_CREATE:
			return "create";
		case IRP_MJ_CLOSE:
			return "close";
		case IRP_MJ_READ:
			return "read";
		case IRP_MJ_WRITE:
			return "write";
		case IRP_MJ_DEVICE_CONTROL:
			return "device_control";
		case IRP_MJ_INTERNAL_DEVICE_CONTROL:
			return "internal_device_control";
		case IRP_MJ_PNP:
			return "pnp";
		case IRP_MJ_POWER:
			return "power";
		default:
			return "major";
		}
	}

	bool is_same_module( const system_module_t* left, const system_module_t* right ) {
		return left && right && left->m_image_base == right->m_image_base;
	}

	unsigned long report_target( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* owner_module, const char* driver_name, const char* slot_name, void* function ) {
		if ( !command || !modules || !function )
			return 0;

		UNREFERENCED_PARAMETER( owner_module );

		auto address = reinterpret_cast< unsigned long long >( function );
		if ( !memory::is_canonical_kernel_address( address ) )
			return 0;

		target_info_t info{ };
		query_target_info( modules, address, &info );

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA( target, sizeof( target ), "%s!%s", driver_name ? driver_name : "driver", slot_name ? slot_name : "dispatch" );

		if ( !info.m_owner || !info.m_executable ) {
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"slot=%s target=0x%llx owner=%s section=%s pfn=0x%llx",
				slot_name ? slot_name : "dispatch",
				address,
				info.m_owner ? info.m_owner : "unknown",
				info.m_section[ 0 ] ? info.m_section : "unknown",
				info.m_pfn
			);

			report::add_memory_detection(
				command,
				target,
				info.m_owner ? report::m_dispatch_outside_owner_violation : report::m_dispatch_unknown_target_violation,
				detail,
				address,
				sizeof( void* )
			);
			return 1;
		}

		if ( info.m_bad_backing ) {
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"slot=%s target=0x%llx pfn=0x%llx walk_pa=0x%llx api_pa=0x%llx user=%u nx=%u",
				slot_name ? slot_name : "dispatch",
				address,
				info.m_pfn,
				info.m_walk_pa,
				info.m_api_pa,
				static_cast< unsigned long >( info.m_user ),
				static_cast< unsigned long >( info.m_nx )
			);

			report::add_memory_detection( command, target, report::m_dispatch_bad_pfn_violation, detail, address, PAGE_SIZE );
			return 1;
		}

		if ( info.m_writable && info.m_executable ) {
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"slot=%s target=0x%llx owner=%s section=%s pfn=0x%llx",
				slot_name ? slot_name : "dispatch",
				address,
				info.m_owner ? info.m_owner : "unknown",
				info.m_section[ 0 ] ? info.m_section : "unknown",
				info.m_pfn
			);

			report::add_memory_detection( command, target, report::m_dispatch_writable_executable_violation, detail, address, PAGE_SIZE );
			return 1;
		}

		return 0;
	}

	unsigned long scan_major_functions( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* owner_module, PDRIVER_OBJECT driver_object, const char* driver_name ) {
		unsigned long detections = 0;
		for ( auto index = 0ul; index <= IRP_MJ_MAXIMUM_FUNCTION; index++ ) {
			char slot[ 32 ]{ };
			RtlStringCbPrintfA( slot, sizeof( slot ), "mj_%s_%lu", major_name( index ), index );
			detections += report_target( command, modules, owner_module, driver_name, slot, reinterpret_cast< void* >( driver_object->MajorFunction[ index ] ) );
		}

		detections += report_target( command, modules, owner_module, driver_name, "driver_init", reinterpret_cast< void* >( driver_object->DriverInit ) );
		detections += report_target( command, modules, owner_module, driver_name, "driver_unload", reinterpret_cast< void* >( driver_object->DriverUnload ) );
		detections += report_target( command, modules, owner_module, driver_name, "add_device", reinterpret_cast< void* >( driver_object->DriverExtension ? driver_object->DriverExtension->AddDevice : nullptr ) );
		return detections;
	}

	unsigned long scan_fast_io( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* owner_module, PDRIVER_OBJECT driver_object, const char* driver_name ) {
		if ( !driver_object || !driver_object->FastIoDispatch )
			return 0;

		auto fast = driver_object->FastIoDispatch;
		unsigned long detections = 0;
		detections += report_target( command, modules, owner_module, driver_name, "fast_check", reinterpret_cast< void* >( fast->FastIoCheckIfPossible ) );
		detections += report_target( command, modules, owner_module, driver_name, "fast_read", reinterpret_cast< void* >( fast->FastIoRead ) );
		detections += report_target( command, modules, owner_module, driver_name, "fast_write", reinterpret_cast< void* >( fast->FastIoWrite ) );
		detections += report_target( command, modules, owner_module, driver_name, "fast_ioctl", reinterpret_cast< void* >( fast->FastIoDeviceControl ) );
		return detections;
	}

	unsigned long scan_ioctl_shape( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* owner_module, PDRIVER_OBJECT driver_object, const char* driver_name ) {
		if ( !command || !driver_object || !driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] )
			return 0;

		target_info_t info{ };
		auto device_control = reinterpret_cast< unsigned long long >(
			driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] );
		query_target_info( modules, device_control, &info );

		if ( !info.m_module || detections::is_suspicious_external_target( modules, info.m_module, device_control ) ) {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"device_control=0x%llx module=%s section=%s",
				device_control,
				info.m_owner ? info.m_owner : "unknown",
				info.m_section[ 0 ] ? info.m_section : "unknown"
			);

			report::add_memory_detection(
				command,
				driver_name ? driver_name : "driver!ioctl",
				report::m_ioctl_dispatch_surface_violation,
				detail,
				device_control,
				sizeof( void* )
			);
			return 1;
		}


		//unsigned long shared_dispatch_slots = 0;
		//for ( auto index = 0ul; index <= IRP_MJ_MAXIMUM_FUNCTION; index++ ) {
		//	if ( driver_object->MajorFunction[ index ] == ioctl_target )
		//		shared_dispatch_slots++;
		//}

		//bool has_buffered_device = false;
		//bool has_network_device = false;
		//unsigned long device_count = 0;
		//for ( auto device = driver_object->DeviceObject; device && device_count < 64; device = device->NextDevice, device_count++ ) {
		//	if ( device->Flags & DO_BUFFERED_IO )
		//		has_buffered_device = true;

		//	if ( device->DeviceType == FILE_DEVICE_NETWORK )
		//		has_network_device = true;
		//}

		//if ( shared_dispatch_slots < 20 || !has_buffered_device )
		//	return 0;

		//bool owner_local_dispatch = owner_module && is_same_module( owner_module, info.m_module );
		////bool nearly_all_slots_shared = shared_dispatch_slots >= IRP_MJ_MAXIMUM_FUNCTION;
		//if ( /*owner_local_dispatch && has_network_device &&*/ info.m_executable && !info.m_bad_backing ) {
			//char detail[ ioctl::m_detection_text_size ]{ };
			//RtlStringCbPrintfA(
			//	detail,
			//	sizeof( detail ),
			//	"device_control=0x%llx shared_slots=%lu devices=%lu buffered=%u network_type=%u owner=%s section=%s reason=owner_local_broad_network_ioctl",
			//	reinterpret_cast< unsigned long long >( ioctl_target ),
			//	shared_dispatch_slots,
			//	device_count,
			//	has_buffered_device ? 1ul : 0ul,
			//	has_network_device ? 1ul : 0ul,
			//	info.m_owner ? info.m_owner : "unknown",
			//	info.m_section[ 0 ] ? info.m_section : "unknown"
			//);

			//report::add_memory_detection(
			//	command,
			//	driver_name ? driver_name : "driver!ioctl",
			//	report::m_ioctl_dispatch_surface_violation,
			//	detail,
			//	reinterpret_cast< unsigned long long >( ioctl_target ),
			//	sizeof( void* )
			//);
			//return 1;
		//}

		//if ( owner_module && is_same_module( owner_module, info.m_module ) && info.m_executable && !info.m_bad_backing )
		//	return 0;

		//if ( owner_module && info.m_module && is_system_module_path( info.m_module ) && info.m_executable && !info.m_bad_backing )
		//	return 0;

		//char detail[ ioctl::m_detection_text_size ]{ };
		//RtlStringCbPrintfA(
		//	detail,
		//	sizeof( detail ),
		//	"device_control=0x%llx shared_slots=%lu devices=%lu buffered=%u network_type=%u owner=%s section=%s loaded_owner=%u",
		//	reinterpret_cast< unsigned long long >( ioctl_target ),
		//	shared_dispatch_slots,
		//	device_count,
		//	has_buffered_device ? 1ul : 0ul,
		//	has_network_device ? 1ul : 0ul,
		//	info.m_owner ? info.m_owner : "unknown",
		//	info.m_section[ 0 ] ? info.m_section : "unknown",
		//	owner_module ? 1ul : 0ul
		//);

		//report::add_memory_detection(
		//	command,
		//	driver_name ? driver_name : "driver!ioctl",
		//	report::m_ioctl_dispatch_surface_violation,
		//	detail,
		//	reinterpret_cast< unsigned long long >( ioctl_target ),
		//	sizeof( void* )
		//);
		return 1;
	}
}

namespace device_surface {
	bool already_scanned_driver( PDRIVER_OBJECT* scanned, unsigned long count, PDRIVER_OBJECT driver_object ) {
		if ( !scanned || !driver_object )
			return false;

		for ( auto index = 0ul; index < count; index++ ) {
			if ( scanned[ index ] == driver_object )
				return true;
		}

		return false;
	}

	void remember_scanned_driver( PDRIVER_OBJECT* scanned, unsigned long* count, PDRIVER_OBJECT driver_object ) {
		if ( !scanned || !count || !driver_object || *count >= 512 )
			return;

		if ( already_scanned_driver( scanned, *count, driver_object ) )
			return;

		scanned[ ( *count )++ ] = driver_object;
	}

	bool driver_object_matches_module( PDRIVER_OBJECT driver_object, const system_module_t* module ) {
		if ( !driver_object || !module )
			return false;

		auto driver_start = reinterpret_cast< unsigned long long >( driver_object->DriverStart );
		auto module_start = reinterpret_cast< unsigned long long >( module->m_image_base );
		return driver_start == module_start && driver_object->DriverSize == module->m_image_size;
	}

	unsigned long report_driver_object_mismatch( ioctl::command_t* command, PDRIVER_OBJECT driver_object, const system_module_t* module, const char* driver_name ) {
		if ( !command || !driver_object || !module )
			return 0;

		if ( driver_object_matches_module( driver_object, module ) )
			return 0;

		if ( !driver_object->DriverSize )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"driver_start=0x%llx driver_size=0x%lx module_base=0x%llx module_size=0x%lx",
			reinterpret_cast< unsigned long long >( driver_object->DriverStart ),
			driver_object->DriverSize,
			reinterpret_cast< unsigned long long >( module->m_image_base ),
			module->m_image_size
		);

		report::add_memory_detection(
			command,
			driver_name ? driver_name : "driver",
			report::m_driver_object_mismatch_violation,
			detail,
			reinterpret_cast< unsigned long long >( driver_object ),
			sizeof( DRIVER_OBJECT )
		);
		return 1;
	}

	unsigned long report_driver_section_mismatch( ioctl::command_t* command, PDRIVER_OBJECT driver_object, const system_module_t* module, const char* driver_name, const char* reason ) {
		if ( !command || !driver_object )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"driver=0x%llx section=0x%llx start=0x%llx size=0x%lx module_base=0x%llx module_size=0x%lx reason=%s",
			reinterpret_cast< unsigned long long >( driver_object ),
			reinterpret_cast< unsigned long long >( driver_object->DriverSection ),
			reinterpret_cast< unsigned long long >( driver_object->DriverStart ),
			driver_object->DriverSize,
			module ? reinterpret_cast< unsigned long long >( module->m_image_base ) : 0ull,
			module ? module->m_image_size : 0ul,
			reason ? reason : "driver section consistency"
		);

		report::add_memory_detection(
			command,
			driver_name ? driver_name : "driver",
			report::m_loaded_module_list_entry_violation,
			detail,
			reinterpret_cast< unsigned long long >( driver_object ),
			sizeof( DRIVER_OBJECT )
		);
		return 1;
	}

	unsigned long scan_driver_section( ioctl::command_t* command, PDRIVER_OBJECT driver_object, const system_module_t* module, const char* driver_name ) {
		if ( !command || !driver_object )
			return 0;

		if ( module && is_system_module_path( module ) )
			return 0;

		if ( !driver_object->DriverSection )
			return report_driver_section_mismatch( command, driver_object, module, driver_name, "driver object has no loader section" );

		loader_module_entry_t entry{ };
		if ( !read_loader_entry( static_cast< LIST_ENTRY* >( driver_object->DriverSection ), &entry ) )
			return report_driver_section_mismatch( command, driver_object, module, driver_name, "driver section is not readable loader entry" );

		auto section_base = reinterpret_cast< unsigned long long >( entry.m_dll_base );
		auto driver_start = reinterpret_cast< unsigned long long >( driver_object->DriverStart );
		auto module_base = module ? reinterpret_cast< unsigned long long >( module->m_image_base ) : 0ull;
		if ( driver_start && section_base && section_base != driver_start )
			return report_driver_section_mismatch( command, driver_object, module, driver_name, "driver section base disagrees with driver start" );

		if ( module_base && section_base && section_base != module_base )
			return report_driver_section_mismatch( command, driver_object, module, driver_name, "driver section base disagrees with module query" );

		if ( driver_object->DriverSize && entry.m_size_of_image && driver_object->DriverSize != entry.m_size_of_image )
			return report_driver_section_mismatch( command, driver_object, module, driver_name, "driver section size disagrees with driver object" );

		if ( module && entry.m_size_of_image && module->m_image_size != entry.m_size_of_image )
			return report_driver_section_mismatch( command, driver_object, module, driver_name, "driver section size disagrees with module query" );

		return 0;
	}

	unsigned long report_loaded_module_entry( ioctl::command_t* command, const system_module_t* module, const char* driver_name, const char* reason ) {
		if ( !command || !module )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"module=%s base=0x%llx size=0x%lx mapped=0x%llx flags=0x%lx reason=%s",
			reinterpret_cast< const char* >( module->m_full_path_name ) + module->m_offset_to_file_name,
			reinterpret_cast< unsigned long long >( module->m_image_base ),
			module->m_image_size,
			reinterpret_cast< unsigned long long >( module->m_mapped_base ),
			module->m_flags,
			reason ? reason : "module list consistency"
		);

		report::add_memory_detection(
			command,
			driver_name ? driver_name : "module",
			report::m_loaded_module_list_entry_violation,
			detail,
			reinterpret_cast< unsigned long long >( module->m_image_base ),
			module->m_image_size ? module->m_image_size : PAGE_SIZE
		);
		return 1;
	}

	unsigned long scan_module_list_entry( ioctl::command_t* command, const system_module_t* module, const char* driver_name, PDRIVER_OBJECT driver_object ) {
		if ( !command || !module || !module->m_image_base )
			return 0;

		UNREFERENCED_PARAMETER( driver_name );
		UNREFERENCED_PARAMETER( driver_object );

		auto module_name = reinterpret_cast< const char* >( module->m_full_path_name ) + module->m_offset_to_file_name;
		if ( module::disk::is_whitelisted_owner( module_name ) )
			return 0;

		if ( is_system_module_path( module ) )
			return 0;

		if ( !module_has_executable_section( module ) )
			return report_loaded_module_entry( command, module, module_name, "non-system module has no valid executable image section" );

		if ( !driver_object && driver_name && driver_name[ 0 ] )
			return report_loaded_module_entry( command, module, module_name, "non-system module has no matching driver object" );

		return 0;
	}

	const system_module_t* find_driver_owner_module( const system_modules_t* modules, PDRIVER_OBJECT driver_object ) {
		if ( !modules || !driver_object || !driver_object->DriverStart )
			return nullptr;

		auto start = reinterpret_cast< unsigned long long >( driver_object->DriverStart );
		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto module = &modules->m_modules[ index ];
			auto base = reinterpret_cast< unsigned long long >( module->m_image_base );
			auto end = base + module->m_image_size;
			if ( start >= base && start < end )
				return module;
		}

		return nullptr;
	}

	const system_module_t* find_trusted_dispatch_host_module( const system_modules_t* modules, PDRIVER_OBJECT driver_object ) {
		if ( !modules || !driver_object )
			return nullptr;

		const system_module_t* host = nullptr;
		auto accept_target = [ & ]( void* function ) {
			if ( !function )
				return true;

			auto address = reinterpret_cast< unsigned long long >( function );
			auto module = module::disk::find_module_by_address( modules, address );
			if ( !module || !module::disk::is_address_in_executable_section( module, address, nullptr, 0 ) )
				return false;

			if ( !host ) {
				host = module;
				return true;
			}

			return host->m_image_base == module->m_image_base;
		};

		for ( auto index = 0ul; index <= IRP_MJ_MAXIMUM_FUNCTION; index++ ) {
			if ( !accept_target( reinterpret_cast< void* >( driver_object->MajorFunction[ index ] ) ) )
				return nullptr;
		}

		if ( !accept_target( reinterpret_cast< void* >( driver_object->DriverInit ) ) ||
			!accept_target( reinterpret_cast< void* >( driver_object->DriverUnload ) ) ||
			!accept_target( reinterpret_cast< void* >(
				driver_object->DriverExtension ? driver_object->DriverExtension->AddDevice : nullptr ) ) )
			return nullptr;

		return host;
	}

	bool is_anonymous_unbacked_driver( PDRIVER_OBJECT driver_object ) {
		if ( !driver_object )
			return false;

		const auto missing_backing = !driver_object->DriverStart ||
			!driver_object->DriverSize ||
			!driver_object->DriverSection;
		return missing_backing;
	}

	unsigned long scan_driver_object( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* module, PDRIVER_OBJECT driver_object, const char* driver_name ) {
		if ( !command || !modules || !driver_object )
			return 0;

		unsigned long detections = 0;
		if ( module )
			detections += report_driver_object_mismatch( command, driver_object, module, driver_name );
		else {
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA(
				detail,
				sizeof( detail ),
				"name=%s driver=0x%llx start=0x%llx size=0x%lx devices=0x%llx",
				driver_name ? driver_name : "unknown",
				reinterpret_cast< unsigned long long >( driver_object ),
				reinterpret_cast< unsigned long long >( driver_object->DriverStart ),
				driver_object->DriverSize,
				reinterpret_cast< unsigned long long >( driver_object->DeviceObject )
			);

			report::add_memory_detection(
				command,
				driver_name ? driver_name : "driver",
				report::m_suspicious_driver_object_violation,
				detail,
				reinterpret_cast< unsigned long long >( driver_object ),
				sizeof( DRIVER_OBJECT )
			);
			detections++;
		}

		detections += scan_driver_section( command, driver_object, module, driver_name );
		detections += dispatch::scan_major_functions( command, modules, module, driver_object, driver_name );
		detections += dispatch::scan_fast_io( command, modules, module, driver_object, driver_name );
		detections += dispatch::scan_ioctl_shape( command, modules, module, driver_object, driver_name );
		detections += object::scan_device_chain( command, driver_object, driver_name );
		return detections;
	}

	unsigned long scan_trusted_hosted_driver( ioctl::command_t* command, const system_modules_t* modules, const system_module_t* host, PDRIVER_OBJECT driver_object, const char* driver_name ) {
		if ( !command || !modules || !host || !driver_object )
			return 0;

		unsigned long detections = 0;
		detections += dispatch::scan_major_functions( command, modules, host, driver_object, driver_name );
		detections += dispatch::scan_fast_io( command, modules, host, driver_object, driver_name );
		detections += object::scan_device_chain( command, driver_object, driver_name );
		return detections;
	}

	unsigned long scan_driver_directory( ioctl::command_t* command, const system_modules_t* modules, PDRIVER_OBJECT* scanned, unsigned long* scanned_count, unsigned long* objects ) {
		if ( !command || !modules || !scanned || !scanned_count )
			return 0;

		HANDLE directory = nullptr;
		if ( !open_driver_directory( &directory ) )
			return 0;

		auto buffer = memory::allocate_pool( m_directory_buffer_size, 1 );
		if ( !buffer ) {
			ZwClose( directory );
			return 0;
		}

		ULONG context = 0;
		ULONG returned = 0;
		unsigned long detections = 0;

		while ( true ) {
			memset( buffer, 0, m_directory_buffer_size );
			auto status = ZwQueryDirectoryObject( directory, buffer, m_directory_buffer_size, TRUE, FALSE, &context, &returned );
			if ( status )
				break;

			auto entry = static_cast< object_directory_information_t* >( buffer );
			char type_name[ 64 ]{ };
			char object_name[ 128 ]{ };
			unicode_to_ascii( entry->m_type_name, type_name, sizeof( type_name ) );
			unicode_to_ascii( entry->m_name, object_name, sizeof( object_name ) );
			if ( !ascii_equal_insensitive( type_name, "Driver" ) )
				continue;

			PDRIVER_OBJECT driver_object = nullptr;
			if ( !reference_driver_object( object_name, &driver_object ) )
				continue;

			if ( objects )
				( *objects )++;

			if ( !already_scanned_driver( scanned, *scanned_count, driver_object ) ) {
				auto owner_module = find_driver_owner_module( modules, driver_object );
				auto dispatch_host = owner_module ? nullptr : find_trusted_dispatch_host_module( modules, driver_object );
				if ( dispatch_host )
					detections += scan_trusted_hosted_driver( command, modules, dispatch_host, driver_object, object_name );
				else
					detections += scan_driver_object( command, modules, owner_module, driver_object, object_name );
				remember_scanned_driver( scanned, scanned_count, driver_object );
			}

			ObDereferenceObject( driver_object );
		}

		memory::free_pool( buffer );
		ZwClose( directory );
		return detections;
	}

	unsigned long report_device_without_loaded_owner( ioctl::command_t* command, const char* name, PDEVICE_OBJECT device_object, PDRIVER_OBJECT driver_object ) {
		if ( !command || !device_object || !driver_object )
			return 0;

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA( target, sizeof( target ), "device!%s", name && name[ 0 ] ? name : "object" );
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"device=0x%llx driver=0x%llx driver_start=0x%llx driver_size=0x%lx driver_section=0x%llx name_length=%u flags=0x%lx type=0x%lx",
			reinterpret_cast< unsigned long long >( device_object ),
			reinterpret_cast< unsigned long long >( driver_object ),
			reinterpret_cast< unsigned long long >( driver_object->DriverStart ),
			driver_object->DriverSize,
			reinterpret_cast< unsigned long long >( driver_object->DriverSection ),
			static_cast< unsigned long >( driver_object->DriverName.Length ),
			device_object->Flags,
			device_object->DeviceType
		);

		report::add_memory_detection(
			command,
			target,
			report::m_hidden_driver_device_violation,
			detail,
			reinterpret_cast< unsigned long long >( device_object ),
			sizeof( DEVICE_OBJECT )
		);
		return 1;
	}

	bool is_known_ownerless_system_device( const char* name ) {
		return name && (
			ascii_equal_insensitive( name, "RawDisk" ) ||
			ascii_equal_insensitive( name, "RawCdRom" ) ||
			ascii_equal_insensitive( name, "RawTape" )
		);
	}

	unsigned long scan_referenced_device( ioctl::command_t* command, const system_modules_t* modules, const char* name, PDEVICE_OBJECT device_object, PDRIVER_OBJECT* scanned, unsigned long* scanned_count ) {
		if ( !command || !modules || !device_object || !scanned || !scanned_count )
			return 0;

		auto driver_object = device_object->DriverObject;
		if ( !driver_object )
			return 0;

		auto owner_module = find_driver_owner_module( modules, driver_object );
		auto dispatch_host = owner_module ? nullptr : find_trusted_dispatch_host_module( modules, driver_object );
		auto effective_owner = owner_module ? owner_module : dispatch_host;
		unsigned long detections = 0;
		if ( !owner_module &&
			( !dispatch_host || !is_known_ownerless_system_device( name ) ) )
			detections += report_device_without_loaded_owner( command, name, device_object, driver_object );

		detections += dispatch::scan_ioctl_shape( command, modules, effective_owner, driver_object, name );
		if ( !already_scanned_driver( scanned, *scanned_count, driver_object ) ) {
			if ( dispatch_host )
				detections += scan_trusted_hosted_driver( command, modules, dispatch_host, driver_object, name );
			else
				detections += scan_driver_object( command, modules, owner_module, driver_object, name );
			remember_scanned_driver( scanned, scanned_count, driver_object );
		}

		return detections;
	}

	unsigned long scan_device_directory_objects( ioctl::command_t* command, const system_modules_t* modules, PDRIVER_OBJECT* scanned, unsigned long* scanned_count, unsigned long* objects ) {
		if ( !command || !modules || !scanned || !scanned_count )
			return 0;

		HANDLE directory = nullptr;
		if ( !open_object_directory( L"\\Device", &directory ) )
			return 0;

		auto buffer = memory::allocate_pool( m_directory_buffer_size, 1 );
		if ( !buffer ) {
			ZwClose( directory );
			return 0;
		}

		ULONG context = 0;
		ULONG returned = 0;
		unsigned long detections = 0;

		while ( true ) {
			memset( buffer, 0, m_directory_buffer_size );
			auto status = ZwQueryDirectoryObject( directory, buffer, m_directory_buffer_size, TRUE, FALSE, &context, &returned );
			if ( status )
				break;

			auto entry = static_cast< object_directory_information_t* >( buffer );
			char type_name[ 64 ]{ };
			char object_name[ 128 ]{ };
			unicode_to_ascii( entry->m_type_name, type_name, sizeof( type_name ) );
			unicode_to_ascii( entry->m_name, object_name, sizeof( object_name ) );

			if ( !ascii_equal_insensitive( type_name, "Device" ) )
				continue;

			PDEVICE_OBJECT device_object = nullptr;
			if ( !reference_device_object( object_name, &device_object ) )
				continue;

			if ( objects )
				( *objects )++;

			detections += scan_referenced_device( command, modules, object_name, device_object, scanned, scanned_count );

			auto top_device = IoGetAttachedDeviceReference( device_object );
			if ( top_device ) {
				if ( top_device != device_object ) {
					if ( objects )
						( *objects )++;
					detections += scan_referenced_device( command, modules, object_name, top_device, scanned, scanned_count );
				}
				ObDereferenceObject( top_device );
			}

			ObDereferenceObject( device_object );
		}

		memory::free_pool( buffer );
		ZwClose( directory );
		return detections;
	}

	unsigned long report_loader_entry( ioctl::command_t* command, const loader_module_entry_t& entry, const char* name, const char* reason, LIST_ENTRY* link ) {
		if ( !command )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"name=%s link=0x%llx base=0x%llx size=0x%lx flink=0x%llx blink=0x%llx reason=%s",
			name && name[ 0 ] ? name : "unknown",
			reinterpret_cast< unsigned long long >( link ),
			reinterpret_cast< unsigned long long >( entry.m_dll_base ),
			entry.m_size_of_image,
			reinterpret_cast< unsigned long long >( entry.m_load_order_links.Flink ),
			reinterpret_cast< unsigned long long >( entry.m_load_order_links.Blink ),
			reason ? reason : "loader list consistency"
		);

		report::add_memory_detection(
			command,
			name && name[ 0 ] ? name : "PsLoadedModuleList",
			report::m_loaded_module_list_entry_violation,
			detail,
			reinterpret_cast< unsigned long long >( entry.m_dll_base ? entry.m_dll_base : link ),
			entry.m_size_of_image ? entry.m_size_of_image : sizeof( loader_module_entry_t )
		);
		return 1;
	}

	bool copy_list_entry( LIST_ENTRY* link, LIST_ENTRY* entry ) {
		if ( !link || !entry )
			return false;

		size_t copied = 0;
		return memory::copy_kernel_memory( link, sizeof( *entry ), entry, &copied );
	}

	bool unicode_name_sane( const UNICODE_STRING& name ) {
		if ( !name.Length || !name.MaximumLength || !name.Buffer )
			return false;

		if ( name.Length > name.MaximumLength || name.Length & 1 )
			return false;

		if ( name.MaximumLength > 512 )
			return false;

		return memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( name.Buffer ) );
	}

	bool image_headers_match_loader_entry( const loader_module_entry_t& entry ) {
		if ( !entry.m_dll_base || entry.m_size_of_image < PAGE_SIZE )
			return false;

		auto image = static_cast< const unsigned char* >( entry.m_dll_base );
		auto headers = memory::validate_pe_image( image, entry.m_size_of_image );
		if ( !headers )
			return false;

		if ( headers->OptionalHeader.SizeOfImage != entry.m_size_of_image )
			return false;

		auto entry_point = reinterpret_cast< unsigned long long >( entry.m_entry_point );
		auto base = reinterpret_cast< unsigned long long >( entry.m_dll_base );
		if ( entry_point && ( entry_point < base || entry_point >= base + entry.m_size_of_image ) )
			return false;

		return true;
	}

	unsigned long scan_loader_entry_invariants( ioctl::command_t* command, const system_modules_t* modules, LIST_ENTRY* head, LIST_ENTRY* link, const loader_module_entry_t& entry, const char* base_name, const char* full_name, bool system_path ) {
		if ( !command || !head || !link )
			return 0;

		auto base = reinterpret_cast< unsigned long long >( entry.m_dll_base );
		if ( !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( link ) ) )
			return report_loader_entry( command, entry, base_name, "loader entry link is not canonical kernel va", link );

		if ( !entry.m_load_order_links.Flink || !entry.m_load_order_links.Blink )
			return report_loader_entry( command, entry, base_name, "loader entry has null links", link );

		if ( entry.m_load_order_links.Flink != head && !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( entry.m_load_order_links.Flink ) ) )
			return report_loader_entry( command, entry, base_name, "loader entry flink is not canonical kernel va", link );

		if ( entry.m_load_order_links.Blink != head && !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( entry.m_load_order_links.Blink ) ) )
			return report_loader_entry( command, entry, base_name, "loader entry blink is not canonical kernel va", link );

		LIST_ENTRY next{ };
		if ( !copy_list_entry( entry.m_load_order_links.Flink, &next ) || next.Blink != link )
			return report_loader_entry( command, entry, base_name, "loader entry flink/blink reciprocity broken", link );

		LIST_ENTRY previous{ };
		if ( !copy_list_entry( entry.m_load_order_links.Blink, &previous ) || previous.Flink != link )
			return report_loader_entry( command, entry, base_name, "loader entry blink/flink reciprocity broken", link );

		if ( !base || !memory::is_canonical_kernel_address( base ) )
			return report_loader_entry( command, entry, base_name, "loader entry image base is not canonical kernel va", link );

		if ( entry.m_size_of_image < PAGE_SIZE || entry.m_size_of_image > 0x20000000ul || ( entry.m_size_of_image & ( PAGE_SIZE - 1 ) ) )
			return report_loader_entry( command, entry, base_name, "loader entry image size is invalid", link );

		if ( !unicode_name_sane( entry.m_base_dll_name ) || !unicode_name_sane( entry.m_full_dll_name ) )
			return report_loader_entry( command, entry, base_name, "loader entry unicode names are invalid", link );

		if ( !image_headers_match_loader_entry( entry ) )
			return report_loader_entry( command, entry, base_name, "loader entry image headers do not match entry fields", link );

		auto module = find_module_by_exact_base( modules, base );
		if ( module && module->m_image_size != entry.m_size_of_image )
			return report_loader_entry( command, entry, base_name, "loader entry size disagrees with system module query", link );

		if ( !system_path ) {
			if ( !full_name || !full_name[ 0 ] || !base_name || !base_name[ 0 ] )
				return report_loader_entry( command, entry, base_name, "non-system loader entry has missing path/name", link );

			if ( !entry.m_section_pointer )
				return report_loader_entry( command, entry, base_name, "non-system loader entry has no section pointer", link );

			if ( !module )
				return report_loader_entry( command, entry, base_name, "non-system loader entry missing from system module query", link );
		}

		return 0;
	}

	unsigned long scan_loaded_module_list( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return 0;

		auto list_address = m_entry.m_pdb.m_ps_loaded_module_list;
		if ( !list_address )
			list_address = find_ps_loaded_module_list_pattern( modules );

		if ( !list_address )
			return 0;

		auto head = reinterpret_cast< LIST_ENTRY* >( list_address );
		LIST_ENTRY head_copy{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( head, sizeof( head_copy ), &head_copy, &copied ) )
			return 0;

		auto current = head_copy.Flink;
		unsigned long detections = 0;
		unsigned long walked = 0;

		while ( current && current != head && walked < 1024 ) {
			loader_module_entry_t entry{ };
			if ( !read_loader_entry( current, &entry ) )
				break;

			char base_name[ 96 ]{ };
			char full_name[ 160 ]{ };
			copy_unicode_name( entry.m_base_dll_name, base_name, sizeof( base_name ) );
			copy_unicode_name( entry.m_full_dll_name, full_name, sizeof( full_name ) );

			if ( !entry.m_load_order_links.Flink || !entry.m_load_order_links.Blink ) {
				detections += report_loader_entry( command, entry, base_name, "broken loader list links", current );
				break;
			}

			auto base = reinterpret_cast< unsigned long long >( entry.m_dll_base );
			auto module = find_module_by_exact_base( modules, base );
			auto system_path = module ? is_system_module_path( module ) :
				( ascii_starts_with_insensitive( full_name, "\\SystemRoot\\" ) ||
					ascii_starts_with_insensitive( full_name, "\\Windows\\" ) ||
					ascii_starts_with_insensitive( full_name, "C:\\Windows\\" ) );

			detections += scan_loader_entry_invariants( command, modules, head, current, entry, base_name, full_name, system_path );

			if ( !module ) {
				if ( !system_path || !module::disk::is_whitelisted_owner( base_name ) )
					detections += report_loader_entry( command, entry, base_name, "present in PsLoadedModuleList missing from system query", current );
			}
			else if ( module->m_image_size != entry.m_size_of_image ) {
				detections += report_loader_entry( command, entry, base_name, "PsLoadedModuleList size disagrees with system query", current );
			}

			if ( !module && base && entry.m_size_of_image >= PAGE_SIZE ) {
				system_module_t pseudo{ };
				pseudo.m_image_base = entry.m_dll_base;
				pseudo.m_image_size = entry.m_size_of_image;
				if ( !module_has_executable_section( &pseudo ) )
					detections += report_loader_entry( command, entry, base_name, "loader entry image has no valid executable section", current );
			}

			if ( base && !system_path && !module::disk::is_whitelisted_owner( base_name ) ) {
				char driver_key[ 96 ]{ };
				strip_extension( base_name, driver_key, sizeof( driver_key ) );

				PDRIVER_OBJECT driver_object = nullptr;
				if ( !reference_driver_object( driver_key, &driver_object ) ) {
					detections += report_loader_entry( command, entry, base_name, "non-system loader entry has no matching driver object", current );
				}
				else {
					ObDereferenceObject( driver_object );
				}
			}

			current = entry.m_load_order_links.Flink;
			walked++;
		}

		if ( current && current != head && walked >= 1024 ) {
			loader_module_entry_t entry{ };
			detections += report_loader_entry( command, entry, "PsLoadedModuleList", "loader list walk exceeded sane limit", current );
		}

		return detections;
	}

	struct mm_unloaded_driver_t {
		UNICODE_STRING m_name;
		void* m_module_start;
		void* m_module_end;
		LARGE_INTEGER m_unload_time;
	};

	struct piddb_cache_entry_t {
		LIST_ENTRY m_list;
		UNICODE_STRING m_driver_name;
		ULONG m_time_date_stamp;
		NTSTATUS m_load_status;
		char m_shim_data[ 16 ];
	};

	unsigned long scan_mm_unloaded_drivers( ioctl::command_t* command ) {
		if ( !command || !m_entry.m_pdb.m_mm_unloaded_drivers )
			return 0;

		mm_unloaded_driver_t* table_ptr = nullptr;
		size_t copied = 0;
		if ( !memory::copy_kernel_memory(
			reinterpret_cast< void* >( m_entry.m_pdb.m_mm_unloaded_drivers ),
			sizeof( table_ptr ),
			&table_ptr,
			&copied ) || !table_ptr || !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( table_ptr ) ) )
			return 0;

		constexpr auto max_unloaded_drivers = 50ul;
		mm_unloaded_driver_t entries[ max_unloaded_drivers ]{ };
		if ( !memory::copy_kernel_memory( table_ptr, sizeof( entries ), entries, &copied ) )
			return 0;

		unsigned long detections = 0;
		for ( auto index = 0ul; index < max_unloaded_drivers; index++ ) {
			const auto& item = entries[ index ];
			if ( !item.m_module_start && !item.m_module_end && !item.m_name.Buffer && !item.m_name.Length )
				continue;

			auto entry_address = reinterpret_cast< unsigned long long >( table_ptr ) + index * sizeof( mm_unloaded_driver_t );

			if ( ( item.m_module_start || item.m_module_end ) && ( !item.m_name.Buffer || !item.m_name.Length ) ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"index=%lu start=0x%llx end=0x%llx reason=wiped_unloaded_driver_name",
					index,
					reinterpret_cast< unsigned long long >( item.m_module_start ),
					reinterpret_cast< unsigned long long >( item.m_module_end )
				);
				report::add_memory_detection(
					command,
					"MmUnloadedDrivers",
					report::m_mm_unloaded_driver_violation,
					detail,
					entry_address,
					sizeof( mm_unloaded_driver_t )
				);
				detections++;
				continue;
			}

			if ( !unicode_name_sane( item.m_name ) )
				continue;

			wchar_t wide_name[ 128 ]{ };
			auto copy_bytes = item.m_name.Length < ( sizeof( wide_name ) - sizeof( wchar_t ) )
				? item.m_name.Length
				: ( sizeof( wide_name ) - sizeof( wchar_t ) );
			if ( !memory::copy_kernel_memory( item.m_name.Buffer, copy_bytes, wide_name, &copied ) )
				continue;

			UNICODE_STRING safe_unicode{ };
			safe_unicode.Buffer = wide_name;
			safe_unicode.Length = static_cast< USHORT >( copy_bytes );
			safe_unicode.MaximumLength = sizeof( wide_name );

			char driver_name[ 128 ]{ };
			if ( !unicode_to_ascii( safe_unicode, driver_name, sizeof( driver_name ) ) || !driver_name[ 0 ] )
				continue;

			char rule_detail[ 160 ]{ };
			if ( callback::is_driver_name_blocked( driver_name, rule_detail, sizeof( rule_detail ) ) ) {
				KeEnterCriticalRegion( );
				ExAcquirePushLockExclusive( &callback::m_blocklist_lock );
				callback::record_blocked_driver_locked( driver_name );
				ExReleasePushLockExclusive( &callback::m_blocklist_lock );
				KeLeaveCriticalRegion( );

				char target[ ioctl::m_detection_target_size ]{ };
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA( target, sizeof( target ), "MmUnloadedDrivers!%s", driver_name );
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"unloaded_driver=%s start=0x%llx end=0x%llx %s",
					driver_name,
					reinterpret_cast< unsigned long long >( item.m_module_start ),
					reinterpret_cast< unsigned long long >( item.m_module_end ),
					rule_detail
				);
				report::add_memory_detection(
					command,
					target,
					report::m_vulnerable_driver_blocklist_violation,
					detail,
					entry_address,
					sizeof( mm_unloaded_driver_t )
				);
				detections++;
			}
		}

		return detections;
	}

	unsigned long scan_pi_ddb_cache_table( ioctl::command_t* command ) {
		if ( !command || !m_entry.m_pdb.m_pi_ddb_cache_table )
			return 0;

		auto table_address = m_entry.m_pdb.m_pi_ddb_cache_table;
		if ( !memory::is_canonical_kernel_address( table_address ) )
			return 0;

		LIST_ENTRY head_copy{ };
		size_t copied = 0;
		auto list_head = reinterpret_cast< LIST_ENTRY* >( table_address + 0x10 );
		if ( !memory::copy_kernel_memory( list_head, sizeof( head_copy ), &head_copy, &copied ) )
			return 0;

		if ( !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( head_copy.Flink ) ) ||
			!memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( head_copy.Blink ) ) )
			return 0;

		unsigned long detections = 0;
		unsigned long walked = 0;
		auto current = head_copy.Flink;

		while ( current && current != list_head && walked < 2048 ) {
			if ( !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( current ) ) )
				break;

			piddb_cache_entry_t entry{ };
			if ( !memory::copy_kernel_memory( current, sizeof( entry ), &entry, &copied ) )
				break;

			if ( !entry.m_list.Flink || !entry.m_list.Blink ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"entry=0x%llx flink=0x%llx blink=0x%llx reason=broken_piddb_links",
					reinterpret_cast< unsigned long long >( current ),
					reinterpret_cast< unsigned long long >( entry.m_list.Flink ),
					reinterpret_cast< unsigned long long >( entry.m_list.Blink )
				);
				report::add_memory_detection(
					command,
					"PiDDBCacheTable",
					report::m_piddb_cache_entry_violation,
					detail,
					reinterpret_cast< unsigned long long >( current ),
					sizeof( piddb_cache_entry_t )
				);
				detections++;
				break;
			}

			if ( unicode_name_sane( entry.m_driver_name ) ) {
				wchar_t wide_name[ 128 ]{ };
				auto copy_bytes = entry.m_driver_name.Length < ( sizeof( wide_name ) - sizeof( wchar_t ) )
					? entry.m_driver_name.Length
					: ( sizeof( wide_name ) - sizeof( wchar_t ) );
				if ( memory::copy_kernel_memory( entry.m_driver_name.Buffer, copy_bytes, wide_name, &copied ) ) {
					UNICODE_STRING safe_unicode{ };
					safe_unicode.Buffer = wide_name;
					safe_unicode.Length = static_cast< USHORT >( copy_bytes );
					safe_unicode.MaximumLength = sizeof( wide_name );

					char driver_name[ 128 ]{ };
					if ( unicode_to_ascii( safe_unicode, driver_name, sizeof( driver_name ) ) && driver_name[ 0 ] ) {
						char rule_detail[ 160 ]{ };
						if ( callback::is_driver_name_blocked( driver_name, rule_detail, sizeof( rule_detail ) ) ) {
							KeEnterCriticalRegion( );
							ExAcquirePushLockExclusive( &callback::m_blocklist_lock );
							callback::record_blocked_driver_locked( driver_name );
							ExReleasePushLockExclusive( &callback::m_blocklist_lock );
							KeLeaveCriticalRegion( );

							char target[ ioctl::m_detection_target_size ]{ };
							char detail[ ioctl::m_detection_text_size ]{ };
							RtlStringCbPrintfA( target, sizeof( target ), "PiDDBCacheTable!%s", driver_name );
							RtlStringCbPrintfA(
								detail,
								sizeof( detail ),
								"cached_driver=%s timestamp=0x%lx status=0x%lx %s",
								driver_name,
								entry.m_time_date_stamp,
								static_cast< unsigned long >( entry.m_load_status ),
								rule_detail
							);
							report::add_memory_detection(
								command,
								target,
								report::m_vulnerable_driver_blocklist_violation,
								detail,
								reinterpret_cast< unsigned long long >( current ),
								sizeof( piddb_cache_entry_t )
							);
							detections++;
						}
						else if ( !entry.m_time_date_stamp && !module::disk::is_whitelisted_owner( driver_name ) ) {
							char target[ ioctl::m_detection_target_size ]{ };
							char detail[ ioctl::m_detection_text_size ]{ };
							RtlStringCbPrintfA( target, sizeof( target ), "PiDDBCacheTable!%s", driver_name );
							RtlStringCbPrintfA(
								detail,
								sizeof( detail ),
								"cached_driver=%s timestamp=0x0 status=0x%lx reason=zeroed_timestamp",
								driver_name,
								static_cast< unsigned long >( entry.m_load_status )
							);
							report::add_memory_detection(
								command,
								target,
								report::m_piddb_cache_entry_violation,
								detail,
								reinterpret_cast< unsigned long long >( current ),
								sizeof( piddb_cache_entry_t )
							);
							detections++;
						}
					}
				}
			}

			current = entry.m_list.Flink;
			walked++;
		}

		return detections;
	}

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		unsigned long resolved = 0;
		unsigned long driver_objects = 0;
		unsigned long detections = 0;
		PDRIVER_OBJECT scanned_drivers[ 512 ]{ };
		unsigned long scanned_driver_count = 0;

		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto module = &modules->m_modules[ index ];
			char driver_name[ 64 ]{ };
			module_driver_name( module, driver_name, sizeof( driver_name ) );
			if ( !driver_name[ 0 ] )
				continue;

			PDRIVER_OBJECT driver_object = nullptr;
			if ( !reference_driver_object( driver_name, &driver_object ) ) {
				detections += scan_module_list_entry( command, module, driver_name, nullptr );
				continue;
			}

			resolved++;
			detections += scan_module_list_entry( command, module, driver_name, driver_object );
			detections += scan_driver_object( command, modules, module, driver_object, driver_name );
			remember_scanned_driver( scanned_drivers, &scanned_driver_count, driver_object );
			ObDereferenceObject( driver_object );
		}

		detections += scan_loaded_module_list( command, modules );
		detections += scan_device_directory_objects( command, modules, scanned_drivers, &scanned_driver_count, &driver_objects );
		detections += scan_driver_directory( command, modules, scanned_drivers, &scanned_driver_count, &driver_objects );
		detections += callback::scan_loaded_modules( command, modules );
		detections += scan_mm_unloaded_drivers( command );
		detections += scan_pi_ddb_cache_table( command );

		utility::print(
			"device surface: modules=%lu resolved_drivers=%lu driver_objects=%lu detections=%lu\n",
			modules->m_count,
			resolved,
			driver_objects,
			command->m_total_detection_count
		);

		command->m_modules_scanned = modules->m_count;
		command->m_sections_scanned = resolved + driver_objects;
		command->m_signature_detections = detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		return true;
	}
}
