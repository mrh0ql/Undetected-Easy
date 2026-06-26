#pragma once

namespace ioctl {
	UNICODE_STRING m_device_name = RTL_CONSTANT_STRING( L"\\Device\\ude" );
	UNICODE_STRING m_symbolic_link = RTL_CONSTANT_STRING( L"\\DosDevices\\ude" );
	PDEVICE_OBJECT m_device_object = nullptr;

	NTSTATUS complete_request( PIRP irp, ULONG_PTR information ) {
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = information;
		IofCompleteRequest( irp, IO_NO_INCREMENT );
		return STATUS_SUCCESS;
	}

	NTSTATUS unsupported_dispatch( PDEVICE_OBJECT dispatch_device_object, PIRP irp ) {
		UNREFERENCED_PARAMETER( dispatch_device_object );
		return complete_request( irp, 0 );
	}

	NTSTATUS create_close_dispatch( PDEVICE_OBJECT dispatch_device_object, PIRP irp ) {
		UNREFERENCED_PARAMETER( dispatch_device_object );
		return complete_request( irp, 0 );
	}

	bool scan_module_integrity( command_t* command, const char* module_name ) {
		if ( !command || !module_name )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		void* disk_image = nullptr;
		unsigned long disk_image_size = 0;

		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto module_entry = module::disk::find_module_by_file_name( modules, module_name );
		if ( !module_entry ) {
			command->m_error = STATUS_NOT_FOUND;
			memory::free_pool( modules );
			return false;
		}

		auto status = module::disk::read_module_image_from_disk( *module_entry, &disk_image, &disk_image_size );
		if ( status ) {
			command->m_error = status;
			memory::free_pool( modules );
			return false;
		}

		auto nt_headers = module::disk::validate_pe_image(
			static_cast< const unsigned char* >( disk_image ),
			disk_image_size
		);

		if ( !nt_headers ) {
			command->m_error = STATUS_INVALID_IMAGE_FORMAT;
			memory::free_pool( disk_image );
			memory::free_pool( modules );
			return false;
		}

		command->m_modules_scanned = 1;
		command->m_error = STATUS_SUCCESS;
		command->m_result = true;

		auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( nt_headers ) );
		unsigned long sections_scanned = 0;

		for ( auto index = 0u; index < nt_headers->FileHeader.NumberOfSections; index++ ) {
			if ( !report::scan_executable_section(
				command,
				modules,
				module_entry,
				module_name,
				static_cast< const unsigned char* >( disk_image ),
				disk_image_size,
				&sections[ index ],
				&sections_scanned
			) ) {
				memory::free_pool( disk_image );
				memory::free_pool( modules );
				return false;
			}
		}

		auto export_detections = report::report_export_differences(
			command,
			static_cast< const unsigned char* >( disk_image ),
			disk_image_size,
			module_entry,
			module_name
		);

		auto import_detections = report::report_import_differences(
			command,
			modules,
			static_cast< const unsigned char* >( disk_image ),
			disk_image_size,
			module_entry,
			module_name
		);

		auto permission_detections = module::protection::scan_section_permissions(
			command,
			module_entry,
			module_name
		);	

		auto stack_detections = module::protection::scan_stack_frames(
			command,
			modules,
			module_name
		);

		utility::print(
			"module disk check: %s executable_sections=%lu eat_detections=%lu iat_detections=%lu permission_detections=%lu stack_detections=%lu detections=%lu\n",
			module_name,
			sections_scanned,
			export_detections,
			import_detections,
			permission_detections,
			stack_detections,
			command->m_detection_count
		);

		memory::free_pool( disk_image );
		memory::free_pool( modules );
		return true;
	}

	bool scan_execution_integrity( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto result = execution::processor::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	bool scan_memory_integrity( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		command->m_modules_scanned = modules->m_count;
		auto result = memory_scan::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	bool scan_device_surface( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto result = device_surface::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	bool scan_service_integrity( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto result = service_integrity::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	bool scan_pool_integrity( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto result = pool_integrity::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	bool scan_cpu_integrity( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto result = cpu_integrity::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	bool scan_object_integrity( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto result = object_integrity::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	bool scan_dpc_integrity( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto result = dpc_integrity::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	bool scan_process_integrity( command_t* command ) {
		if ( !command )
			return false;

		free_detection_snapshot( );
		reset_command( command );
		command->m_detection_session = m_detection_snapshot_session;

		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) ) {
			command->m_error = STATUS_UNSUCCESSFUL;
			return false;
		}

		auto result = process_integrity::scan( command, modules );
		memory::free_pool( modules );
		return result;
	}

	NTSTATUS device_control_dispatch( PDEVICE_OBJECT dispatch_device_object, PIRP irp ) {
		UNREFERENCED_PARAMETER( dispatch_device_object );

		auto stack_location = IoGetCurrentIrpStackLocation( irp );
		if ( !stack_location )
			return complete_request( irp, 0 );

		auto control_code = stack_location->Parameters.DeviceIoControl.IoControlCode;
		auto output_length = stack_location->Parameters.DeviceIoControl.OutputBufferLength;
		auto input_length = stack_location->Parameters.DeviceIoControl.InputBufferLength;
		auto system_buffer = irp->AssociatedIrp.SystemBuffer;
		auto command = reinterpret_cast< command_t* >( system_buffer );

		switch ( control_code ) {
		case m_ping_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			reset_command( command );
			command->m_result = true;
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_module_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_module_integrity( command, "ntoskrnl.exe" );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_execution_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_execution_integrity( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_memory_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_memory_integrity( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_device_surface_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_device_surface( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_pool_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_pool_integrity( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_service_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_service_integrity( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_cpu_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_cpu_integrity( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_object_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_object_integrity( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_dpc_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_dpc_integrity( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_process_integrity_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			scan_process_integrity( command );
			return complete_request( irp, sizeof( command_t ) );
		}
		case m_fetch_detections_code: {
			if ( !system_buffer || output_length < sizeof( command_t ) )
				return complete_request( irp, 0 );

			auto requested_offset = command->m_detection_offset;
			auto requested_session = command->m_detection_session;
			reset_command( command );

			if ( requested_session != m_detection_snapshot_session ) {
				command->m_error = STATUS_NOT_FOUND;
				return complete_request( irp, sizeof( command_t ) );
			}

			copy_detection_window( command, requested_offset );
			command->m_result = true;
			command->m_error = STATUS_SUCCESS;
			return complete_request( irp, sizeof( command_t ) );
		}
        case m_setup_image_callback_code: {
            const auto header_size = FIELD_OFFSET( callback::blocklist_upload_t, m_entries );
            if ( !system_buffer || input_length < header_size || output_length < header_size )
                return complete_request( irp, 0 );

            auto request = static_cast< callback::blocklist_upload_t* >( system_buffer );
            request->m_status = callback::upload_blocklist( request, input_length );
            request->m_result = NT_SUCCESS( request->m_status );
            return complete_request( irp, header_size );
        }
		case m_query_blocked_drivers_code: {
			if ( !system_buffer || input_length < sizeof( callback::blocked_driver_query_t ) ||
				output_length < sizeof( callback::blocked_driver_query_t ) )
				return complete_request( irp, 0 );

			auto query = static_cast< callback::blocked_driver_query_t* >( system_buffer );
			query->m_status = callback::query_blocked_drivers( query, output_length );
			query->m_result = NT_SUCCESS( query->m_status );
			return complete_request( irp, sizeof( *query ) );
		}
		default:
			return complete_request( irp, system_buffer && output_length >= sizeof( command_t ) ? sizeof( command_t ) : 0 );
		}
	}

	bool initialize( PDRIVER_OBJECT driver_object ) {
		IoDeleteSymbolicLink( &m_symbolic_link );

		auto result = IoCreateDevice(
			driver_object,
			0,
			&m_device_name,
			FILE_DEVICE_UNKNOWN,
			FILE_DEVICE_SECURE_OPEN,
			FALSE,
			&m_device_object
		);

		if ( result ) {
			m_device_object = nullptr;
			return false;
		}

		result = IoCreateSymbolicLink( &m_symbolic_link, &m_device_name );
		if ( result ) {
			IoDeleteDevice( m_device_object );
			m_device_object = nullptr;
			return false;
		}

		for ( auto index = 0ul; index <= IRP_MJ_MAXIMUM_FUNCTION; index++ )
			driver_object->MajorFunction[ index ] = unsupported_dispatch;

		driver_object->MajorFunction[ IRP_MJ_CREATE ] = create_close_dispatch;
		driver_object->MajorFunction[ IRP_MJ_CLOSE ] = create_close_dispatch;
		driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = device_control_dispatch;

		m_device_object->Flags |= DO_BUFFERED_IO;
		m_device_object->Flags &= ~DO_DEVICE_INITIALIZING;

		utility::print( "ioctl initialized\n" );
		return true;
	}

	void destroy( ) {
		callback::destroy( );
		free_detection_snapshot( );
		IoDeleteSymbolicLink( &m_symbolic_link );

		if ( m_device_object ) {
			IoDeleteDevice( m_device_object );
			m_device_object = nullptr;
		}
	}
}
