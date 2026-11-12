#pragma once

namespace object_integrity {
	struct relative_security_descriptor_t {
		unsigned char m_revision;
		unsigned char m_reserved;
		unsigned short m_control;
		unsigned long m_owner;
		unsigned long m_group;
		unsigned long m_sacl;
		unsigned long m_dacl;
	};

	struct absolute_security_descriptor_t {
		unsigned char m_revision;
		unsigned char m_reserved;
		unsigned short m_control;
		void* m_owner;
		void* m_group;
		PACL m_sacl;
		PACL m_dacl;
	};

	struct ace_header_t {
		unsigned char m_type;
		unsigned char m_flags;
		unsigned short m_size;
	};

	struct access_allowed_ace_t {
		ace_header_t m_header;
		unsigned long m_mask;
		unsigned long m_sid_start;
	};

	bool is_world_sid( const unsigned char* sid, size_t available ) {
		if ( !sid || available < 12 )
			return false;

		return sid[ 0 ] == 1 && sid[ 1 ] == 1 &&
			!sid[ 2 ] && !sid[ 3 ] && !sid[ 4 ] && !sid[ 5 ] && !sid[ 6 ] && sid[ 7 ] == 1 &&
			!sid[ 8 ] && !sid[ 9 ] && !sid[ 10 ] && !sid[ 11 ];
	}

	bool has_world_full_access( void* object, unsigned long* granted_access ) {
		if ( granted_access )
			*granted_access = 0;

		PSECURITY_DESCRIPTOR security = nullptr;
		BOOLEAN allocated = FALSE;
		if ( ObGetObjectSecurity( object, &security, &allocated ) || !security )
			return false;

		auto relative = static_cast< relative_security_descriptor_t* >( security );
		constexpr auto dacl_present = 0x0004u;
		constexpr auto self_relative = 0x8000u;
		PACL dacl = nullptr;
		if ( relative->m_control & dacl_present ) {
			if ( relative->m_control & self_relative ) {
				if ( relative->m_dacl )
					dacl = reinterpret_cast< PACL >( reinterpret_cast< unsigned char* >( security ) + relative->m_dacl );
			}
			else
				dacl = reinterpret_cast< absolute_security_descriptor_t* >( security )->m_dacl;
		}

		bool exposed = !( relative->m_control & dacl_present ) || !dacl;
		if ( exposed && granted_access )
			*granted_access = SECTION_ALL_ACCESS;

		if ( dacl && dacl->AclSize >= sizeof( ACL ) ) {
			auto cursor = reinterpret_cast< unsigned char* >( dacl ) + sizeof( ACL );
			auto end = reinterpret_cast< unsigned char* >( dacl ) + dacl->AclSize;
			for ( auto index = 0ul; index < dacl->AceCount && cursor + sizeof( access_allowed_ace_t ) <= end; index++ ) {
				auto ace = reinterpret_cast< access_allowed_ace_t* >( cursor );
				if ( ace->m_header.m_size < sizeof( access_allowed_ace_t ) || cursor + ace->m_header.m_size > end )
					break;

				if ( ace->m_header.m_type != 0 || !is_world_sid( reinterpret_cast< unsigned char* >( &ace->m_sid_start ), ace->m_header.m_size - 8 ) ) {
					cursor += ace->m_header.m_size;
					continue;
				}

				if ( ( ace->m_mask & SECTION_ALL_ACCESS ) != SECTION_ALL_ACCESS ) {
					cursor += ace->m_header.m_size;
					continue;
				}

				exposed = true;
				if ( granted_access )
					*granted_access = ace->m_mask;
				break;
			}
		}

		ObReleaseObjectSecurity( security, allocated );
		return exposed;
	}

	unsigned long scan_named_sections( ioctl::command_t* command, const wchar_t* directory_path, const char* scope, unsigned long* sections ) {
		HANDLE directory = nullptr;
		if ( !device_surface::open_object_directory( directory_path, &directory ) )
			return 0;

		auto buffer = memory::allocate_pool( device_surface::m_directory_buffer_size, 1 );
		if ( !buffer ) {
			ZwClose( directory );
			return 0;
		}

		ULONG context = 0;
		ULONG returned = 0;
		unsigned long detections = 0;
		while ( true ) {
			memset( buffer, 0, device_surface::m_directory_buffer_size );
			auto status = ZwQueryDirectoryObject( directory, buffer, device_surface::m_directory_buffer_size, TRUE, FALSE, &context, &returned );
			if ( status )
				break;

			auto entry = static_cast< object_directory_information_t* >( buffer );
			char type_name[ 64 ]{ };
			char object_name[ 128 ]{ };
			device_surface::unicode_to_ascii( entry->m_type_name, type_name, sizeof( type_name ) );
			device_surface::unicode_to_ascii( entry->m_name, object_name, sizeof( object_name ) );
			if ( !ascii_equal_insensitive( type_name, "Section" ) )
				continue;

			char path[ 256 ]{ };
			RtlStringCbPrintfA( path, sizeof( path ), "%ws\\%s", directory_path, object_name );
			ANSI_STRING ansi{ };
			UNICODE_STRING unicode{ };
			RtlInitAnsiString( &ansi, path );
			if ( RtlAnsiStringToUnicodeString( &unicode, &ansi, TRUE ) )
				continue;

			OBJECT_ATTRIBUTES attributes{ };
			InitializeObjectAttributes( &attributes, &unicode, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr );
			HANDLE section = nullptr;
			status = ZwOpenSection( &section, READ_CONTROL, &attributes );
			RtlFreeUnicodeString( &unicode );
			if ( status )
				continue;

			void* object = nullptr;
			status = ObReferenceObjectByHandle( section, READ_CONTROL, nullptr, KernelMode, &object, nullptr );
			ZwClose( section );
			if ( status || !object )
				continue;

			if ( sections )
				( *sections )++;

			unsigned long granted_access = 0;
			if ( has_world_full_access( object, &granted_access ) ) {
				char target[ ioctl::m_detection_target_size ]{ };
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA( target, sizeof( target ), "section!%s", object_name );
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"namespace=%s name=%s object=0x%llx world_access=0x%lx",
					scope ? scope : "global",
					object_name,
					reinterpret_cast< unsigned long long >( object ),
					granted_access
				);
				report::add_memory_detection(
					command,
					target,
					report::m_world_writable_section_violation,
					detail,
					reinterpret_cast< unsigned long long >( object ),
					0
				);
				detections++;
			}

			ObDereferenceObject( object );
		}

		memory::free_pool( buffer );
		ZwClose( directory );
		return detections;
	}

	bool reference_symbolic_link_device( const char* name, PDEVICE_OBJECT* device_object ) {
		if ( !name || !device_object )
			return false;

		*device_object = nullptr;
		char path[ 192 ]{ };
		RtlStringCbPrintfA( path, sizeof( path ), "\\GLOBAL??\\%s", name );

		ANSI_STRING ansi{ };
		UNICODE_STRING unicode{ };
		RtlInitAnsiString( &ansi, path );
		if ( RtlAnsiStringToUnicodeString( &unicode, &ansi, TRUE ) )
			return false;

		OBJECT_ATTRIBUTES attributes{ };
		InitializeObjectAttributes( &attributes, &unicode, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr );
		HANDLE link = nullptr;
		auto status = ZwOpenSymbolicLinkObject( &link, SYMBOLIC_LINK_QUERY, &attributes );
		RtlFreeUnicodeString( &unicode );
		if ( status )
			return false;

		wchar_t target_buffer[ 512 ]{ };
		UNICODE_STRING target{ };
		target.Buffer = target_buffer;
		target.MaximumLength = sizeof( target_buffer );
		status = ZwQuerySymbolicLinkObject( link, &target, nullptr );
		ZwClose( link );
		if ( status || !target.Length )
			return false;

		void* object = nullptr;
		status = ObReferenceObjectByName(
			&target,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			nullptr,
			0,
			*IoDeviceObjectType,
			KernelMode,
			nullptr,
			&object
		);
		if ( !status && object ) {
			*device_object = static_cast< PDEVICE_OBJECT >( object );
			return true;
		}

		PFILE_OBJECT file_object = nullptr;
		PDEVICE_OBJECT resolved_device = nullptr;
		status = IoGetDeviceObjectPointer(
			&target,
			FILE_READ_ATTRIBUTES,
			&file_object,
			&resolved_device
		);
		if ( status || !file_object || !resolved_device ) {
			if ( file_object )
				ObDereferenceObject( file_object );
			return false;
		}

		ObReferenceObject( resolved_device );
		ObDereferenceObject( file_object );
		*device_object = resolved_device;
		return true;
	}

	unsigned long scan_public_device_links( ioctl::command_t* command, const system_modules_t* modules, PDRIVER_OBJECT* scanned, unsigned long* scanned_count, unsigned long* links ) {
		HANDLE directory = nullptr;
		if ( !device_surface::open_object_directory( L"\\GLOBAL??", &directory ) )
			return 0;

		auto buffer = memory::allocate_pool( device_surface::m_directory_buffer_size, 1 );
		if ( !buffer ) {
			ZwClose( directory );
			return 0;
		}

		ULONG context = 0;
		ULONG returned = 0;
		unsigned long detections = 0;
		while ( true ) {
			memset( buffer, 0, device_surface::m_directory_buffer_size );
			auto status = ZwQueryDirectoryObject( directory, buffer, device_surface::m_directory_buffer_size, TRUE, FALSE, &context, &returned );
			if ( status )
				break;

			auto entry = static_cast< object_directory_information_t* >( buffer );
			char type_name[ 64 ]{ };
			char object_name[ 128 ]{ };
			device_surface::unicode_to_ascii( entry->m_type_name, type_name, sizeof( type_name ) );
			device_surface::unicode_to_ascii( entry->m_name, object_name, sizeof( object_name ) );
			if ( !ascii_equal_insensitive( type_name, "SymbolicLink" ) )
				continue;

			PDEVICE_OBJECT device_object = nullptr;
			if ( !reference_symbolic_link_device( object_name, &device_object ) )
				continue;

			if ( links )
				( *links )++;

			auto driver_object = device_object->DriverObject;
			auto owner = device_surface::find_driver_owner_module( modules, driver_object );
			auto dispatch_host = owner || !driver_object ? nullptr : device_surface::find_trusted_dispatch_host_module( modules, driver_object );
			auto effective_owner = owner ? owner : dispatch_host;
			if ( driver_object && !dispatch_host && ( device_surface::is_anonymous_unbacked_driver( driver_object ) || !owner ) )
				detections += device_surface::report_device_without_loaded_owner( command, object_name, device_object, driver_object );

			if ( driver_object && device_surface::already_scanned_driver( scanned, *scanned_count, driver_object ) )
				detections += device_surface::dispatch::scan_ioctl_shape( command, modules, effective_owner, driver_object, object_name );
			else if ( driver_object ) {
				if ( dispatch_host )
					detections += device_surface::scan_trusted_hosted_driver( command, modules, dispatch_host, driver_object, object_name );
				else
					detections += device_surface::scan_driver_object( command, modules, owner, driver_object, object_name );
				device_surface::remember_scanned_driver( scanned, scanned_count, driver_object );
			}

			ObDereferenceObject( device_object );
		}

		memory::free_pool( buffer );
		ZwClose( directory );
		return detections;
	}

	bool is_local_system_sid( const unsigned char* sid, size_t available ) {
		if ( !sid || available < 12 )
			return false;

		return sid[ 0 ] == 1 && sid[ 1 ] == 1 &&
			!sid[ 2 ] && !sid[ 3 ] && !sid[ 4 ] && !sid[ 5 ] && !sid[ 6 ] && sid[ 7 ] == 5 &&
			sid[ 8 ] == 18 && !sid[ 9 ] && !sid[ 10 ] && !sid[ 11 ];
	}

	unsigned long scan_physical_memory_section( ioctl::command_t* command ) {
		if ( !command )
			return 0;

		UNICODE_STRING phys_name = RTL_CONSTANT_STRING( L"\\Device\\PhysicalMemory" );
		OBJECT_ATTRIBUTES attributes{ };
		InitializeObjectAttributes( &attributes, &phys_name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr );

		HANDLE section = nullptr;
		if ( !NT_SUCCESS( ZwOpenSection( &section, READ_CONTROL, &attributes ) ) || !section )
			return 0;

		void* object = nullptr;
		auto status = ObReferenceObjectByHandle( section, READ_CONTROL, nullptr, KernelMode, &object, nullptr );
		ZwClose( section );
		if ( !NT_SUCCESS( status ) || !object )
			return 0;

		PSECURITY_DESCRIPTOR security = nullptr;
		BOOLEAN allocated = FALSE;
		unsigned long detections = 0;

		if ( NT_SUCCESS( ObGetObjectSecurity( object, &security, &allocated ) ) && security ) {
			auto relative = static_cast< relative_security_descriptor_t* >( security );
			constexpr auto dacl_present = 0x0004u;
			constexpr auto self_relative = 0x8000u;
			PACL dacl = nullptr;
			if ( relative->m_control & dacl_present ) {
				if ( relative->m_control & self_relative ) {
					if ( relative->m_dacl )
						dacl = reinterpret_cast< PACL >( reinterpret_cast< unsigned char* >( security ) + relative->m_dacl );
				}
				else
					dacl = reinterpret_cast< absolute_security_descriptor_t* >( security )->m_dacl;
			}

			bool tampered = !( relative->m_control & dacl_present ) || !dacl;
			unsigned long rogue_mask = 0;

			if ( dacl && dacl->AclSize >= sizeof( ACL ) ) {
				auto cursor = reinterpret_cast< unsigned char* >( dacl ) + sizeof( ACL );
				auto end = reinterpret_cast< unsigned char* >( dacl ) + dacl->AclSize;
				for ( auto index = 0ul; index < dacl->AceCount && cursor + sizeof( access_allowed_ace_t ) <= end; index++ ) {
					auto ace = reinterpret_cast< access_allowed_ace_t* >( cursor );
					if ( ace->m_header.m_size < sizeof( access_allowed_ace_t ) || cursor + ace->m_header.m_size > end )
						break;

					const auto sid_bytes = reinterpret_cast< const unsigned char* >( &ace->m_sid_start );
					const auto sid_len = ace->m_header.m_size - 8u;
					if ( ace->m_header.m_type == 0 &&
						( ace->m_mask & ( SECTION_MAP_READ | SECTION_MAP_WRITE ) ) != 0 &&
						!is_local_system_sid( sid_bytes, sid_len ) ) {
						tampered = true;
						rogue_mask = ace->m_mask;
						break;
					}

					cursor += ace->m_header.m_size;
				}
			}

			ObReleaseObjectSecurity( security, allocated );

			if ( tampered ) {
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"object=0x%llx non_system_map_mask=0x%lx reason=physical_memory_dacl_exposed",
					reinterpret_cast< unsigned long long >( object ),
					rogue_mask
				);
				report::add_memory_detection(
					command,
					"section!PhysicalMemory",
					report::m_physical_memory_section_violation,
					detail,
					reinterpret_cast< unsigned long long >( object ),
					0
				);
				detections++;
			}
		}

		ObDereferenceObject( object );
		return detections;
	}

	unsigned long scan_kuser_shared_data( ioctl::command_t* command ) {
		if ( !command )
			return 0;

		constexpr auto kuser_va = 0xFFFFF78000000000ull;
		paging::pt_entries_t entries{ };
		if ( !paging::hyperspace_entries( entries, kuser_va ) )
			return 0;

		const bool user_writable = entries.m_pte.hard.user_supervisor && entries.m_pte.hard.read_write;
		const bool executable = !entries.m_pte.hard.no_execute;
		if ( !user_writable && !executable )
			return 0;

		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"va=0x%llx pfn=0x%llx user_rw=%u exec=%u reason=kuser_shared_data_protection",
			kuser_va,
			static_cast< unsigned long long >( entries.m_pte.hard.pfn ),
			user_writable ? 1ul : 0ul,
			executable ? 1ul : 0ul
		);
		report::add_memory_detection(
			command,
			"memory!KUSER_SHARED_DATA",
			report::m_physical_memory_section_violation,
			detail,
			kuser_va,
			PAGE_SIZE
		);
		return 1;
	}

	bool scan( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return false;

		unsigned long named_sections = 0;
		unsigned long symbolic_links = 0;
		PDRIVER_OBJECT scanned_drivers[ 512 ]{ };
		unsigned long scanned_driver_count = 0;

		auto detections = scan_named_sections(
			command, L"\\BaseNamedObjects", "global", &named_sections
		);
		detections += scan_public_device_links(
			command, modules, scanned_drivers, &scanned_driver_count, &symbolic_links
		);
		detections += scan_physical_memory_section( command );
		detections += scan_kuser_shared_data( command );

		command->m_modules_scanned = modules->m_count;
		command->m_sections_scanned = named_sections + symbolic_links + 2;
		command->m_signature_candidates = named_sections + symbolic_links + 2;
		command->m_signature_detections = detections;
		command->m_result = true;
		command->m_error = STATUS_SUCCESS;
		utility::print(
			"object integrity: named sections=%lu links=%lu detections=%lu\n",
			named_sections,
			symbolic_links,
			command->m_total_detection_count
		);
		return true;
	}
}
