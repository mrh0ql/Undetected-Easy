#pragma once

namespace callback {
	constexpr auto m_blocklist_protocol_version = 1ul;
	constexpr auto m_max_blocklist_entries = 10000ul;
	constexpr auto m_max_blocked_drivers = 256ul;
	constexpr auto m_blocked_drivers_per_query = 64ul;

	enum class blocklist_rule_kind : unsigned long {
		direct_deny,
		denied_signer_file_attribute,
		denied_signer
	};

	struct blocklist_entry_t {
		blocklist_rule_kind m_kind;
		char m_hash[ 65 ];
		char m_file_name[ 128 ];
		char m_internal_name[ 128 ];
		char m_friendly_name[ 128 ];
		char m_product_name[ 128 ];
		char m_file_description[ 128 ];
		char m_minimum_file_version[ 24 ];
		char m_maximum_file_version[ 24 ];
		char m_signer_id[ 64 ];
	};

	struct blocklist_upload_t {
		unsigned long m_protocol_version;
		unsigned long m_total_count;
		unsigned long m_offset;
		unsigned long m_entry_count;
		NTSTATUS m_status;
		BOOLEAN m_finalize;
		BOOLEAN m_result;
		unsigned short m_reserved;
		blocklist_entry_t m_entries[ 1 ];
	};

	static_assert( sizeof( blocklist_entry_t ) == 824 );
	static_assert( FIELD_OFFSET( blocklist_upload_t, m_entries ) == 24 );

	struct blocked_driver_query_t {
		unsigned long m_offset;
		unsigned long m_total_count;
		unsigned long m_returned_count;
		NTSTATUS m_status;
		BOOLEAN m_result;
		unsigned char m_reserved[ 3 ];
		char m_names[ m_blocked_drivers_per_query ][ 128 ];
	};

	static_assert( FIELD_OFFSET( blocked_driver_query_t, m_names ) == 20 );

	inline EX_PUSH_LOCK m_blocklist_lock{ };
	inline blocklist_entry_t* m_vulnerable_driver_blocklist = nullptr;
	inline unsigned long m_vulnerable_driver_blocklist_count = 0;
	inline blocklist_entry_t* m_staging_blocklist = nullptr;
	inline unsigned long m_staging_blocklist_count = 0;
	inline unsigned long m_staging_received = 0;
	inline bool m_image_callback_registered = false;
	inline volatile long m_blocked_image_matches = 0;
	inline char m_blocked_driver_names[ m_max_blocked_drivers ][ 128 ]{ };
	inline unsigned long m_blocked_driver_count = 0;

	inline bool equal_ascii_insensitive( const char* left, const char* right ) {
		if ( !left || !right )
			return false;
		for ( auto index = 0ul; ; index++ ) {
			auto lhs = left[ index ];
			auto rhs = right[ index ];
			if ( lhs >= 'A' && lhs <= 'Z' ) lhs += 'a' - 'A';
			if ( rhs >= 'A' && rhs <= 'Z' ) rhs += 'a' - 'A';
			if ( lhs != rhs )
				return false;
			if ( !lhs )
				return true;
		}
	}

	inline bool equal_image_name( const UNICODE_STRING* full_name, const char* candidate ) {
		if ( !full_name || !full_name->Buffer || !candidate || !candidate[ 0 ] )
			return false;

		auto candidate_length = 0ul;
		while ( candidate[ candidate_length ] )
			candidate_length++;
		const auto character_count = full_name->Length / sizeof( wchar_t );
		if ( !character_count || candidate_length > character_count )
			return false;

		auto name = full_name->Buffer;
		auto name_start = character_count;
		while ( name_start && name[ name_start - 1 ] != L'\\' && name[ name_start - 1 ] != L'/' )
			name_start--;
		if ( character_count - name_start != candidate_length )
			return false;

		for ( auto index = 0ul; index < candidate_length; index++ ) {
			auto left = name[ name_start + index ];
			auto right = static_cast< wchar_t >( static_cast< unsigned char >( candidate[ index ] ) );
			if ( left >= L'A' && left <= L'Z' ) left += L'a' - L'A';
			if ( right >= L'A' && right <= L'Z' ) right += L'a' - L'A';
			if ( left != right )
				return false;
		}
		return true;
	}

	inline void record_blocked_driver_locked( const char* name ) {
		if ( !name || !name[ 0 ] )
			return;
		for ( auto index = 0ul; index < m_blocked_driver_count; index++ ) {
			if ( equal_ascii_insensitive( m_blocked_driver_names[ index ], name ) )
				return;
		}
		if ( m_blocked_driver_count >= m_max_blocked_drivers )
			return;
		RtlStringCbCopyA(
			m_blocked_driver_names[ m_blocked_driver_count ],
			sizeof( m_blocked_driver_names[ 0 ] ),
			name
		);
		m_blocked_driver_count++;
		m_blocked_image_matches = static_cast< long >( m_blocked_driver_count );
	}

	inline bool blocklist_matches_name( const blocklist_entry_t& entry, const char* name ) {
		if ( !name || !name[ 0 ] )
			return false;

		if ( entry.m_kind != blocklist_rule_kind::direct_deny &&
			entry.m_kind != blocklist_rule_kind::denied_signer_file_attribute )
			return false;

		if ( entry.m_file_name[ 0 ] && !equal_ascii_insensitive( entry.m_file_name, "*" ) &&
			equal_ascii_insensitive( entry.m_file_name, name ) )
			return true;

		if ( entry.m_internal_name[ 0 ] && !equal_ascii_insensitive( entry.m_internal_name, "*" ) &&
			equal_ascii_insensitive( entry.m_internal_name, name ) )
			return true;

		return false;
	}

	inline void format_sha1_hex( const sha1_digest_t& digest, char* output, size_t output_size ) {
		if ( !output || output_size < 41 )
			return;

		constexpr const char* hex_digits = "0123456789abcdef";
		for ( auto i = 0u; i < 20u; i++ ) {
			output[ i * 2 ] = hex_digits[ ( digest.m_bytes[ i ] >> 4 ) & 0x0f ];
			output[ i * 2 + 1 ] = hex_digits[ digest.m_bytes[ i ] & 0x0f ];
		}
		output[ 40 ] = '\0';
	}

	inline bool blocklist_matches_sha1( const blocklist_entry_t& entry, const char* sha1_hex ) {
		if ( entry.m_kind != blocklist_rule_kind::direct_deny || !entry.m_hash[ 0 ] || !sha1_hex || !sha1_hex[ 0 ] )
			return false;

		return equal_ascii_insensitive( entry.m_hash, sha1_hex );
	}

	inline bool is_driver_name_blocked( const char* name, char* matched_rule_detail, size_t detail_size ) {
		if ( matched_rule_detail && detail_size )
			matched_rule_detail[ 0 ] = '\0';

		if ( !name || !name[ 0 ] )
			return false;

		bool matched = false;
		KeEnterCriticalRegion( );
		ExAcquirePushLockShared( &m_blocklist_lock );
		for ( auto index = 0ul; index < m_vulnerable_driver_blocklist_count; index++ ) {
			const auto& entry = m_vulnerable_driver_blocklist[ index ];
			if ( blocklist_matches_name( entry, name ) ) {
				matched = true;
				if ( matched_rule_detail && detail_size ) {
					RtlStringCbPrintfA(
						matched_rule_detail,
						detail_size,
						"rule=%s file=%s min_ver=%s max_ver=%s",
						entry.m_friendly_name[ 0 ] ? entry.m_friendly_name : "BlocklistRule",
						entry.m_file_name[ 0 ] ? entry.m_file_name : entry.m_internal_name,
						entry.m_minimum_file_version[ 0 ] ? entry.m_minimum_file_version : "any",
						entry.m_maximum_file_version[ 0 ] ? entry.m_maximum_file_version : "any"
					);
				}
				break;
			}
		}
		ExReleasePushLockShared( &m_blocklist_lock );
		KeLeaveCriticalRegion( );
		return matched;
	}

	inline bool is_driver_sha1_blocked( const char* sha1_hex, char* matched_rule_detail, size_t detail_size ) {
		if ( matched_rule_detail && detail_size )
			matched_rule_detail[ 0 ] = '\0';

		if ( !sha1_hex || !sha1_hex[ 0 ] )
			return false;

		bool matched = false;
		KeEnterCriticalRegion( );
		ExAcquirePushLockShared( &m_blocklist_lock );
		for ( auto index = 0ul; index < m_vulnerable_driver_blocklist_count; index++ ) {
			const auto& entry = m_vulnerable_driver_blocklist[ index ];
			if ( blocklist_matches_sha1( entry, sha1_hex ) ) {
				matched = true;
				if ( matched_rule_detail && detail_size ) {
					RtlStringCbPrintfA(
						matched_rule_detail,
						detail_size,
						"rule=%s sha1=%s",
						entry.m_friendly_name[ 0 ] ? entry.m_friendly_name : "BlocklistHashRule",
						entry.m_hash
					);
				}
				break;
			}
		}
		ExReleasePushLockShared( &m_blocklist_lock );
		KeLeaveCriticalRegion( );
		return matched;
	}

	inline unsigned long scan_loaded_modules( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return 0;

		unsigned long detections = 0;
		for ( auto module_index = 0ul; module_index < modules->m_count; module_index++ ) {
			const auto& mod = modules->m_modules[ module_index ];
			if ( mod.m_offset_to_file_name >= sizeof( mod.m_full_path_name ) )
				continue;

			const auto name = reinterpret_cast< const char* >( mod.m_full_path_name ) + mod.m_offset_to_file_name;
			if ( !name || !name[ 0 ] || module::disk::is_whitelisted_owner( name ) )
				continue;

			char rule_detail[ 160 ]{ };
			bool matched = is_driver_name_blocked( name, rule_detail, sizeof( rule_detail ) );

			if ( !matched ) {
				void* disk_image = nullptr;
				unsigned long disk_size = 0;
				if ( NT_SUCCESS( module::disk::read_module_image_from_disk( mod, &disk_image, &disk_size ) ) && disk_image && disk_size ) {
					auto digest = c_sha1::hash_buffer( disk_image, disk_size );
					memory::free_pool( disk_image );

					char sha1_hex[ 41 ]{ };
					format_sha1_hex( digest, sha1_hex, sizeof( sha1_hex ) );
					matched = is_driver_sha1_blocked( sha1_hex, rule_detail, sizeof( rule_detail ) );
				}
			}

			if ( matched ) {
				KeEnterCriticalRegion( );
				ExAcquirePushLockExclusive( &m_blocklist_lock );
				record_blocked_driver_locked( name );
				ExReleasePushLockExclusive( &m_blocklist_lock );
				KeLeaveCriticalRegion( );

				char target[ ioctl::m_detection_target_size ]{ };
				char detail[ ioctl::m_detection_text_size ]{ };
				RtlStringCbPrintfA( target, sizeof( target ), "blocklist!%s", name );
				RtlStringCbPrintfA(
					detail,
					sizeof( detail ),
					"driver=%s base=0x%llx size=0x%lx %s",
					name,
					reinterpret_cast< unsigned long long >( mod.m_image_base ),
					mod.m_image_size,
					rule_detail
				);
				report::add_memory_detection(
					command,
					target,
					report::m_vulnerable_driver_blocklist_violation,
					detail,
					reinterpret_cast< unsigned long long >( mod.m_image_base ),
					mod.m_image_size ? mod.m_image_size : PAGE_SIZE
				);
				detections++;
			}
		}

		return detections;
	}

	inline void image_load_notify(
		PUNICODE_STRING full_image_name,
		HANDLE process_id,
		PIMAGE_INFO image_info
	) {
		UNREFERENCED_PARAMETER( process_id );
		UNREFERENCED_PARAMETER( image_info );
		if ( !full_image_name )
			return;

		KeEnterCriticalRegion( );
		ExAcquirePushLockExclusive( &m_blocklist_lock );
		for ( auto index = 0ul; index < m_vulnerable_driver_blocklist_count; index++ ) {
			const auto& entry = m_vulnerable_driver_blocklist[ index ];
			if ( ( entry.m_kind == blocklist_rule_kind::direct_deny ||
				entry.m_kind == blocklist_rule_kind::denied_signer_file_attribute ) &&
				entry.m_file_name[ 0 ] &&
				!equal_ascii_insensitive( entry.m_file_name, "*" ) &&
				equal_image_name( full_image_name, entry.m_file_name ) ) {
				const auto name = entry.m_file_name;
				record_blocked_driver_locked( name );
				break;
			}
		}
		ExReleasePushLockExclusive( &m_blocklist_lock );
		KeLeaveCriticalRegion( );
	}

	inline NTSTATUS seed_loaded_drivers( ) {
		system_modules_t* modules = nullptr;
		if ( !memory::query_system_modules( &modules ) || !modules )
			return STATUS_UNSUCCESSFUL;

		for ( auto module_index = 0ul; module_index < modules->m_count; module_index++ ) {
			const auto& mod = modules->m_modules[ module_index ];
			if ( mod.m_offset_to_file_name >= sizeof( mod.m_full_path_name ) )
				continue;
			const auto name = reinterpret_cast< const char* >( mod.m_full_path_name ) +
				mod.m_offset_to_file_name;
			if ( !name || !name[ 0 ] || module::disk::is_whitelisted_owner( name ) )
				continue;

			char rule_detail[ 128 ]{ };
			bool matched = is_driver_name_blocked( name, rule_detail, sizeof( rule_detail ) );
			if ( !matched ) {
				void* disk_image = nullptr;
				unsigned long disk_size = 0;
				if ( NT_SUCCESS( module::disk::read_module_image_from_disk( mod, &disk_image, &disk_size ) ) && disk_image && disk_size ) {
					auto digest = c_sha1::hash_buffer( disk_image, disk_size );
					memory::free_pool( disk_image );

					char sha1_hex[ 41 ]{ };
					format_sha1_hex( digest, sha1_hex, sizeof( sha1_hex ) );
					matched = is_driver_sha1_blocked( sha1_hex, rule_detail, sizeof( rule_detail ) );
				}
			}

			if ( matched ) {
				KeEnterCriticalRegion( );
				ExAcquirePushLockExclusive( &m_blocklist_lock );
				record_blocked_driver_locked( name );
				ExReleasePushLockExclusive( &m_blocklist_lock );
				KeLeaveCriticalRegion( );
			}
		}
		memory::free_pool( modules );
		return STATUS_SUCCESS;
	}

	inline NTSTATUS query_blocked_drivers( blocked_driver_query_t* query, size_t output_length ) {
		if ( !query || output_length < sizeof( blocked_driver_query_t ) )
			return STATUS_BUFFER_TOO_SMALL;

		const auto requested_offset = query->m_offset;
		memset( query, 0, sizeof( *query ) );
		KeEnterCriticalRegion( );
		ExAcquirePushLockShared( &m_blocklist_lock );
		query->m_total_count = m_blocked_driver_count;
		if ( requested_offset < m_blocked_driver_count ) {
			const auto available = m_blocked_driver_count - requested_offset;
			query->m_returned_count = available < m_blocked_drivers_per_query
				? available
				: m_blocked_drivers_per_query;
			memcpy(
				query->m_names,
				m_blocked_driver_names + requested_offset,
				query->m_returned_count * sizeof( query->m_names[ 0 ] )
			);
		}
		ExReleasePushLockShared( &m_blocklist_lock );
		KeLeaveCriticalRegion( );
		return STATUS_SUCCESS;
	}

	inline NTSTATUS setup_image_callback( ) {
		if ( m_image_callback_registered )
			return STATUS_SUCCESS;
		const auto status = PsSetLoadImageNotifyRoutine( image_load_notify );
		if ( !status )
			m_image_callback_registered = true;
		return status;
	}

	inline NTSTATUS upload_blocklist( blocklist_upload_t* request, size_t input_length ) {
		const auto header_size = FIELD_OFFSET( blocklist_upload_t, m_entries );
		if ( !request || input_length < header_size ||
			request->m_protocol_version != m_blocklist_protocol_version ||
			!request->m_total_count || request->m_total_count > m_max_blocklist_entries ||
			!request->m_entry_count ||
			request->m_entry_count > request->m_total_count - request->m_offset ||
			input_length < header_size + sizeof( blocklist_entry_t ) * request->m_entry_count )
			return STATUS_INVALID_PARAMETER;

		if ( request->m_offset == 0 ) {
			auto staging = memory::allocate_pool< blocklist_entry_t* >(
				sizeof( blocklist_entry_t ) * request->m_total_count, 1
			);
			if ( !staging )
				return STATUS_INSUFFICIENT_RESOURCES;
			memset( staging, 0, sizeof( blocklist_entry_t ) * request->m_total_count );

			KeEnterCriticalRegion( );
			ExAcquirePushLockExclusive( &m_blocklist_lock );
			if ( m_staging_blocklist )
				memory::free_pool( m_staging_blocklist );
			m_staging_blocklist = staging;
			m_staging_blocklist_count = request->m_total_count;
			m_staging_received = 0;
			ExReleasePushLockExclusive( &m_blocklist_lock );
			KeLeaveCriticalRegion( );
		}

		KeEnterCriticalRegion( );
		ExAcquirePushLockExclusive( &m_blocklist_lock );
		if ( !m_staging_blocklist ||
			m_staging_blocklist_count != request->m_total_count ||
			m_staging_received != request->m_offset ) {
			ExReleasePushLockExclusive( &m_blocklist_lock );
			KeLeaveCriticalRegion( );
			return STATUS_INVALID_DEVICE_STATE;
		}
		memcpy(
			m_staging_blocklist + request->m_offset,
			request->m_entries,
			sizeof( blocklist_entry_t ) * request->m_entry_count
		);
		m_staging_received += request->m_entry_count;

		if ( request->m_finalize ) {
			if ( m_staging_received != m_staging_blocklist_count ) {
				ExReleasePushLockExclusive( &m_blocklist_lock );
				KeLeaveCriticalRegion( );
				return STATUS_INVALID_BUFFER_SIZE;
			}
			if ( m_vulnerable_driver_blocklist )
				memory::free_pool( m_vulnerable_driver_blocklist );
			m_vulnerable_driver_blocklist = m_staging_blocklist;
			m_vulnerable_driver_blocklist_count = m_staging_blocklist_count;
			m_staging_blocklist = nullptr;
			m_staging_blocklist_count = 0;
			m_staging_received = 0;
			memset( m_blocked_driver_names, 0, sizeof( m_blocked_driver_names ) );
			m_blocked_driver_count = 0;
			m_blocked_image_matches = 0;
		}
		ExReleasePushLockExclusive( &m_blocklist_lock );
		KeLeaveCriticalRegion( );

		if ( !request->m_finalize )
			return STATUS_SUCCESS;
		const auto callback_status = setup_image_callback( );
		if ( !NT_SUCCESS( callback_status ) )
			return callback_status;
		return seed_loaded_drivers( );
	}

	struct ex_callback_routine_block_t {
		EX_RUNDOWN_REF m_rundown_protect;
		void* m_function;
		void* m_context;
	};

	struct ob_callback_entry_item_t {
		LIST_ENTRY m_entry_item_list;
		OB_OPERATION m_operations;
		ULONG m_active;
		void* m_callback_entry;
		POBJECT_TYPE m_object_type;
		void* m_pre_operation;
		void* m_post_operation;
		EX_RUNDOWN_REF m_rundown_protection;
	};

	inline unsigned long validate_callback_target(
		ioctl::command_t* command,
		const system_modules_t* modules,
		const char* table_name,
		unsigned long slot_index,
		unsigned long long routine,
		const char* violation_override = nullptr ) {
		const auto violation_type = violation_override ? violation_override : report::m_kernel_callback_target_violation;
		if ( !command || !modules || !routine )
			return 0;

		if ( !memory::is_canonical_kernel_address( routine ) ) {
			char target[ ioctl::m_detection_target_size ]{ };
			char detail[ ioctl::m_detection_text_size ]{ };
			RtlStringCbPrintfA( target, sizeof( target ), "callback!%s[%lu]", table_name ? table_name : "notify", slot_index );
			RtlStringCbPrintfA( detail, sizeof( detail ), "table=%s slot=%lu target=0x%llx reason=non_canonical_target", table_name ? table_name : "notify", slot_index, routine );
			report::add_memory_detection( command, target, violation_type, detail, routine, sizeof( void* ) );
			return 1;
		}

		command->m_signature_candidates++;

		char section[ 9 ]{ };
		auto owner_mod = module::disk::find_module_by_address( modules, routine );
		const char* owner = owner_mod
			? reinterpret_cast< const char* >( owner_mod->m_full_path_name ) + owner_mod->m_offset_to_file_name
			: nullptr;
		auto executable = owner_mod && module::disk::is_address_in_executable_section( owner_mod, routine, section, sizeof( section ) );

		bool bad_backing = false;
		unsigned long long pfn = 0;
		paging::pt_entries_t entries{ };
		if ( paging::hyperspace_entries( entries, routine ) ) {
			pfn = entries.m_pdpte.hard.page_size ? entries.m_pdpte.hard.pfn :
				entries.m_pde.hard.page_size ? entries.m_pde.hard.pfn :
				entries.m_pte.hard.pfn;
			auto user_page = entries.m_pdpte.hard.page_size ? entries.m_pdpte.hard.user_supervisor :
				entries.m_pde.hard.page_size ? entries.m_pde.hard.user_supervisor :
				entries.m_pte.hard.user_supervisor;
			auto nx_page = entries.m_pdpte.hard.page_size ? entries.m_pdpte.hard.no_execute :
				entries.m_pde.hard.page_size ? entries.m_pde.hard.no_execute :
				entries.m_pte.hard.no_execute;

			std::uint32_t page_size = 0;
			unsigned long long walk_pa = 0;
			paging::translate_linear( routine, &walk_pa, &page_size );
			auto api_pa = static_cast< unsigned long long >( MmGetPhysicalAddress( reinterpret_cast< void* >( routine ) ).QuadPart );
			bad_backing = ( walk_pa && api_pa && walk_pa != api_pa ) || user_page || nx_page;
		}

		if ( owner_mod && executable && !bad_backing )
			return 0;

		char target[ ioctl::m_detection_target_size ]{ };
		char detail[ ioctl::m_detection_text_size ]{ };
		RtlStringCbPrintfA( target, sizeof( target ), "callback!%s[%lu]", table_name ? table_name : "notify", slot_index );
		RtlStringCbPrintfA(
			detail,
			sizeof( detail ),
			"table=%s slot=%lu target=0x%llx owner=%s section=%s pfn=0x%llx bad_pfn=%u",
			table_name ? table_name : "notify",
			slot_index,
			routine,
			owner ? owner : "unknown",
			section[ 0 ] ? section : "unknown",
			pfn,
			bad_backing ? 1ul : 0ul
		);

		report::add_memory_detection(
			command,
			target,
			violation_type,
			detail,
			routine,
			sizeof( void* )
		);
		return 1;
	}

	inline unsigned long scan_notify_array(
		ioctl::command_t* command,
		const system_modules_t* modules,
		unsigned long long array_address,
		const char* array_name ) {
		if ( !command || !modules || !array_address || !memory::is_canonical_kernel_address( array_address ) )
			return 0;

		unsigned long long slots[ 64 ]{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( array_address ), sizeof( slots ), slots, &copied ) )
			return 0;

		unsigned long detections = 0;
		for ( auto index = 0ul; index < 64ul; index++ ) {
			auto block_va = slots[ index ] & ~0xfull;
			if ( !block_va || !memory::is_canonical_kernel_address( block_va ) )
				continue;

			ex_callback_routine_block_t block{ };
			if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( block_va ), sizeof( block ), &block, &copied ) )
				continue;

			detections += validate_callback_target(
				command,
				modules,
				array_name,
				index,
				reinterpret_cast< unsigned long long >( block.m_function )
			);
		}

		return detections;
	}

	inline unsigned long scan_cm_callbacks( ioctl::command_t* command, const system_modules_t* modules ) {
		auto head_address = m_entry.m_pdb.m_cm_callback_list_head;
		if ( !command || !modules || !head_address || !memory::is_canonical_kernel_address( head_address ) )
			return 0;

		auto head = reinterpret_cast< LIST_ENTRY* >( head_address );
		LIST_ENTRY head_copy{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( head, sizeof( head_copy ), &head_copy, &copied ) )
			return 0;

		auto current = head_copy.Flink;
		unsigned long detections = 0;
		unsigned long walked = 0;

		while ( current && current != head && walked < 256ul ) {
			if ( !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( current ) ) )
				break;

			unsigned char raw_block[ 0x48 ]{ };
			if ( !memory::copy_kernel_memory( current, sizeof( raw_block ), raw_block, &copied ) )
				break;

			const auto links = reinterpret_cast< const LIST_ENTRY* >( raw_block );
			unsigned long long function_va = 0;

			auto check_altitude_at = [ & ]( size_t alt_offset ) -> bool {
				if ( alt_offset < sizeof( void* ) || alt_offset + sizeof( UNICODE_STRING ) > sizeof( raw_block ) )
					return false;
				const auto alt = reinterpret_cast< const UNICODE_STRING* >( raw_block + alt_offset );
				return alt->Length > 0 && alt->Length <= alt->MaximumLength &&
					alt->MaximumLength <= 256 && ( alt->Length & 1 ) == 0 &&
					memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( alt->Buffer ) );
			};

			if ( check_altitude_at( 0x30 ) )
				memcpy( &function_va, raw_block + 0x28, sizeof( function_va ) );
			else if ( check_altitude_at( 0x28 ) )
				memcpy( &function_va, raw_block + 0x20, sizeof( function_va ) );

			if ( function_va )
				detections += validate_callback_target( command, modules, "CmCallbackList", walked, function_va );

			current = links->Flink;
			walked++;
		}

		return detections;
	}

	inline unsigned long scan_ob_type_callbacks(
		ioctl::command_t* command,
		const system_modules_t* modules,
		POBJECT_TYPE object_type,
		const char* type_label ) {
		auto list_offset = m_entry.m_offsets.m_object_type_callback_list;
		if ( !command || !modules || !object_type || !list_offset || list_offset > 0x400 )
			return 0;

		auto head_va = reinterpret_cast< unsigned long long >( object_type ) + list_offset;
		if ( !memory::is_canonical_kernel_address( head_va ) )
			return 0;

		auto head = reinterpret_cast< LIST_ENTRY* >( head_va );
		LIST_ENTRY head_copy{ };
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( head, sizeof( head_copy ), &head_copy, &copied ) )
			return 0;

		auto current = head_copy.Flink;
		unsigned long detections = 0;
		unsigned long walked = 0;

		while ( current && current != head && walked < 256ul ) {
			if ( !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( current ) ) )
				break;

			ob_callback_entry_item_t item{ };
			if ( !memory::copy_kernel_memory( current, sizeof( item ), &item, &copied ) )
				break;

			if ( item.m_object_type == object_type && item.m_active ) {
				if ( item.m_pre_operation ) {
					detections += validate_callback_target(
						command,
						modules,
						type_label,
						walked * 2,
						reinterpret_cast< unsigned long long >( item.m_pre_operation )
					);
				}
				if ( item.m_post_operation ) {
					detections += validate_callback_target(
						command,
						modules,
						type_label,
						walked * 2 + 1,
						reinterpret_cast< unsigned long long >( item.m_post_operation )
					);
				}
			}

			current = item.m_entry_item_list.Flink;
			walked++;
		}

		return detections;
	}

	struct knmi_handler_callback_t {
		knmi_handler_callback_t* m_next;
		void* m_callback;
		void* m_context;
		void* m_handle;
	};

	inline unsigned long scan_nmi_callbacks( ioctl::command_t* command, const system_modules_t* modules ) {
		auto head_va = m_entry.m_pdb.m_ki_nmi_callback_list_head;
		if ( !command || !modules || !head_va || !memory::is_canonical_kernel_address( head_va ) )
			return 0;

		knmi_handler_callback_t* current = nullptr;
		size_t copied = 0;
		if ( !memory::copy_kernel_memory( reinterpret_cast< void* >( head_va ), sizeof( current ), &current, &copied ) )
			return 0;

		unsigned long detections = 0;
		for ( auto walked = 0ul; current && walked < 64ul; walked++ ) {
			auto current_va = reinterpret_cast< unsigned long long >( current );
			if ( !memory::is_canonical_kernel_address( current_va ) )
				break;

			knmi_handler_callback_t node{ };
			if ( !memory::copy_kernel_memory( current, sizeof( node ), &node, &copied ) )
				break;

			if ( node.m_callback ) {
				detections += validate_callback_target(
					command,
					modules,
					"KiNmiCallbackList",
					walked,
					reinterpret_cast< unsigned long long >( node.m_callback ),
					report::m_nmi_callback_violation
				);
			}

			current = node.m_next;
		}

		return detections;
	}

	inline unsigned long scan_bugcheck_callbacks( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return 0;

		unsigned long detections = 0;
		size_t copied = 0;

		auto bc_head_va = m_entry.m_pdb.m_ke_bugcheck_callback_list_head;
		if ( bc_head_va && memory::is_canonical_kernel_address( bc_head_va ) ) {
			auto head = reinterpret_cast< LIST_ENTRY* >( bc_head_va );
			LIST_ENTRY head_copy{ };
			if ( memory::copy_kernel_memory( head, sizeof( head_copy ), &head_copy, &copied ) ) {
				auto current = head_copy.Flink;
				for ( auto walked = 0ul; current && current != head && walked < 256ul; walked++ ) {
					if ( !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( current ) ) )
						break;

					KBUGCHECK_CALLBACK_RECORD record{ };
					if ( !memory::copy_kernel_memory( current, sizeof( record ), &record, &copied ) )
						break;

					if ( record.State == BufferInserted && record.CallbackRoutine ) {
						detections += validate_callback_target(
							command,
							modules,
							"KeBugCheckCallbackList",
							walked,
							reinterpret_cast< unsigned long long >( record.CallbackRoutine ),
							report::m_bugcheck_callback_violation
						);
					}

					current = record.Entry.Flink;
				}
			}
		}

		auto bcr_head_va = m_entry.m_pdb.m_ke_bugcheck_reason_callback_list_head;
		if ( bcr_head_va && memory::is_canonical_kernel_address( bcr_head_va ) ) {
			auto head = reinterpret_cast< LIST_ENTRY* >( bcr_head_va );
			LIST_ENTRY head_copy{ };
			if ( memory::copy_kernel_memory( head, sizeof( head_copy ), &head_copy, &copied ) ) {
				auto current = head_copy.Flink;
				for ( auto walked = 0ul; current && current != head && walked < 256ul; walked++ ) {
					if ( !memory::is_canonical_kernel_address( reinterpret_cast< unsigned long long >( current ) ) )
						break;

					KBUGCHECK_REASON_CALLBACK_RECORD record{ };
					if ( !memory::copy_kernel_memory( current, sizeof( record ), &record, &copied ) )
						break;

					if ( record.State == BufferInserted && record.CallbackRoutine ) {
						detections += validate_callback_target(
							command,
							modules,
							"KeBugCheckReasonCallbackList",
							walked,
							reinterpret_cast< unsigned long long >( record.CallbackRoutine ),
							report::m_bugcheck_callback_violation
						);
					}

					current = record.Entry.Flink;
				}
			}
		}

		return detections;
	}

	inline unsigned long scan_kernel_callbacks( ioctl::command_t* command, const system_modules_t* modules ) {
		if ( !command || !modules )
			return 0;

		unsigned long detections = 0;
		detections += scan_notify_array( command, modules, m_entry.m_pdb.m_psp_create_process_notify_routine, "PspCreateProcessNotifyRoutine" );
		detections += scan_notify_array( command, modules, m_entry.m_pdb.m_psp_create_thread_notify_routine, "PspCreateThreadNotifyRoutine" );
		detections += scan_notify_array( command, modules, m_entry.m_pdb.m_psp_load_image_notify_routine, "PspLoadImageNotifyRoutine" );
		detections += scan_cm_callbacks( command, modules );
		detections += scan_nmi_callbacks( command, modules );
		detections += scan_bugcheck_callbacks( command, modules );
		if ( PsProcessType && *PsProcessType )
			detections += scan_ob_type_callbacks( command, modules, *PsProcessType, "ObProcessCallbacks" );
		if ( PsThreadType && *PsThreadType )
			detections += scan_ob_type_callbacks( command, modules, *PsThreadType, "ObThreadCallbacks" );

		return detections;
	}

	inline void destroy( ) {
		if ( m_image_callback_registered ) {
			PsRemoveLoadImageNotifyRoutine( image_load_notify );
			m_image_callback_registered = false;
		}

		KeEnterCriticalRegion( );
		ExAcquirePushLockExclusive( &m_blocklist_lock );
		if ( m_vulnerable_driver_blocklist )
			memory::free_pool( m_vulnerable_driver_blocklist );
		if ( m_staging_blocklist )
			memory::free_pool( m_staging_blocklist );
		m_vulnerable_driver_blocklist = nullptr;
		m_vulnerable_driver_blocklist_count = 0;
		m_staging_blocklist = nullptr;
		m_staging_blocklist_count = 0;
		m_staging_received = 0;
		memset( m_blocked_driver_names, 0, sizeof( m_blocked_driver_names ) );
		m_blocked_driver_count = 0;
		m_blocked_image_matches = 0;
		ExReleasePushLockExclusive( &m_blocklist_lock );
		KeLeaveCriticalRegion( );
	}
}
