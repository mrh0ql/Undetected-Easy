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
		if ( entry.m_kind != blocklist_rule_kind::direct_deny || !entry.m_file_name[ 0 ] )
			return false;
		if ( !equal_ascii_insensitive( entry.m_minimum_file_version, "0.0.0.0" ) ||
			!equal_ascii_insensitive( entry.m_maximum_file_version, "65535.65535.65535.65535" ) )
			return false;
		return equal_ascii_insensitive( entry.m_file_name, name );
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
			if ( entry.m_kind == blocklist_rule_kind::direct_deny &&
				equal_ascii_insensitive( entry.m_minimum_file_version, "0.0.0.0" ) &&
				equal_ascii_insensitive( entry.m_maximum_file_version, "65535.65535.65535.65535" ) &&
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

		KeEnterCriticalRegion( );
		ExAcquirePushLockExclusive( &m_blocklist_lock );
		for ( auto module_index = 0ul; module_index < modules->m_count; module_index++ ) {
			const auto& module = modules->m_modules[ module_index ];
			if ( module.m_offset_to_file_name >= sizeof( module.m_full_path_name ) )
				continue;
			const auto name = reinterpret_cast< const char* >( module.m_full_path_name ) +
				module.m_offset_to_file_name;
			for ( auto rule_index = 0ul; rule_index < m_vulnerable_driver_blocklist_count; rule_index++ ) {
				if ( blocklist_matches_name( m_vulnerable_driver_blocklist[ rule_index ], name ) ) {
					record_blocked_driver_locked( name );
					break;
				}
			}
		}
		ExReleasePushLockExclusive( &m_blocklist_lock );
		KeLeaveCriticalRegion( );
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
