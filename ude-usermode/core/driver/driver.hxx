#pragma once

namespace driver {
	constexpr auto m_ping_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_module_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_execution_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_memory_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_device_surface_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_pool_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_service_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_fetch_detections_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_cpu_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_object_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_dpc_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_process_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80c, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_setup_image_callback_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80d, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_query_blocked_drivers_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80e, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_max_detections = 64ul;
	constexpr auto m_max_snapshot_detections = 65536ul;
	constexpr auto m_detection_target_size = 96ul;
	constexpr auto m_detection_text_size = 96ul;
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

	constexpr auto m_blocked_drivers_per_query = 64ul;
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

    struct detection_t {
		CHAR m_target[ m_detection_target_size ];
		CHAR m_type[ m_detection_text_size ];
		CHAR m_method[ m_detection_text_size ];
		ULONG64 m_address;
		ULONG m_size;
		NTSTATUS m_error;
	};

	struct command_t {
		bool m_result;
		NTSTATUS m_error;
		ULONG m_detection_count;
		ULONG m_total_detection_count;
		ULONG m_detection_offset;
		ULONG m_detection_session;
		ULONG m_detection_dropped_count;
		bool m_has_more_detections;
		ULONG m_modules_scanned;
		ULONG m_sections_scanned;
		ULONG m_dirty_chunks;
		ULONG m_raw_ranges;
		ULONG m_ignored_ranges;
		ULONG m_signature_candidates;
		ULONG m_signature_detections;
		ULONG m_relocated_bytes;
		ULONG m_nonzero_live_bytes;
		detection_t m_detections[ m_max_detections ];
	};

	class c_driver {
	public:
		~c_driver( ) {
			close( );
		}

		bool setup( ) {
			close( );

			m_handle = CreateFileW(
				obf( L"\\\\.\\ude" ),
				GENERIC_READ | GENERIC_WRITE,
				0,
				nullptr,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				nullptr
			);

			return m_handle != INVALID_HANDLE_VALUE;
		}

		void close( ) {
			if ( m_handle && m_handle != INVALID_HANDLE_VALUE ) {
				CloseHandle( m_handle );
				m_handle = INVALID_HANDLE_VALUE;
			}
		}

		bool ping( ) {
			command_t command{ };
			return send_command( m_ping_code, &command );
		}

		bool module_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_module_integrity_code, command );
		}

		bool execution_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_execution_integrity_code, command );
		}

		bool memory_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_memory_integrity_code, command );
		}

		bool device_surface( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_device_surface_code, command );
		}

		bool service_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_service_integrity_code, command );
		}

		bool pool_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_pool_integrity_code, command );
		}

		bool cpu_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_cpu_integrity_code, command );
		}

		bool object_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_object_integrity_code, command );
		}

		bool dpc_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_dpc_integrity_code, command );
		}

		bool process_integrity( command_t* command ) {
			if ( !command )
				return false;

			*command = {};
			return send_command( m_process_integrity_code, command );
		}

		bool fetch_detections( command_t* command, ULONG offset, ULONG session ) {
			if ( !command )
				return false;

			*command = {};
			command->m_detection_offset = offset;
			command->m_detection_session = session;
			return send_command( m_fetch_detections_code, command );
		}
        bool setup_image_callback( const blocklist::policy_t& policy ) {
            if ( policy.rules.empty( ) || policy.rules.size( ) > 10000 )
                return false;

            constexpr auto protocol_version = 1ul;
            constexpr auto entries_per_request = 32ul;
            const auto header_size = FIELD_OFFSET( blocklist_upload_t, m_entries );
            auto copy_text = [ ]( char* destination, size_t capacity, const std::string& source ) {
                if ( !destination || !capacity )
                    return;
                strncpy_s( destination, capacity, source.c_str( ), _TRUNCATE );
            };

            const auto total = static_cast< unsigned long >( policy.rules.size( ) );
            for ( auto offset = 0ul; offset < total; offset += entries_per_request ) {
                const auto count = ( std::min )( entries_per_request, total - offset );
                std::vector< std::uint8_t > storage(
                    header_size + sizeof( blocklist_entry_t ) * count, 0
                );
                auto request = reinterpret_cast< blocklist_upload_t* >( storage.data( ) );
                request->m_protocol_version = protocol_version;
                request->m_total_count = total;
                request->m_offset = offset;
                request->m_entry_count = count;
                request->m_finalize = offset + count == total;

                for ( auto index = 0ul; index < count; index++ ) {
                    const auto& source = policy.rules[ offset + index ];
                    auto& destination = request->m_entries[ index ];
                    destination.m_kind = static_cast< blocklist_rule_kind >( source.kind );
                    copy_text( destination.m_hash, sizeof( destination.m_hash ), source.hash );
                    copy_text( destination.m_file_name, sizeof( destination.m_file_name ), source.file_name );
                    copy_text( destination.m_internal_name, sizeof( destination.m_internal_name ), source.internal_name );
                    copy_text( destination.m_friendly_name, sizeof( destination.m_friendly_name ), source.friendly_name );
                    copy_text( destination.m_product_name, sizeof( destination.m_product_name ), source.product_name );
                    copy_text( destination.m_file_description, sizeof( destination.m_file_description ), source.file_description );
                    copy_text( destination.m_minimum_file_version, sizeof( destination.m_minimum_file_version ), source.minimum_file_version );
                    copy_text( destination.m_maximum_file_version, sizeof( destination.m_maximum_file_version ), source.maximum_file_version );
                    copy_text( destination.m_signer_id, sizeof( destination.m_signer_id ), source.signer_id );
                }

                DWORD bytes_returned = 0;
                const auto sent = DeviceIoControl(
                    m_handle,
                    m_setup_image_callback_code,
                    request,
                    static_cast< DWORD >( storage.size( ) ),
                    request,
                    static_cast< DWORD >( storage.size( ) ),
                    &bytes_returned,
                    nullptr
                );
                if ( !sent || bytes_returned < header_size || !request->m_result )
                    return false;
            }
            return true;
        }

		bool query_blocked_drivers( std::vector< std::string >& names ) {
			names.clear( );
			auto offset = 0ul;
			for ( ;; ) {
				blocked_driver_query_t query{ };
				query.m_offset = offset;
				DWORD bytes_returned = 0;
				const auto sent = DeviceIoControl(
					m_handle,
					m_query_blocked_drivers_code,
					&query,
					sizeof( query ),
					&query,
					sizeof( query ),
					&bytes_returned,
					nullptr
				);
				if ( !sent || bytes_returned != sizeof( query ) || !query.m_result )
					return false;

				for ( auto index = 0ul; index < query.m_returned_count; index++ )
					names.emplace_back( query.m_names[ index ] );
				offset += query.m_returned_count;
				if ( offset >= query.m_total_count )
					return true;
				if ( !query.m_returned_count )
					return false;
			}
		}
	private:
		HANDLE m_handle = INVALID_HANDLE_VALUE;

		bool send_command( DWORD control_code, command_t* command ) {
			if ( !command )
				return false;

			DWORD bytes_returned = 0;
			auto result = DeviceIoControl(
				m_handle,
				control_code,
				command,
				sizeof( *command ),
				command,
				sizeof( *command ),
				&bytes_returned,
				nullptr
			);

			if ( !result || bytes_returned != sizeof( *command ) )
				return false;

			return command->m_result;
		}
	};
}
