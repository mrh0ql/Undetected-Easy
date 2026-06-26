#pragma once

namespace ioctl {
	constexpr auto m_ping_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_module_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_execution_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_memory_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_device_surface_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_pool_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_service_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_fetch_detections_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_callback_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_cpu_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_object_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_dpc_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_process_integrity_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80c, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_setup_image_callback_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80d, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_query_blocked_drivers_code = CTL_CODE( FILE_DEVICE_UNKNOWN, 0x80e, METHOD_BUFFERED, FILE_ANY_ACCESS );
	constexpr auto m_max_detections = 64ul;
	constexpr auto m_max_snapshot_detections = 65536ul;
	constexpr auto m_detection_page_capacity = 256ul;
	constexpr auto m_detection_target_size = 96ul;
	constexpr auto m_detection_text_size = 96ul;

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

	struct detection_page_t {
		detection_page_t* m_next;
		ULONG m_count;
		detection_t m_detections[ m_detection_page_capacity ];
	};

	detection_page_t* m_detection_snapshot_head = nullptr;
	detection_page_t* m_detection_snapshot_tail = nullptr;
	ULONG m_detection_snapshot_count = 0;
	ULONG m_detection_snapshot_dropped = 0;
	ULONG m_detection_snapshot_session = 1;

	void free_detection_snapshot( ) {
		auto page = m_detection_snapshot_head;
		while ( page ) {
			auto next = page->m_next;
			memory::free_pool( page );
			page = next;
		}

		m_detection_snapshot_head = nullptr;
		m_detection_snapshot_tail = nullptr;
		m_detection_snapshot_count = 0;
		m_detection_snapshot_dropped = 0;
		m_detection_snapshot_session++;
		if ( !m_detection_snapshot_session )
			m_detection_snapshot_session = 1;
	}

	void reset_command( command_t* command ) {
		if ( !command )
			return;

		memset( command, 0, sizeof( *command ) );
		command->m_error = STATUS_SUCCESS;
	}

	bool copy_text( CHAR* destination, SIZE_T destination_size, const CHAR* source ) {
		if ( !destination || !destination_size )
			return false;

		destination[ 0 ] = 0;

		if ( !source )
			return false;

		return !RtlStringCbCopyA( destination, destination_size, source );
	}

	bool append_detection_to_snapshot( const detection_t& source ) {
		if ( m_detection_snapshot_count >= m_max_snapshot_detections ) {
			m_detection_snapshot_dropped++;
			return false;
		}

		if ( !m_detection_snapshot_tail || m_detection_snapshot_tail->m_count >= m_detection_page_capacity ) {
			auto page = memory::allocate_pool< detection_page_t* >( sizeof( detection_page_t ), 1 );
			if ( !page ) {
				m_detection_snapshot_dropped++;
				return false;
			}

			memset( page, 0, sizeof( *page ) );
			if ( m_detection_snapshot_tail )
				m_detection_snapshot_tail->m_next = page;
			else
				m_detection_snapshot_head = page;

			m_detection_snapshot_tail = page;
		}

		auto detection = &m_detection_snapshot_tail->m_detections[ m_detection_snapshot_tail->m_count++ ];
		memcpy( detection, &source, sizeof( *detection ) );
		m_detection_snapshot_count++;
		return true;
	}

	bool copy_detection_window( command_t* command, ULONG offset ) {
		if ( !command )
			return false;

		command->m_detection_count = 0;
		command->m_total_detection_count = m_detection_snapshot_count;
		command->m_detection_offset = offset;
		command->m_detection_session = m_detection_snapshot_session;
		command->m_detection_dropped_count = m_detection_snapshot_dropped;
		command->m_has_more_detections = offset < m_detection_snapshot_count;
		memset( command->m_detections, 0, sizeof( command->m_detections ) );

		if ( offset >= m_detection_snapshot_count )
			return true;

		ULONG skipped = 0;
		auto page = m_detection_snapshot_head;
		while ( page && skipped + page->m_count <= offset ) {
			skipped += page->m_count;
			page = page->m_next;
		}

		while ( page && command->m_detection_count < m_max_detections ) {
			auto start = offset > skipped ? offset - skipped : 0;
			for ( auto index = start; index < page->m_count && command->m_detection_count < m_max_detections; index++ ) {
				memcpy(
					&command->m_detections[ command->m_detection_count++ ],
					&page->m_detections[ index ],
					sizeof( detection_t )
				);
			}

			skipped += page->m_count;
			page = page->m_next;
			offset = skipped;
		}

		command->m_has_more_detections = command->m_detection_offset + command->m_detection_count < m_detection_snapshot_count;
		return true;
	}

	bool add_detection( command_t* command, const CHAR* target, const CHAR* type, const CHAR* method, ULONG64 address, ULONG size, NTSTATUS error ) {
		if ( !command )
			return false;

		detection_t snapshot_detection{ };
		auto detection = &snapshot_detection;
		memset( detection, 0, sizeof( *detection ) );

		copy_text( detection->m_target, sizeof( detection->m_target ), target );
		copy_text( detection->m_type, sizeof( detection->m_type ), type );
		copy_text( detection->m_method, sizeof( detection->m_method ), method );
		detection->m_address = address;
		detection->m_size = size;
		detection->m_error = error;

		if ( !append_detection_to_snapshot( snapshot_detection ) ) {
			command->m_total_detection_count = m_detection_snapshot_count;
			command->m_detection_dropped_count = m_detection_snapshot_dropped;
			command->m_has_more_detections = false;
			return false;
		}

		command->m_total_detection_count = m_detection_snapshot_count;
		command->m_detection_session = m_detection_snapshot_session;
		command->m_detection_dropped_count = m_detection_snapshot_dropped;
		if ( command->m_detection_count < m_max_detections ) {
			memcpy( &command->m_detections[ command->m_detection_count++ ], &snapshot_detection, sizeof( snapshot_detection ) );
			command->m_has_more_detections = m_detection_snapshot_count > command->m_detection_count;
		}
		else {
			command->m_has_more_detections = true;
		}

		return true;
	}
}
