#pragma once

namespace config {
	constexpr auto m_value_name = L"Config";

	NTSTATUS query_binary_value( HANDLE key, const wchar_t* value_name, void* buffer, ULONG buffer_size ) {
		if ( !key || !value_name || !buffer || !buffer_size )
			return STATUS_INVALID_PARAMETER;

		UNICODE_STRING value_string{ };
		RtlInitUnicodeString( &value_string, value_name );

		ULONG required_size = 0;
		auto status = ZwQueryValueKey(
			key,
			&value_string,
			KeyValuePartialInformation,
			nullptr,
			0,
			&required_size
		);

		if ( status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW )
			return status;

		auto value_info = memory::allocate_pool< KEY_VALUE_PARTIAL_INFORMATION* >( required_size, 1 );
		if ( !value_info )
			return STATUS_INSUFFICIENT_RESOURCES;

		memset( value_info, 0, required_size );

		status = ZwQueryValueKey(
			key,
			&value_string,
			KeyValuePartialInformation,
			value_info,
			required_size,
			&required_size
		);

		if ( !status ) {
			if ( value_info->Type != REG_BINARY || value_info->DataLength != buffer_size ) {
				status = STATUS_INFO_LENGTH_MISMATCH;
			}
			else {
				memcpy( buffer, value_info->Data, buffer_size );
			}
		}

		memory::free_pool( value_info );
		return status;
	}

	bool read( PUNICODE_STRING registry_path ) {
		if ( !registry_path || !registry_path->Buffer || !registry_path->Length )
			return false;

		wchar_t parameters_path[ 512 ]{ };
		auto result = RtlStringCbPrintfW(
			parameters_path,
			sizeof( parameters_path ),
			L"%wZ\\Parameters",
			registry_path
		);

		if ( result )
			return false;

		UNICODE_STRING parameters_string{ };
		RtlInitUnicodeString( &parameters_string, parameters_path );

		OBJECT_ATTRIBUTES attributes{ };
		InitializeObjectAttributes( &attributes, &parameters_string, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );

		HANDLE key = nullptr;
		result = ZwOpenKey( &key, KEY_READ, &attributes );
		if ( result )
			return false;

		entry_t entry{ };
		result = query_binary_value( key, m_value_name, &entry, sizeof( entry ) );
		ZwClose( key );

		if ( result )
			return false;

		m_entry = entry;
		utility::print(
			"config loaded -> ntoskrnl=0x%llx\n",
			m_entry.m_ntoskrnl_base,
			m_entry.m_pdb.m_mm_allocate_independent_pages
		);

		return true;
	}
}
