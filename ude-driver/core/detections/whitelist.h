#pragma once

namespace detections {
	constexpr const char* m_whitelisted_modules[ ] = {
		"ntoskrnl.exe",
		"tm.sys",
		"clipsp.sys",
		"PSHED.dll",
		"BOOTVID.dll",
		"cng.sys",
		"kdcom.dll",
		"kd.dll",
		"NETIO.SYS",
		"TDI.SYS",
		"storport.sys",
		"ndis.sys",
		"WppRecorder.sys",
		"WDFLDR.SYS",
		"CLASSPNP.SYS",
		"WMILIB.SYS",
		"Wdf01000.sys",
		"CLFS.SYS",
		"msrpc.sys",
		"cmimcext.sys",
		"CI.dll",
		"dxgkrnl.sys",
		"werkernel.sys",
		"ntosext.sys"
	};

	bool is_whitelisted_owner( const char* owner ) {
		if ( !owner )
			return false;

		for ( auto index = 0ul; index < ARRAYSIZE( m_whitelisted_modules ); index++ ) {
			if ( ascii_equal_insensitive( owner, m_whitelisted_modules[ index ] ) )
				return true;
		}

		return false;
	}

	bool is_suspicious_external_target( const system_modules_t* modules, const system_module_t* module, unsigned long long target ) {
		if ( !modules || !module || !target )
			return false;

		auto module_base = reinterpret_cast< unsigned long long >( module->m_image_base );
		auto module_end = module_base + module->m_image_size;
		if ( module_end > module_base && target >= module_base && target < module_end )
			return false;

		for ( auto index = 0ul; index < modules->m_count; index++ ) {
			auto target_module = &modules->m_modules[ index ];
			auto target_base = reinterpret_cast< unsigned long long >( target_module->m_image_base );
			auto target_end = target_base + target_module->m_image_size;
			if ( target_end <= target_base || target < target_base || target >= target_end )
				continue;

			auto image = static_cast< const unsigned char* >( target_module->m_image_base );
			auto headers = memory::validate_pe_image( image, target_module->m_image_size );
			if ( !headers )
				return true;

			auto rva = static_cast< unsigned long >( target - target_base );
			auto sections = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS64* >( headers ) );
			for ( auto section_index = 0u; section_index < headers->FileHeader.NumberOfSections; section_index++ ) {
				auto section_start = sections[ section_index ].VirtualAddress;
				auto section_size = sections[ section_index ].Misc.VirtualSize;
				if ( section_size < sections[ section_index ].SizeOfRawData )
					section_size = sections[ section_index ].SizeOfRawData;

				auto section_end = section_start + section_size;
				if ( section_end <= section_start || rva < section_start || rva >= section_end )
					continue;

				return !( sections[ section_index ].Characteristics & IMAGE_SCN_MEM_EXECUTE );
			}

			return true;
		}

		return memory::is_canonical_kernel_address( target );
	}
}
