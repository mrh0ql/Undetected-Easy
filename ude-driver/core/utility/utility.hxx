#pragma once

namespace utility {
	template<typename... args_t>
	void print( const char* format, args_t... args ) {
		DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, args... );
	}
}
