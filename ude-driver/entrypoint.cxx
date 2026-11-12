#include "includes.h"

void driver_unload( PDRIVER_OBJECT driver_object ) {
	ioctl::destroy( );
	module::protection::free_kernel_image_snapshot( );
	paging::remap::destroy( );
	memory::pool::cleanup( );
	utility::print( "unloaded ioctl\n" );
}

NTSTATUS entry_point( PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path ) {
	if ( !driver_object || !registry_path )
		return STATUS_INVALID_PARAMETER;

	memory::pool::setup( );
	if ( !config::read( registry_path ) ) {
		utility::print( "failed to read config.\n" );
		memory::pool::cleanup( );
		return STATUS_UNSUCCESSFUL;
	}

	paging::m_directory_table_base = *reinterpret_cast< std::uint64_t* >( 
		reinterpret_cast< std::uint64_t >( PsInitialSystemProcess ) + 0x28 );
	if ( !paging::remap::initialize( ) ) {
		utility::print( "failed to initialize remap.\n" );
		memory::pool::cleanup( );
		return STATUS_UNSUCCESSFUL;
	}

	driver_object->DriverUnload = driver_unload;
	if ( !ioctl::initialize( driver_object ) ) {
		paging::remap::destroy( );
		memory::pool::cleanup( );
		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
}
