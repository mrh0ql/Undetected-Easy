#pragma once

namespace paging {
	namespace remap {
        void destroy( ) {
        }

        bool initialize( ) {
            return true;
        }

        bool read_physical_page_chunk( std::uint64_t physical_address, void* buffer, std::size_t size ) {
            if ( !buffer || !size )
                return false;

            auto page_offset = static_cast< std::size_t >( physical_address & page_4kb_mask );
            if ( page_offset + size > page_4kb_size )
                return false;

            MM_COPY_ADDRESS copy_addr{};
            copy_addr.PhysicalAddress.QuadPart = static_cast< LONGLONG >( physical_address );
            SIZE_T bytes_transferred = 0;
            const auto status = MmCopyMemory(
                buffer,
                copy_addr,
                size,
                MM_COPY_MEMORY_PHYSICAL,
                &bytes_transferred
            );

            return NT_SUCCESS( status ) && bytes_transferred == size;
        }

        bool read_physical( std::uint64_t physical_address, void* buffer, std::size_t size ) {
            if ( !buffer || !size )
                return false;

            auto destination = reinterpret_cast< std::uint8_t* >( buffer );
            std::size_t remaining = size;
            std::uint64_t current_pa = physical_address;

            while ( remaining > 0 ) {
                auto page_offset = static_cast< std::size_t >( current_pa & page_4kb_mask );
                auto chunk_size = page_4kb_size - page_offset;
                if ( chunk_size > remaining )
                    chunk_size = remaining;

                if ( !read_physical_page_chunk( current_pa, destination, chunk_size ) )
                    return false;

                destination += chunk_size;
                current_pa += chunk_size;
                remaining -= chunk_size;
            }

            return true;
        }
	}
}
