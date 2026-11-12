#pragma once

namespace paging {
	namespace remap {
        struct processor_remap_t {
            std::uint64_t m_base_address;
            pte* m_pte_address;
        };

        processor_remap_t* m_processor_remap = nullptr;
        std::uint32_t m_processor_count = 0;

        void destroy( ) {
            if ( !m_processor_remap )
                return;

            for ( auto index = m_processor_count; index > 0; index-- ) {
                auto slot = index - 1;
                if ( m_processor_remap[ slot ].m_base_address ) {
                    memory::free_pages( m_processor_remap[ slot ].m_base_address, page_4kb_size );
                    m_processor_remap[ slot ].m_base_address = 0;
                    m_processor_remap[ slot ].m_pte_address = nullptr;
                }
            }

            memory::free_pages( reinterpret_cast< std::uint64_t >( m_processor_remap ), m_processor_count * sizeof( processor_remap_t ) );
            m_processor_remap = nullptr;
            m_processor_count = 0;
        }

        bool initialize( ) {
            m_processor_count = KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS );
            if ( !m_processor_count )
                return false;

            m_processor_remap = memory::allocate_pages< processor_remap_t* >( m_processor_count * sizeof( processor_remap_t ) );
            if ( !m_processor_remap )
                return false;

            for ( auto index = 0ul; index < m_processor_count; index++ ) {
                m_processor_remap[ index ].m_base_address = memory::allocate_pages< std::uint64_t >( page_4kb_size );
                if ( !m_processor_remap[ index ].m_base_address ) {
                    destroy( );
                    return false;
                }

                m_processor_remap[ index ].m_pte_address = get_pte_address( m_processor_remap[ index ].m_base_address );
                if ( !m_processor_remap[ index ].m_pte_address ) {
                    destroy( );
                    return false;
                }
            }

            return true;
        }

        bool read_physical_page_chunk( std::uint64_t physical_address, void* buffer, std::size_t size ) {
            if ( !m_processor_remap || !buffer || !size )
                return false;

            auto processor = KeGetCurrentProcessorNumberEx( nullptr );
            if ( processor >= m_processor_count )
                return false;

            auto& remapping = m_processor_remap[ processor ];
            if ( !remapping.m_base_address || !remapping.m_pte_address ) {
                return false;
            }

            auto page_offset = static_cast< std::size_t >( physical_address & page_4kb_mask );
            if ( page_offset + size > page_4kb_size )
                return false;

            auto old_pfn = remapping.m_pte_address->hard.pfn;

            _disable( );
            remapping.m_pte_address->hard.pfn = physical_address >> page_shift;
            __invlpg( reinterpret_cast< void* >( remapping.m_base_address ) );
            auto source_ptr = reinterpret_cast< std::uint8_t* >( remapping.m_base_address ) + page_offset;
            __movsb( reinterpret_cast< std::uint8_t* >( buffer ), source_ptr, size );

            remapping.m_pte_address->hard.pfn = old_pfn;
            __invlpg( reinterpret_cast< void* >( remapping.m_base_address ) );
            _enable( );
            return true;
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
