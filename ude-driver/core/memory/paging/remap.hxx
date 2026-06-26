#pragma once

namespace paging {
	namespace remap {
        struct processor_remap_t {
            std::uint64_t m_base_address;
            pte* m_pte_address;
        };

        processor_remap_t* m_processor_remap = nullptr;
        std::uint32_t m_processor_count = 0;

        bool initialize( ) {
            m_processor_count = KeQueryActiveProcessorCountEx( ALL_PROCESSOR_GROUPS );
            if ( !m_processor_count )
                return false;

            m_processor_remap = memory::allocate_pages< processor_remap_t* >( m_processor_count * sizeof( processor_remap_t ) );
            if ( !m_processor_remap )
                return false;

            for ( auto index = 0ul; index < m_processor_count; index++ ) {
                m_processor_remap[ index ].m_base_address = memory::allocate_pages< std::uint64_t >( page_4kb_size );
                if ( !m_processor_remap[ index ].m_base_address )
                    return false;

                m_processor_remap[ index ].m_pte_address = get_pte_address( m_processor_remap[ index ].m_base_address );
                if ( !m_processor_remap[ index ].m_pte_address )
                    return false;
            }

            return true;
        }

        bool read_physical( std::uint64_t physical_address, void* buffer, std::size_t size ) {
            auto processor = KeGetCurrentProcessorNumber( );
            auto& remapping = m_processor_remap[ processor ];
            if ( !remapping.m_base_address || !remapping.m_pte_address ) {
                return false;
            }

            auto old_pfn = remapping.m_pte_address->hard.pfn;

            _disable( );
            remapping.m_pte_address->hard.pfn = physical_address >> page_shift;
            __invlpg( reinterpret_cast< void* >( remapping.m_base_address ) );
            auto source_ptr = reinterpret_cast< std::uint8_t* >( remapping.m_base_address ) + ( physical_address & page_4kb_mask );
            __movsb( reinterpret_cast< std::uint8_t* >( buffer ), source_ptr, size );

            remapping.m_pte_address->hard.pfn = old_pfn;
            __invlpg( reinterpret_cast< void* >( remapping.m_base_address ) );
            _enable( );
            return true;
        }
	}
}
