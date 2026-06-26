#pragma once

namespace memory {
    namespace pool {
        list_entry_t m_list_head;
        bool m_initialized = false;
        constexpr unsigned long m_pool_tag =
            static_cast< unsigned long >( 'U' ) |
            ( static_cast< unsigned long >( 'd' ) << 8 ) |
            ( static_cast< unsigned long >( 'e' ) << 16 ) |
            ( static_cast< unsigned long >( 'P' ) << 24 );

        struct pool_entry_t {
            list_entry_t  m_list;
            unsigned long m_tag;
            size_t        m_size;
        };

        unsigned long random_tag( ) {
            unsigned int low = *reinterpret_cast< unsigned int* >( 0xFFFFF78000000000 );
            unsigned int mul = *reinterpret_cast< unsigned int* >( 0xFFFFF78000000004 );
            auto seed = ( ( std::uint64_t )( low ) * ( std::uint64_t )( mul ) ) >> 24;

            auto r1 = RtlRandomEx( ( unsigned long* )&seed );
            auto r2 = RtlRandomEx( ( unsigned long* )&seed );
            return ( r1 & 0xFFFF0000 ) | ( r2 & 0x0000FFFF );
        }

        void setup( ) {
            if ( m_initialized )
                return;

            list_init( &m_list_head );
            m_initialized = true;
        }

        template <typename result_t>
        result_t allocate( size_t size, int type ) {
            setup( );

            auto pool = reinterpret_cast< uintptr_t >(
                ExAllocatePoolWithTag( static_cast< POOL_TYPE >( type ), size + sizeof( pool_entry_t ), m_pool_tag ) );
            if ( !pool )
                return nullptr;

            auto entry = reinterpret_cast< pool_entry_t* >( pool );
            entry->m_tag = m_pool_tag;
            entry->m_size = size;

            list_insert_tail( &m_list_head, &entry->m_list );
            return reinterpret_cast< result_t >( pool + sizeof( pool_entry_t ) );
        }

        bool owns_allocation_address( unsigned long long address ) {
            if ( !m_initialized || !address )
                return false;

            for ( auto e = m_list_head.m_flink; e != &m_list_head; e = e->m_flink ) {
                auto entry = reinterpret_cast< pool_entry_t* >( e );
                auto base = reinterpret_cast< unsigned long long >( entry );
                auto end = base + sizeof( pool_entry_t ) + entry->m_size;
                if ( address >= base && address < end )
                    return true;
            }

            return false;
        }

        void free( unsigned long tag ) {
            if ( !m_initialized )
                return;

            for ( auto e = m_list_head.m_flink; e != &m_list_head; e = e->m_flink ) {
                auto entry = reinterpret_cast< pool_entry_t* >( e );
                if ( entry->m_tag != tag ) continue;

                list_remove( e );
                ExFreePoolWithTag( entry, tag );
                return;
            }
        }

        void cleanup( ) {
            if ( !m_initialized )
                return;

            while ( !list_empty( &m_list_head ) ) {
                list_entry_t* e = nullptr;
                list_remove_head( &m_list_head, e );

                auto entry = reinterpret_cast< pool_entry_t* >( e );
                ExFreePoolWithTag( entry, entry->m_tag );
            }

            m_initialized = false;
        }
    }

    template <typename t = void*>
    t allocate_pool( std::size_t size, int type = 0 ) {
        return pool::allocate<t>( size, type );
    }

    template <typename t>
    void free_pool( t pool_base ) {
        if ( !pool_base )
            return;

        auto entry = reinterpret_cast< pool::pool_entry_t* >(
            reinterpret_cast< uintptr_t >( pool_base ) - sizeof( pool::pool_entry_t )
            );
        list_remove( &entry->m_list );
        ExFreePoolWithTag( entry, entry->m_tag );
    }
}
