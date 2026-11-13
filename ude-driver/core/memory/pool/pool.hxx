#pragma once

namespace memory {
    namespace pool {
        list_entry_t m_list_head;
        KSPIN_LOCK m_lock;
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
            LARGE_INTEGER tick{ };
            KeQueryTickCount( &tick );
            unsigned long seed = tick.LowPart ^ tick.HighPart;

            auto r1 = RtlRandomEx( &seed );
            auto r2 = RtlRandomEx( &seed );
            return ( r1 & 0xFFFF0000 ) | ( r2 & 0x0000FFFF );
        }

        void setup( ) {
            if ( m_initialized )
                return;

            KeInitializeSpinLock( &m_lock );
            list_init( &m_list_head );
            m_initialized = true;
        }

        template <typename result_t>
        result_t allocate( size_t size, int type ) {
            UNREFERENCED_PARAMETER( type );
            setup( );

            constexpr POOL_TYPE nx_non_paged = static_cast< POOL_TYPE >( 512 );
            auto raw_pool = ExAllocatePoolWithTag( nx_non_paged, size + sizeof( pool_entry_t ), m_pool_tag );
            if ( !raw_pool )
                raw_pool = ExAllocatePoolWithTag( NonPagedPool, size + sizeof( pool_entry_t ), m_pool_tag );
            if ( !raw_pool )
                return nullptr;

            auto pool = reinterpret_cast< uintptr_t >( raw_pool );

            auto entry = reinterpret_cast< pool_entry_t* >( pool );
            entry->m_tag = m_pool_tag;
            entry->m_size = size;

            KIRQL old_irql = PASSIVE_LEVEL;
            KeAcquireSpinLock( &m_lock, &old_irql );
            list_insert_tail( &m_list_head, &entry->m_list );
            KeReleaseSpinLock( &m_lock, old_irql );

            return reinterpret_cast< result_t >( pool + sizeof( pool_entry_t ) );
        }

        bool owns_allocation_address( unsigned long long address ) {
            if ( !m_initialized || !address )
                return false;

            auto found = false;
            KIRQL old_irql = PASSIVE_LEVEL;
            KeAcquireSpinLock( &m_lock, &old_irql );

            for ( auto e = m_list_head.m_flink; e != &m_list_head; e = e->m_flink ) {
                auto entry = reinterpret_cast< pool_entry_t* >( e );
                auto base = reinterpret_cast< unsigned long long >( entry );
                auto end = base + sizeof( pool_entry_t ) + entry->m_size;
                if ( address >= base && address < end ) {
                    found = true;
                    break;
                }
            }

            KeReleaseSpinLock( &m_lock, old_irql );
            return found;
        }

        void free( unsigned long tag ) {
            if ( !m_initialized )
                return;

            pool_entry_t* found_entry = nullptr;
            KIRQL old_irql = PASSIVE_LEVEL;
            KeAcquireSpinLock( &m_lock, &old_irql );

            for ( auto e = m_list_head.m_flink; e != &m_list_head; e = e->m_flink ) {
                auto entry = reinterpret_cast< pool_entry_t* >( e );
                if ( entry->m_tag != tag ) continue;

                list_remove( e );
                found_entry = entry;
                break;
            }

            KeReleaseSpinLock( &m_lock, old_irql );
            if ( found_entry )
                ExFreePoolWithTag( found_entry, tag );
        }

        void cleanup( ) {
            if ( !m_initialized )
                return;

            for ( ;; ) {
                pool_entry_t* entry = nullptr;
                KIRQL old_irql = PASSIVE_LEVEL;
                KeAcquireSpinLock( &m_lock, &old_irql );

                if ( !list_empty( &m_list_head ) ) {
                    auto tail = m_list_head.m_blink;
                    list_remove( tail );
                    entry = reinterpret_cast< pool_entry_t* >( tail );
                }

                KeReleaseSpinLock( &m_lock, old_irql );
                if ( !entry )
                    break;

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

        if ( pool::m_initialized ) {
            KIRQL old_irql = PASSIVE_LEVEL;
            KeAcquireSpinLock( &pool::m_lock, &old_irql );
            list_remove( &entry->m_list );
            KeReleaseSpinLock( &pool::m_lock, old_irql );
        }

        ExFreePoolWithTag( entry, entry->m_tag );
    }
}
