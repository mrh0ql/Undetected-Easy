#pragma once

namespace paging {
    namespace remap {
        bool initialize( );
        bool read_physical( std::uint64_t physical_address, void* buffer, std::size_t size );
    }

	std::uint64_t m_directory_table_base;

	struct pt_entries_t {
		pml4e m_pml4e;
		pdpte m_pdpte;
		pde m_pde;
		pte m_pte;
	};

	std::uint64_t generate_va( std::uint64_t pml4e_index, std::uint64_t pdpte_index,
		std::uint64_t pde_index, std::uint64_t pte_index, std::uint64_t offset ) {
		return ( pml4e_index << 39 ) |
			( pdpte_index << 30 ) |
			( pde_index << 21 ) |
			( pte_index << 12 ) |
			offset;
	}

    bool hyperspace_entries( pt_entries_t& entries, std::uint64_t addr ) {
        virt_addr_t va{ addr };
        if ( !remap::read_physical( m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
            &entries.m_pml4e, sizeof( pml4e ) ) )
            return false;

        if ( !entries.m_pml4e.hard.present )
            return false;

        if ( !remap::read_physical( ( entries.m_pml4e.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) ),
            &entries.m_pdpte, sizeof( pdpte ) ) )
            return false;

        if ( !entries.m_pdpte.hard.present )
            return false;

        if ( entries.m_pdpte.hard.page_size ) {
            return true;
        }

        if ( !remap::read_physical( ( entries.m_pdpte.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) ),
            &entries.m_pde, sizeof( pde ) ) )
            return false;

        if ( !entries.m_pde.hard.present )
            return false;

        if ( entries.m_pde.hard.page_size ) {
            return true;
        }

        if ( !remap::read_physical( ( entries.m_pde.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
            &entries.m_pte, sizeof( pte ) ) )
            return false;

        if ( !entries.m_pte.hard.present )
            return false;

        return true;
    }

    bool translate_linear( std::uint64_t va, std::uint64_t* pa = nullptr, std::uint32_t* page_size = nullptr ) {
        pt_entries_t pt_entries;
        if ( !hyperspace_entries( pt_entries, va ) )
            return false;

        if ( !pt_entries.m_pml4e.hard.present )
            return false;

        if ( !pt_entries.m_pdpte.hard.present )
            return false;

        if ( pt_entries.m_pdpte.hard.page_size ) {
            if ( page_size ) *page_size = page_1gb_size;
            if ( pa ) {
                auto pfn_masked = pt_entries.m_pdpte.hard.pfn & 0x3FFFFF;
                *pa = ( pfn_masked << page_shift ) | ( va & page_1gb_mask );
            }
            return true;
        }

        if ( !pt_entries.m_pde.hard.present )
            return false;

        if ( pt_entries.m_pde.hard.page_size ) {
            if ( page_size ) *page_size = page_2mb_size;
            if ( pa ) {
                auto pfn_masked = pt_entries.m_pde.hard.pfn & 0x7FFFFFFF;
                *pa = ( pfn_masked << page_shift ) | ( va & page_2mb_mask );
            }
            return true;
        }

        if ( !pt_entries.m_pte.hard.present )
            return false;

        if ( page_size ) *page_size = page_4kb_size;
        if ( pa ) {
            *pa = ( pt_entries.m_pte.hard.pfn << page_shift ) | ( va & page_4kb_mask );
        }
        return true;
    }
}
