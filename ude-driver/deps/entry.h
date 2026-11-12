#pragma once

struct entry_t {
    struct symbols_t {
        std::uint64_t m_mm_allocate_independent_pages;
        std::uint64_t m_mm_free_independent_pages;
        std::uint64_t m_mm_set_page_protection;
        std::uint64_t m_mi_lock_page_table_page;
        std::uint64_t m_mi_is_page_on_bad_list;
        std::uint64_t m_mi_make_page_bad;
        std::uint64_t m_ps_loaded_module_list;
        std::uint64_t m_pi_ddb_cache_table;
        std::uint64_t m_pi_ddb_lock;
        std::uint64_t m_mm_unloaded_drivers;
        std::uint64_t m_mm_last_unloaded_driver;
        std::uint64_t m_hal_dispatch_table;
        std::uint64_t m_hal_private_dispatch_table;
        std::uint64_t m_ki_wait_never;
        std::uint64_t m_ki_wait_always;
        std::uint64_t m_kd_debugger_not_present;
        std::uint64_t m_kd_pitch_debugger;
    } m_pdb;

    struct offsets_t {
    } m_offsets;

    std::uint64_t m_image_base;
    std::uint64_t m_image_size;
    std::uint64_t m_ntoskrnl_base;
    std::uint64_t m_directory_table_base;
}; entry_t m_entry{ };
