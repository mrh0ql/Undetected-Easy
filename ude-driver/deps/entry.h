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
        std::uint64_t m_psp_create_process_notify_routine;
        std::uint64_t m_psp_create_thread_notify_routine;
        std::uint64_t m_psp_load_image_notify_routine;
        std::uint64_t m_cm_callback_list_head;
        std::uint64_t m_ke_service_descriptor_table;
        std::uint64_t m_ke_service_descriptor_table_shadow;
        std::uint64_t m_mm_pfn_database;
        std::uint64_t m_etw_threat_int_prov_reg_handle;
        std::uint64_t m_hal_send_nmi;
        std::uint64_t m_ci_kernel_hash_bucket_list;
        std::uint64_t m_ci_hash_cache_lock;
        std::uint64_t m_flt_globals;
        std::uint64_t m_ndis_global_filter_list;
    } m_pdb;

    struct offsets_t {
        std::uint64_t m_kprcb_timer_table;
        std::uint64_t m_kprcb_dpc_data;
        std::uint64_t m_kthread_previous_mode;
        std::uint64_t m_kthread_misc_flags;
        std::uint64_t m_kthread_apc_state;
        std::uint64_t m_kthread_start_address;
        std::uint64_t m_kthread_win32_start_address;
        std::uint64_t m_object_type_callback_list;
        std::uint64_t m_mmpfn_size;
        std::uint64_t m_mmpfn_pte_address;
        std::uint64_t m_mmpfn_u4;
    } m_offsets;

    std::uint64_t m_image_base;
    std::uint64_t m_image_size;
    std::uint64_t m_ntoskrnl_base;
    std::uint64_t m_directory_table_base;
};
static_assert( sizeof( entry_t ) == 360, "entry_t layout must match service::driver_config_t" );
entry_t m_entry{ };
