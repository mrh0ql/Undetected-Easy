#pragma once

constexpr auto page_4kb_size = 0x1000ull;
constexpr auto page_2mb_size = 0x200000ull;
constexpr auto page_1gb_size = 0x40000000ull;

constexpr auto page_shift = 12ull;
constexpr auto page_2mb_shift = 21ull;
constexpr auto page_1gb_shift = 30ull;

constexpr auto page_4kb_mask = 0xFFFull;
constexpr auto page_2mb_mask = 0x1FFFFFull;
constexpr auto page_1gb_mask = 0x3FFFFFFFull;

constexpr auto m_system_module_information = 11ul;
constexpr auto m_system_big_pool_information = 0x42ul;

extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    unsigned long system_information_class,
    void* system_information,
    unsigned long system_information_length,
    unsigned long* return_length
);

extern "C" NTSYSAPI unsigned long NTAPI RtlWalkFrameChain(
    void** callout,
    unsigned long count,
    unsigned long flags
);

extern "C" NTSYSAPI std::uint32_t NTAPI RtlRandomEx(
    unsigned long*
);

extern "C" NTSYSAPI PPHYSICAL_MEMORY_RANGE NTAPI MmGetPhysicalMemoryRanges( );

extern "C" NTKERNELAPI NTSTATUS NTAPI PsLookupProcessByProcessId(
	HANDLE process_id,
	PEPROCESS* process
);

extern "C" NTKERNELAPI NTSTATUS NTAPI PsLookupThreadByThreadId(
	HANDLE thread_id,
	PETHREAD* thread
);

extern "C" NTKERNELAPI HANDLE NTAPI PsGetProcessId(
	PEPROCESS process
);

extern "C" NTKERNELAPI PEPROCESS NTAPI PsGetThreadProcess(
	PETHREAD thread
);

extern "C" NTKERNELAPI HANDLE NTAPI PsGetThreadId(
	PETHREAD thread
);

extern "C" NTKERNELAPI ULONG NTAPI PsGetProcessSessionId(
	PEPROCESS process
);

extern "C" NTKERNELAPI NTSTATUS NTAPI PsGetProcessExitStatus(
	PEPROCESS process
);

extern "C" NTKERNELAPI const char* NTAPI PsGetProcessImageFileName(
	PEPROCESS process
);

extern "C" POBJECT_TYPE* IoDriverObjectType;
extern "C" POBJECT_TYPE* IoDeviceObjectType;
extern "C" POBJECT_TYPE* PsProcessType;
extern "C" POBJECT_TYPE* PsThreadType;

extern "C" NTKERNELAPI BOOLEAN NTAPI PsIsSystemThread(
	PETHREAD thread
);

extern "C" NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	PUNICODE_STRING object_name,
	ULONG attributes,
	PACCESS_STATE access_state,
	ACCESS_MASK desired_access,
	POBJECT_TYPE object_type,
	KPROCESSOR_MODE access_mode,
	void* parse_context,
	void** object
);

extern "C" NTSYSAPI NTSTATUS NTAPI ZwOpenDirectoryObject(
	PHANDLE directory_handle,
	ACCESS_MASK desired_access,
	POBJECT_ATTRIBUTES object_attributes
);

extern "C" NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryObject(
	HANDLE directory_handle,
	void* buffer,
	ULONG length,
	BOOLEAN return_single_entry,
	BOOLEAN restart_scan,
	PULONG context,
	PULONG return_length
);

struct object_directory_information_t {
	UNICODE_STRING m_name;
	UNICODE_STRING m_type_name;
};

struct system_bigpool_entry_t {
	union {
		void* m_virtual_address;
		ULONG_PTR m_non_paged : 1;
	};
	ULONG_PTR m_size_in_bytes;
	union {
		UCHAR m_tag[ 4 ];
		ULONG m_tag_ulong;
	};
};

struct system_bigpool_information_t {
	ULONG m_count;
	system_bigpool_entry_t m_allocated_info[ 1 ];
};

#define make_physical_address( address ) \
	( PHYSICAL_ADDRESS{ .QuadPart = static_cast< LONGLONG >( address ) } )

typedef union _virt_addr_t {
    std::uintptr_t value;
    struct {
        std::uint64_t offset : 12;        // 0:11
        std::uint64_t pte_index : 9;      // 12:20
        std::uint64_t pde_index : 9;      // 21:29
        std::uint64_t pdpte_index : 9;    // 30:38
        std::uint64_t pml4e_index : 9;    // 39:47
        std::uint64_t reserved : 16;      // 48:63
    };
} virt_addr_t, * pvirt_addr_t;

typedef union _pfn_t {
    std::uintptr_t value;
    std::uintptr_t offset;
} pfn_t, * ppfn_t;

typedef union _pml4e {
    struct {
        std::uint64_t present : 1;                   // Must be 1 if valid
        std::uint64_t read_write : 1;               // Write access control
        std::uint64_t user_supervisor : 1;           // User/supervisor access control
        std::uint64_t page_write_through : 1;        // Write-through caching
        std::uint64_t cached_disable : 1;            // Cache disable
        std::uint64_t accessed : 1;                  // Set when accessed
        std::uint64_t ignored0 : 1;                  // Ignored
        std::uint64_t large_page : 1;               // Reserved (must be 0)
        std::uint64_t ignored1 : 4;                 // Ignored
        std::uint64_t pfn : 36;                     // Physical frame number
        std::uint64_t reserved : 4;                 // Reserved for software
        std::uint64_t ignored2 : 11;                // Ignored
        std::uint64_t no_execute : 1;               // No-execute bit
    } hard;
    std::uint64_t value;
} pml4e, * ppml4e;

typedef union _pdpte {
    struct {
        std::uint64_t present : 1;                   // Must be 1 if valid
        std::uint64_t read_write : 1;               // Write access control
        std::uint64_t user_supervisor : 1;           // User/supervisor access control
        std::uint64_t page_write_through : 1;        // Write-through caching
        std::uint64_t cached_disable : 1;            // Cache disable
        std::uint64_t accessed : 1;                  // Set when accessed
        std::uint64_t dirty : 1;                    // Set when written to (1GB pages)
        std::uint64_t page_size : 1;                // 1=1GB page, 0=points to page directory
        std::uint64_t ignored1 : 4;                 // Ignored
        std::uint64_t pfn : 36;                     // Physical frame number
        std::uint64_t reserved : 4;                 // Reserved for software
        std::uint64_t ignored2 : 11;                // Ignored
        std::uint64_t no_execute : 1;               // No-execute bit
    } hard;
    std::uint64_t value;
} pdpte, * ppdpte;

typedef union _pde {
    struct {
        std::uint64_t present : 1;                   // Must be 1 if valid
        std::uint64_t read_write : 1;               // Write access control
        std::uint64_t user_supervisor : 1;           // User/supervisor access control
        std::uint64_t page_write_through : 1;        // Write-through caching
        std::uint64_t cached_disable : 1;            // Cache disable
        std::uint64_t accessed : 1;                  // Set when accessed
        std::uint64_t dirty : 1;                    // Set when written to (2MB pages)
        std::uint64_t page_size : 1;                // 1=2MB page, 0=points to page table
        std::uint64_t global : 1;                   // Global page (if CR4.PGE=1)
        std::uint64_t ignored1 : 3;                 // Ignored
        std::uint64_t pfn : 36;                     // Physical frame number
        std::uint64_t reserved : 4;                 // Reserved for software
        std::uint64_t ignored2 : 11;                // Ignored
        std::uint64_t no_execute : 1;               // No-execute bit
    } hard;
    std::uint64_t value;
} pde, * ppde;

typedef union _pte {
    struct {
        std::uint64_t present : 1;                   // Must be 1 if valid
        std::uint64_t read_write : 1;               // Write access control
        std::uint64_t user_supervisor : 1;           // User/supervisor access control
        std::uint64_t page_write_through : 1;        // Write-through caching
        std::uint64_t cached_disable : 1;            // Cache disable
        std::uint64_t accessed : 1;                  // Set when accessed
        std::uint64_t dirty : 1;                    // Set when written to
        std::uint64_t pat : 1;                      // Page Attribute Table bit
        std::uint64_t global : 1;                   // Global page
        std::uint64_t ignored1 : 3;                 // Ignored
        std::uint64_t pfn : 36;                     // Physical frame number
        std::uint64_t reserved : 4;                 // Reserved for software
        std::uint64_t ignored2 : 7;                 // Ignored
        std::uint64_t protection_key : 4;           // Protection key
        std::uint64_t no_execute : 1;               // No-execute bit
    } hard;
    std::uint64_t value;
} pte, * ppte;


struct system_module_t {
    HANDLE m_section;
    void* m_mapped_base;
    void* m_image_base;
    unsigned long m_image_size;
    unsigned long m_flags;
    unsigned short m_load_order_index;
    unsigned short m_init_order_index;
    unsigned short m_load_count;
    unsigned short m_offset_to_file_name;
    unsigned char m_full_path_name[ 256 ];
};

struct system_modules_t {
    unsigned long m_count;
    system_module_t m_modules[ 1 ];
};


bool ascii_equal_insensitive( const char* left, const char* right ) {
    if ( !left || !right )
        return false;

    ANSI_STRING left_string{ };
    ANSI_STRING right_string{ };
    RtlInitAnsiString( &left_string, left );
    RtlInitAnsiString( &right_string, right );
    return RtlEqualString( &left_string, &right_string, TRUE ) != FALSE;
}

bool ascii_starts_with_insensitive( const char* text, const char* prefix ) {
    if ( !text || !prefix )
        return false;

    while ( *prefix ) {
        auto left = *text;
        auto right = *prefix;
        if ( !left )
            return false;

        if ( left >= 'A' && left <= 'Z' )
            left = left - 'A' + 'a';

        if ( right >= 'A' && right <= 'Z' )
            right = right - 'A' + 'a';

        if ( left != right )
            return false;

        text++;
        prefix++;
    }

    return true;
}
