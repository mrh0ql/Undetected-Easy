#pragma once

namespace utility {
    void enable_utf8( ) {
        auto std_handle = GetStdHandle( STD_OUTPUT_HANDLE );
        DWORD mode;
        GetConsoleMode( std_handle, &mode );
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode( std_handle, mode );
    }

    bool is_admin( ) {
        BOOL is_admin = FALSE;
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        PSID administrators_group;
        if ( AllocateAndInitializeSid( &nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators_group ) ) {
            if ( !CheckTokenMembership( NULL, administrators_group, &is_admin ) ) {
                is_admin = FALSE;
            }
            FreeSid( administrators_group );
        }
        return is_admin != FALSE;
    }

    template<typename... Args>
    inline void print( const char* prefix, const char* format, Args... args ) {
        auto now = std::chrono::system_clock::now( );
        std::time_t time = std::chrono::system_clock::to_time_t( now );
        tm local_tm;
        localtime_s( &local_tm, &time );
        printf( obf( "\x1b[38;2;128;128;128m[\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m/\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m/\x1b[38;2;128;128;128m%04d\x1b[38;2;128;128;128m \x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m:\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m:\x1b[38;2;128;128;128m%02d]\x1b[0m " ),
            local_tm.tm_mon + 1,
            local_tm.tm_mday,
            local_tm.tm_year + 1900,
            local_tm.tm_hour,
            local_tm.tm_min,
            local_tm.tm_sec );
        printf( obf( "\x1b[38;2;1;86;131m%s\x1b[0m " ), prefix );
        printf( obf( "\x1b[37m" ) );
        printf( format, args... );
        printf( obf( "\x1b[0m\n" ) );
    }

    template<typename... Args>
    inline void print_line( const char* prefix, const char* format, Args... args ) {
        auto now = std::chrono::system_clock::now( );
        std::time_t time = std::chrono::system_clock::to_time_t( now );
        tm local_tm;
        localtime_s( &local_tm, &time );
        printf( "\r" );
        printf( obf( "\x1b[38;2;128;128;128m[\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m/\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m/\x1b[38;2;128;128;128m%04d\x1b[38;2;128;128;128m \x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m:\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m:\x1b[38;2;128;128;128m%02d]\x1b[0m " ),
            local_tm.tm_mon + 1,
            local_tm.tm_mday,
            local_tm.tm_year + 1900,
            local_tm.tm_hour,
            local_tm.tm_min,
            local_tm.tm_sec );
        printf( obf( "\x1b[38;2;1;86;131m%s\x1b[0m " ), prefix );
        printf( obf( "\x1b[37m" ) );
        printf( format, args... );
        printf( obf( "\x1b[0m" ) );
    }

    template<typename... Args>
    inline void debug( bool selected, const char* prefix, const char* format, Args... args ) {
        auto now = std::chrono::system_clock::now( );
        std::time_t time = std::chrono::system_clock::to_time_t( now );
        tm local_tm;
        localtime_s( &local_tm, &time );
        printf( obf( "\r\x1b[2K" ) );
        printf( obf( "\x1b[38;2;128;128;128m[\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m/\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m/\x1b[38;2;128;128;128m%04d\x1b[38;2;128;128;128m \x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m:\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m:\x1b[38;2;128;128;128m%02d]\x1b[0m " ),
            local_tm.tm_mon + 1,
            local_tm.tm_mday,
            local_tm.tm_year + 1900,
            local_tm.tm_hour,
            local_tm.tm_min,
            local_tm.tm_sec );
        printf( obf( "\x1b[38;2;1;86;131m%s\x1b[0m " ), selected ? obf( ">" ) : obf( " " ) );
        printf( obf( "\x1b[38;2;1;86;131m%s\x1b[0m " ), prefix );
        printf( obf( "\x1b[37m" ) );
        printf( format, args... );
        printf( obf( "\x1b[0m\n" ) );
    }

    template<typename... Args>
    inline void debug_status( const char* prefix, const char* format, Args... args ) {
        auto now = std::chrono::system_clock::now( );
        std::time_t time = std::chrono::system_clock::to_time_t( now );
        tm local_tm;
        localtime_s( &local_tm, &time );
        printf( obf( "\r\x1b[2K" ) );
        printf( obf( "\x1b[38;2;128;128;128m[\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m/\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m/\x1b[38;2;128;128;128m%04d\x1b[38;2;128;128;128m \x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m:\x1b[38;2;128;128;128m%02d\x1b[38;2;128;128;128m:\x1b[38;2;128;128;128m%02d]\x1b[0m " ),
            local_tm.tm_mon + 1,
            local_tm.tm_mday,
            local_tm.tm_year + 1900,
            local_tm.tm_hour,
            local_tm.tm_min,
            local_tm.tm_sec );
        printf( obf( "\x1b[38;2;1;86;131m%s\x1b[0m " ), prefix );
        printf( obf( "\x1b[37m" ) );
        printf( format, args... );
        printf( obf( "\x1b[0m\n" ) );
    }
}
