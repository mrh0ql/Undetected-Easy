#include "window.hxx"
#include <dwmapi.h>
#include <string>
#include <windowsx.h>

#pragma comment( lib, "dwmapi.lib" )

namespace render {
	namespace {
		constexpr auto m_window_class = L"ude-render-window";
	}

	c_window::~c_window( ) {
		destroy( );
	}

	bool c_window::create( int width, int height, std::wstring_view title ) {
		if ( m_handle || width <= 0 || height <= 0 )
			return false;

		m_instance = GetModuleHandleW( nullptr );
		SetProcessDpiAwarenessContext( DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 );

		WNDCLASSEXW window_class{ };
		window_class.cbSize = sizeof( window_class );
		window_class.style = CS_HREDRAW | CS_VREDRAW;
		window_class.lpfnWndProc = window_proc;
		window_class.hInstance = m_instance;
		window_class.hCursor = LoadCursorW( nullptr, IDC_ARROW );
		window_class.lpszClassName = m_window_class;
		if ( !RegisterClassExW( &window_class ) && GetLastError( ) != ERROR_CLASS_ALREADY_EXISTS )
			return false;

		RECT area{ 0, 0, width, height };
		AdjustWindowRectEx( &area, WS_OVERLAPPEDWINDOW, FALSE, 0 );
		std::wstring owned_title( title );
		m_handle = CreateWindowExW(
			0,
			m_window_class,
			owned_title.c_str( ),
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT,
			CW_USEDEFAULT,
			area.right - area.left,
			area.bottom - area.top,
			nullptr,
			nullptr,
			m_instance,
			this
		);
		if ( !m_handle )
			return false;

		m_width = width;
		m_height = height;
		m_closed = false;
		ShowWindow( m_handle, SW_SHOW );
		UpdateWindow( m_handle );
		return true;
	}

	bool c_window::create_overlay( std::wstring_view title ) {
		if ( m_handle )
			return false;

		m_instance = GetModuleHandleW( nullptr );
		SetProcessDpiAwarenessContext( DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 );

		WNDCLASSEXW window_class{ };
		window_class.cbSize = sizeof( window_class );
		window_class.style = CS_HREDRAW | CS_VREDRAW;
		window_class.lpfnWndProc = window_proc;
		window_class.hInstance = m_instance;
		window_class.hCursor = LoadCursorW( nullptr, IDC_ARROW );
		window_class.lpszClassName = m_window_class;
		if ( !RegisterClassExW( &window_class ) && GetLastError( ) != ERROR_CLASS_ALREADY_EXISTS )
			return false;

		auto left = GetSystemMetrics( SM_XVIRTUALSCREEN );
		auto top = GetSystemMetrics( SM_YVIRTUALSCREEN );
		m_width = GetSystemMetrics( SM_CXVIRTUALSCREEN );
		m_height = GetSystemMetrics( SM_CYVIRTUALSCREEN );
		std::wstring owned_title( title );
		m_handle = CreateWindowExW(
			WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_APPWINDOW,
			m_window_class,
			owned_title.c_str( ),
			WS_POPUP,
			left,
			top,
			m_width,
			m_height,
			nullptr,
			nullptr,
			m_instance,
			this
		);
		if ( !m_handle )
			return false;

		m_overlay = true;
		m_closed = false;
		SetLayeredWindowAttributes( m_handle, RGB( 0, 0, 0 ), 0, LWA_COLORKEY );
		MARGINS margins{ -1 };
		DwmExtendFrameIntoClientArea( m_handle, &margins );
		ShowWindow( m_handle, SW_SHOWNOACTIVATE );
		UpdateWindow( m_handle );
		return true;
	}

	void c_window::destroy( ) {
		if ( m_handle ) {
			DestroyWindow( m_handle );
			m_handle = nullptr;
		}

		if ( m_instance ) {
			UnregisterClassW( m_window_class, m_instance );
			m_instance = nullptr;
		}
		m_overlay = false;
	}

	void c_window::set_click_through( bool enabled ) {
		if ( !m_handle || !m_overlay )
			return;

		auto styles = GetWindowLongPtrW( m_handle, GWL_EXSTYLE );
		if ( enabled )
			styles |= WS_EX_TRANSPARENT | WS_EX_NOACTIVATE;
		else
			styles &= ~( WS_EX_TRANSPARENT | WS_EX_NOACTIVATE );
		SetWindowLongPtrW( m_handle, GWL_EXSTYLE, styles );
		SetWindowPos( m_handle, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_FRAMECHANGED );
	}

	void c_window::set_interactive_area( rect_t area ) {
		m_interactive_area = area;
	}

	void c_window::minimize( ) {
		if ( m_handle )
			ShowWindow( m_handle, SW_MINIMIZE );
	}

	bool c_window::poll( ) {
		MSG message{ };
		while ( PeekMessageW( &message, nullptr, 0, 0, PM_REMOVE ) ) {
			if ( message.message == WM_QUIT )
				m_closed = true;

			TranslateMessage( &message );
			DispatchMessageW( &message );
		}

		return !m_closed;
	}

	bool c_window::consume_resize( ) {
		auto pending = m_resize_pending;
		m_resize_pending = false;
		return pending;
	}

	LRESULT CALLBACK c_window::window_proc( HWND window, UINT message, WPARAM wparam, LPARAM lparam ) {
		auto self = reinterpret_cast< c_window* >( GetWindowLongPtrW( window, GWLP_USERDATA ) );
		if ( message == WM_NCCREATE ) {
			auto create = reinterpret_cast< CREATESTRUCTW* >( lparam );
			self = static_cast< c_window* >( create->lpCreateParams );
			SetWindowLongPtrW( window, GWLP_USERDATA, reinterpret_cast< LONG_PTR >( self ) );
		}

		if ( self ) {
			switch ( message ) {
			case WM_NCHITTEST: {
				if ( !self->m_overlay )
					break;

				POINT cursor{ GET_X_LPARAM( lparam ), GET_Y_LPARAM( lparam ) };
				ScreenToClient( window, &cursor );
				auto& area = self->m_interactive_area;
				if ( cursor.x >= area.x && cursor.x < area.x + area.width &&
					cursor.y >= area.y && cursor.y < area.y + area.height )
					return HTCLIENT;

				return HTTRANSPARENT;
			}
			case WM_MOUSEACTIVATE:
				return MA_NOACTIVATE;
			case WM_SIZE:
				if ( wparam != SIZE_MINIMIZED ) {
					self->m_width = LOWORD( lparam );
					self->m_height = HIWORD( lparam );
					self->m_resize_pending = true;
				}
				return 0;
			case WM_CLOSE:
				DestroyWindow( window );
				return 0;
			case WM_DESTROY:
				self->m_handle = nullptr;
				self->m_closed = true;
				PostQuitMessage( 0 );
				return 0;
			default:
				break;
			}
		}

		return DefWindowProcW( window, message, wparam, lparam );
	}
}
