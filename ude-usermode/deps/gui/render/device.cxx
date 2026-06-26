#include "device.hxx"
#include <d2d1helper.h>

#pragma comment( lib, "d2d1.lib" )
#pragma comment( lib, "d3d11.lib" )
#pragma comment( lib, "dwrite.lib" )
#pragma comment( lib, "dxgi.lib" )

namespace render {
	c_device::~c_device( ) {
		shutdown( );
	}

	bool c_device::initialize( c_window& window ) {
		if ( m_device || !window.handle( ) )
			return false;

		m_window = &window;
		m_width = window.width( );
		m_height = window.height( );

		DXGI_SWAP_CHAIN_DESC swap_desc{ };
		swap_desc.BufferCount = 2;
		swap_desc.BufferDesc.Width = m_width;
		swap_desc.BufferDesc.Height = m_height;
		swap_desc.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
		swap_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
		swap_desc.OutputWindow = window.handle( );
		swap_desc.SampleDesc.Count = 1;
		swap_desc.Windowed = TRUE;
		swap_desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

		constexpr D3D_FEATURE_LEVEL feature_levels[] = {
			D3D_FEATURE_LEVEL_11_1,
			D3D_FEATURE_LEVEL_11_0
		};
		auto flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
#if defined( _DEBUG )
		flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

		auto result = D3D11CreateDeviceAndSwapChain(
			nullptr,
			D3D_DRIVER_TYPE_HARDWARE,
			nullptr,
			flags,
			feature_levels,
			ARRAYSIZE( feature_levels ),
			D3D11_SDK_VERSION,
			&swap_desc,
			m_swap_chain.GetAddressOf( ),
			m_device.GetAddressOf( ),
			nullptr,
			m_device_context.GetAddressOf( )
		);
		if ( FAILED( result ) ) {
			result = D3D11CreateDeviceAndSwapChain(
				nullptr,
				D3D_DRIVER_TYPE_WARP,
				nullptr,
				flags & ~D3D11_CREATE_DEVICE_DEBUG,
				feature_levels,
				ARRAYSIZE( feature_levels ),
				D3D11_SDK_VERSION,
				&swap_desc,
				m_swap_chain.GetAddressOf( ),
				m_device.GetAddressOf( ),
				nullptr,
				m_device_context.GetAddressOf( )
			);
		}
		if ( FAILED( result ) ) {
			shutdown( );
			return false;
		}

		D2D1_FACTORY_OPTIONS factory_options{ };
#if defined( _DEBUG )
		factory_options.debugLevel = D2D1_DEBUG_LEVEL_INFORMATION;
#endif
		result = D2D1CreateFactory( D2D1_FACTORY_TYPE_SINGLE_THREADED, factory_options, m_d2d_factory.GetAddressOf( ) );
		if ( FAILED( result ) ) {
			shutdown( );
			return false;
		}

		Microsoft::WRL::ComPtr< IDXGIDevice > dxgi_device;
		result = m_device.As( &dxgi_device );
		if ( FAILED( result ) || FAILED( m_d2d_factory->CreateDevice( dxgi_device.Get( ), m_d2d_device.GetAddressOf( ) ) ) ||
			FAILED( m_d2d_device->CreateDeviceContext( D2D1_DEVICE_CONTEXT_OPTIONS_NONE, m_d2d_context.GetAddressOf( ) ) ) ) {
			shutdown( );
			return false;
		}

		result = DWriteCreateFactory(
			DWRITE_FACTORY_TYPE_SHARED,
			__uuidof( IDWriteFactory ),
			reinterpret_cast< IUnknown** >( m_text_factory.GetAddressOf( ) )
		);
		if ( SUCCEEDED( result ) ) {
			result = m_text_factory->CreateCustomRenderingParams(
				2.2f,
				1.25f,
				0.0f,
				DWRITE_PIXEL_GEOMETRY_FLAT,
				DWRITE_RENDERING_MODE_NATURAL_SYMMETRIC,
				m_text_rendering_params.GetAddressOf( )
			);
		}
		if ( FAILED( result ) || !m_fonts.initialize( m_text_factory.Get( ) ) || !create_target( ) ) {
			shutdown( );
			return false;
		}

		return true;
	}

	void c_device::shutdown( ) {
		if ( m_d2d_context )
			m_d2d_context->SetTarget( nullptr );

		m_target.Reset( );
		m_fonts.shutdown( );
		m_text_rendering_params.Reset( );
		m_text_factory.Reset( );
		m_d2d_context.Reset( );
		m_d2d_device.Reset( );
		m_d2d_factory.Reset( );
		m_swap_chain.Reset( );
		m_device_context.Reset( );
		m_device.Reset( );
		m_window = nullptr;
		m_width = 0;
		m_height = 0;
	}

	bool c_device::create_target( ) {
		Microsoft::WRL::ComPtr< IDXGISurface > surface;
		if ( FAILED( m_swap_chain->GetBuffer( 0, IID_PPV_ARGS( surface.GetAddressOf( ) ) ) ) )
			return false;

		auto properties = D2D1::BitmapProperties1(
			D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW,
			D2D1::PixelFormat( DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE )
		);
		if ( FAILED( m_d2d_context->CreateBitmapFromDxgiSurface( surface.Get( ), &properties, m_target.GetAddressOf( ) ) ) )
			return false;

		m_d2d_context->SetTarget( m_target.Get( ) );
		m_d2d_context->SetUnitMode( D2D1_UNIT_MODE_PIXELS );
		m_d2d_context->SetAntialiasMode( D2D1_ANTIALIAS_MODE_PER_PRIMITIVE );
		// Layered overlays do not have a stable RGB subpixel background, so
		// grayscale coverage produces cleaner glyph edges than ClearType.
		m_d2d_context->SetTextAntialiasMode( D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE );
		m_d2d_context->SetTextRenderingParams( m_text_rendering_params.Get( ) );
		return true;
	}

	bool c_device::resize( int width, int height ) {
		if ( width <= 0 || height <= 0 )
			return true;

		m_d2d_context->SetTarget( nullptr );
		m_target.Reset( );
		if ( FAILED( m_swap_chain->ResizeBuffers( 0, width, height, DXGI_FORMAT_UNKNOWN, 0 ) ) )
			return false;

		m_width = width;
		m_height = height;
		return create_target( );
	}

	bool c_device::begin_frame( color_t clear ) {
		if ( !m_window || !m_d2d_context )
			return false;

		if ( m_window->consume_resize( ) && !resize( m_window->width( ), m_window->height( ) ) )
			return false;

		m_d2d_context->BeginDraw( );
		m_d2d_context->SetTransform( D2D1::Matrix3x2F::Identity( ) );
		m_d2d_context->Clear( D2D1::ColorF( clear.r, clear.g, clear.b, clear.a ) );
		return true;
	}

	bool c_device::end_frame( ) {
		if ( !m_d2d_context || !m_swap_chain )
			return false;

		auto result = m_d2d_context->EndDraw( );
		if ( result == D2DERR_RECREATE_TARGET ) {
			m_d2d_context->SetTarget( nullptr );
			m_target.Reset( );
			return create_target( );
		}

		return SUCCEEDED( result ) && SUCCEEDED( m_swap_chain->Present( 1, 0 ) );
	}
}
