#pragma once

#include "types.hxx"
#include "window.hxx"
#include "../fonts/fonts.hxx"
#include <d2d1_1.h>
#include <d3d11.h>
#include <dwrite.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

namespace render {
	class c_device {
	public:
		c_device( ) = default;
		~c_device( );

		c_device( const c_device& ) = delete;
		c_device& operator=( const c_device& ) = delete;

		bool initialize( c_window& window );
		void shutdown( );
		bool begin_frame( color_t clear );
		bool end_frame( );

		ID2D1DeviceContext* context( ) const { return m_d2d_context.Get( ); }
		IDWriteFactory* text_factory( ) const { return m_text_factory.Get( ); }
		IDWriteFontCollection* font_collection( ) const { return m_fonts.get( ); }
		int width( ) const { return m_width; }
		int height( ) const { return m_height; }
		void set_interactive_area( rect_t area ) { if ( m_window ) m_window->set_interactive_area( area ); }
		void minimize_window( ) { if ( m_window ) m_window->minimize( ); }

	private:
		bool create_target( );
		bool resize( int width, int height );

		c_window* m_window = nullptr;
		int m_width = 0;
		int m_height = 0;
		Microsoft::WRL::ComPtr< ID3D11Device > m_device;
		Microsoft::WRL::ComPtr< ID3D11DeviceContext > m_device_context;
		Microsoft::WRL::ComPtr< IDXGISwapChain > m_swap_chain;
		Microsoft::WRL::ComPtr< ID2D1Factory1 > m_d2d_factory;
		Microsoft::WRL::ComPtr< ID2D1Device > m_d2d_device;
		Microsoft::WRL::ComPtr< ID2D1DeviceContext > m_d2d_context;
		Microsoft::WRL::ComPtr< ID2D1Bitmap1 > m_target;
		Microsoft::WRL::ComPtr< IDWriteFactory > m_text_factory;
		Microsoft::WRL::ComPtr< IDWriteRenderingParams > m_text_rendering_params;
		fonts::c_font_collection m_fonts;
	};
}
