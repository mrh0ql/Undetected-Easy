#pragma once

#include "device.hxx"
#include <string_view>

namespace render {
	using image_t = Microsoft::WRL::ComPtr< ID2D1Bitmap1 >;

	class c_renderer {
	public:
		c_renderer( ) = default;
		~c_renderer( );

		c_renderer( const c_renderer& ) = delete;
		c_renderer& operator=( const c_renderer& ) = delete;

		bool initialize( c_device& device );
		void shutdown( );
		bool begin_frame( color_t clear );
		bool end_frame( );

		void line( point_t from, point_t to, color_t color, float thickness = 1.0f );
		void rectangle( rect_t area, color_t color, float thickness = 1.0f );
		void filled_rectangle( rect_t area, color_t color );
		void rounded_rectangle( rect_t area, float radius, color_t color, float thickness = 1.0f );
		void filled_rounded_rectangle( rect_t area, float radius, color_t color );
		void circle( point_t center, float radius, color_t color, float thickness = 1.0f );
		void arc( point_t center, float radius, float start_angle, float sweep_angle, color_t color, float thickness = 1.0f );
		void filled_circle( point_t center, float radius, color_t color );
		image_t load_image( std::wstring_view path );
		void draw_image( const image_t& image, rect_t area, float opacity = 1.0f );
		void push_opacity( float opacity );
		void pop_opacity( );
		bool push_rounded_clip( rect_t area, float radius );
		void pop_clip( );
		void interactive_area( rect_t area );
		void minimize_window( );
		void text( std::wstring_view value, rect_t area, float font_size, color_t color, text_align_t alignment = text_align_t::left, std::wstring_view font_family = L"Segoe UI", DWRITE_FONT_WEIGHT font_weight = DWRITE_FONT_WEIGHT_BOLD, bool wrap = false );
		size_t measure_text( std::wstring_view value, float font_size, std::wstring_view font_family = L"Segoe UI", DWRITE_FONT_WEIGHT font_weight = DWRITE_FONT_WEIGHT_BOLD, float maximum_width = 16384.0f );

	private:
		ID2D1SolidColorBrush* brush( color_t color );
		D2D1_RECT_F native_rect( rect_t area ) const;

		c_device* m_device = nullptr;
		Microsoft::WRL::ComPtr< ID2D1SolidColorBrush > m_brush;
		Microsoft::WRL::ComPtr< ID2D1RoundedRectangleGeometry > m_clip_geometry;
		bool m_clip_active = false;
		std::size_t m_opacity_layer_count = 0;
	};
}
