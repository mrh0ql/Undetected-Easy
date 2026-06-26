#include "renderer.hxx"
#include <d2d1helper.h>
#include <d2d1_1helper.h>
#include <cmath>
#include <string>
#include <wincodec.h>

#pragma comment( lib, "windowscodecs.lib" )

namespace render {
	c_renderer::~c_renderer( ) {
		shutdown( );
	}

	bool c_renderer::initialize( c_device& device ) {
		if ( m_device || !device.context( ) )
			return false;

		m_device = &device;
		if ( FAILED( device.context( )->CreateSolidColorBrush( D2D1::ColorF( 1.0f, 1.0f, 1.0f, 1.0f ), m_brush.GetAddressOf( ) ) ) ) {
			m_device = nullptr;
			return false;
		}

		return true;
	}

	void c_renderer::shutdown( ) {
		if ( m_clip_active && m_device )
			m_device->context( )->PopLayer( );
		m_clip_active = false;
		m_clip_geometry.Reset( );
		m_brush.Reset( );
		m_device = nullptr;
	}

	bool c_renderer::begin_frame( color_t clear ) {
		return m_device && m_device->begin_frame( clear );
	}

	bool c_renderer::end_frame( ) {
		return m_device && m_device->end_frame( );
	}

	ID2D1SolidColorBrush* c_renderer::brush( color_t color ) {
		if ( !m_brush )
			return nullptr;

		m_brush->SetColor( D2D1::ColorF( color.r, color.g, color.b, color.a ) );
		return m_brush.Get( );
	}

	D2D1_RECT_F c_renderer::native_rect( rect_t area ) const {
		return D2D1::RectF( area.x, area.y, area.x + area.width, area.y + area.height );
	}

	void c_renderer::line( point_t from, point_t to, color_t color, float thickness ) {
		if ( !m_device || thickness <= 0.0f )
			return;

		m_device->context( )->DrawLine( D2D1::Point2F( from.x, from.y ), D2D1::Point2F( to.x, to.y ), brush( color ), thickness );
	}

	void c_renderer::rectangle( rect_t area, color_t color, float thickness ) {
		if ( !m_device || thickness <= 0.0f )
			return;

		m_device->context( )->DrawRectangle( native_rect( area ), brush( color ), thickness );
	}

	void c_renderer::filled_rectangle( rect_t area, color_t color ) {
		if ( m_device )
			m_device->context( )->FillRectangle( native_rect( area ), brush( color ) );
	}

	void c_renderer::rounded_rectangle( rect_t area, float radius, color_t color, float thickness ) {
		if ( !m_device || thickness <= 0.0f )
			return;

		auto rounded = D2D1::RoundedRect( native_rect( area ), radius, radius );
		m_device->context( )->DrawRoundedRectangle( rounded, brush( color ), thickness );
	}

	void c_renderer::filled_rounded_rectangle( rect_t area, float radius, color_t color ) {
		if ( !m_device )
			return;

		auto rounded = D2D1::RoundedRect( native_rect( area ), radius, radius );
		m_device->context( )->FillRoundedRectangle( rounded, brush( color ) );
	}

	void c_renderer::circle( point_t center, float radius, color_t color, float thickness ) {
		if ( !m_device || radius <= 0.0f || thickness <= 0.0f )
			return;

		m_device->context( )->DrawEllipse( D2D1::Ellipse( D2D1::Point2F( center.x, center.y ), radius, radius ), brush( color ), thickness );
	}

	void c_renderer::arc( point_t center, float radius, float start_angle, float sweep_angle, color_t color, float thickness ) {
		if ( !m_device || radius <= 0.0f || thickness <= 0.0f || std::abs( sweep_angle ) <= 0.0001f )
			return;

		Microsoft::WRL::ComPtr< ID2D1Factory > factory;
		Microsoft::WRL::ComPtr< ID2D1PathGeometry > geometry;
		Microsoft::WRL::ComPtr< ID2D1GeometrySink > sink;
		Microsoft::WRL::ComPtr< ID2D1StrokeStyle > stroke_style;
		m_device->context( )->GetFactory( factory.GetAddressOf( ) );
		if ( !factory || FAILED( factory->CreatePathGeometry( geometry.GetAddressOf( ) ) ) ||
			FAILED( geometry->Open( sink.GetAddressOf( ) ) ) )
			return;

		const auto end_angle = start_angle + sweep_angle;
		const auto start = D2D1::Point2F(
			center.x + std::cos( start_angle ) * radius,
			center.y + std::sin( start_angle ) * radius
		);
		const auto end = D2D1::Point2F(
			center.x + std::cos( end_angle ) * radius,
			center.y + std::sin( end_angle ) * radius
		);
		sink->BeginFigure( start, D2D1_FIGURE_BEGIN_HOLLOW );
		sink->AddArc( D2D1::ArcSegment(
			end,
			D2D1::SizeF( radius, radius ),
			0.0f,
			sweep_angle >= 0.0f ? D2D1_SWEEP_DIRECTION_CLOCKWISE : D2D1_SWEEP_DIRECTION_COUNTER_CLOCKWISE,
			std::abs( sweep_angle ) > 3.14159265358979323846f ? D2D1_ARC_SIZE_LARGE : D2D1_ARC_SIZE_SMALL
		) );
		sink->EndFigure( D2D1_FIGURE_END_OPEN );
		if ( FAILED( sink->Close( ) ) )
			return;

		D2D1_STROKE_STYLE_PROPERTIES properties = D2D1::StrokeStyleProperties( );
		properties.startCap = D2D1_CAP_STYLE_ROUND;
		properties.endCap = D2D1_CAP_STYLE_ROUND;
		properties.dashCap = D2D1_CAP_STYLE_ROUND;
		if ( FAILED( factory->CreateStrokeStyle( properties, nullptr, 0, stroke_style.GetAddressOf( ) ) ) )
			return;

		m_device->context( )->DrawGeometry( geometry.Get( ), brush( color ), thickness, stroke_style.Get( ) );
	}

	void c_renderer::filled_circle( point_t center, float radius, color_t color ) {
		if ( !m_device || radius <= 0.0f )
			return;

		m_device->context( )->FillEllipse( D2D1::Ellipse( D2D1::Point2F( center.x, center.y ), radius, radius ), brush( color ) );
	}

	image_t c_renderer::load_image( std::wstring_view path ) {
		image_t image;
		if ( !m_device || path.empty( ) )
			return image;

		std::wstring resolved_path( path );
		if ( resolved_path.size( ) < 2 || resolved_path[ 1 ] != L':' ) {
			wchar_t module_path[ MAX_PATH ]{ };
			auto length = GetModuleFileNameW( nullptr, module_path, MAX_PATH );
			if ( !length || length == MAX_PATH )
				return image;

			resolved_path.assign( module_path, length );
			auto separator = resolved_path.find_last_of( L"\\/" );
			if ( separator == std::wstring::npos )
				return image;

			resolved_path.resize( separator + 1 );
			resolved_path.append( path );
		}

		Microsoft::WRL::ComPtr< IWICImagingFactory > factory;
		Microsoft::WRL::ComPtr< IWICBitmapDecoder > decoder;
		Microsoft::WRL::ComPtr< IWICBitmapFrameDecode > frame;
		Microsoft::WRL::ComPtr< IWICFormatConverter > converter;

		if ( FAILED( CoCreateInstance( CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS( factory.GetAddressOf( ) ) ) ) ||
			FAILED( factory->CreateDecoderFromFilename( resolved_path.c_str( ), nullptr, GENERIC_READ, WICDecodeMetadataCacheOnLoad, decoder.GetAddressOf( ) ) ) ||
			FAILED( decoder->GetFrame( 0, frame.GetAddressOf( ) ) ) ||
			FAILED( factory->CreateFormatConverter( converter.GetAddressOf( ) ) ) ||
			FAILED( converter->Initialize( frame.Get( ), GUID_WICPixelFormat32bppPBGRA, WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom ) ) ||
			FAILED( m_device->context( )->CreateBitmapFromWicBitmap( converter.Get( ), nullptr, image.GetAddressOf( ) ) ) )
			image.Reset( );

		return image;
	}

	void c_renderer::draw_image( const image_t& image, rect_t area, float opacity ) {
		if ( !m_device || !image || area.width <= 0.0f || area.height <= 0.0f || opacity <= 0.0f )
			return;

		if ( opacity > 1.0f )
			opacity = 1.0f;

		auto destination = native_rect( area );
		m_device->context( )->DrawBitmap(
			image.Get( ),
			&destination,
			opacity,
			D2D1_INTERPOLATION_MODE_HIGH_QUALITY_CUBIC,
			nullptr,
			nullptr
		);
	}

	void c_renderer::push_opacity( float opacity ) {
		if ( !m_device )
			return;

		opacity = ( std::max )( 0.0f, ( std::min )( 1.0f, opacity ) );
		D2D1_LAYER_PARAMETERS1 parameters{ };
		parameters.contentBounds = D2D1::InfiniteRect( );
		parameters.maskAntialiasMode = D2D1_ANTIALIAS_MODE_PER_PRIMITIVE;
		parameters.maskTransform = D2D1::Matrix3x2F::Identity( );
		parameters.opacity = opacity;
		parameters.layerOptions = D2D1_LAYER_OPTIONS1_NONE;
		m_device->context( )->PushLayer( parameters, nullptr );
		++m_opacity_layer_count;
	}

	void c_renderer::pop_opacity( ) {
		if ( !m_device || !m_opacity_layer_count )
			return;
		m_device->context( )->PopLayer( );
		--m_opacity_layer_count;
	}

	bool c_renderer::push_rounded_clip( rect_t area, float radius ) {
		if ( !m_device || m_clip_active || area.width <= 0.0f || area.height <= 0.0f || radius < 0.0f )
			return false;

		Microsoft::WRL::ComPtr< ID2D1Factory > factory;
		m_device->context( )->GetFactory( factory.GetAddressOf( ) );
		if ( !factory || FAILED( factory->CreateRoundedRectangleGeometry(
			D2D1::RoundedRect( native_rect( area ), radius, radius ),
			m_clip_geometry.GetAddressOf( )
		) ) )
			return false;

		D2D1_LAYER_PARAMETERS1 parameters{ };
		parameters.contentBounds = D2D1::InfiniteRect( );
		parameters.geometricMask = m_clip_geometry.Get( );
		parameters.maskAntialiasMode = D2D1_ANTIALIAS_MODE_PER_PRIMITIVE;
		parameters.maskTransform = D2D1::Matrix3x2F::Identity( );
		parameters.opacity = 1.0f;
		parameters.layerOptions = D2D1_LAYER_OPTIONS1_NONE;
		m_device->context( )->PushLayer( parameters, nullptr );
		m_clip_active = true;
		return true;
	}

	void c_renderer::pop_clip( ) {
		if ( !m_device || !m_clip_active )
			return;

		m_device->context( )->PopLayer( );
		m_clip_active = false;
		m_clip_geometry.Reset( );
	}

	void c_renderer::interactive_area( rect_t area ) {
		if ( m_device )
			m_device->set_interactive_area( area );
	}

	void c_renderer::minimize_window( ) {
		if ( m_device )
			m_device->minimize_window( );
	}

	void c_renderer::text( std::wstring_view value, rect_t area, float font_size, color_t color, text_align_t alignment, std::wstring_view font_family, DWRITE_FONT_WEIGHT font_weight, bool wrap ) {
		if ( !m_device || value.empty( ) || font_size <= 0.0f )
			return;

		std::wstring owned_family( font_family );
		auto collection = font_family == L"Segoe UI" ? nullptr : m_device->font_collection( );
		Microsoft::WRL::ComPtr< IDWriteTextFormat > format;
		if ( FAILED( m_device->text_factory( )->CreateTextFormat(
			owned_family.c_str( ),
			collection,
			font_weight,
			DWRITE_FONT_STYLE_NORMAL,
			DWRITE_FONT_STRETCH_NORMAL,
			font_size,
			L"en-us",
			format.GetAddressOf( )
		) ) )
			return;

		switch ( alignment ) {
		case text_align_t::center:
			format->SetTextAlignment( DWRITE_TEXT_ALIGNMENT_CENTER );
			break;
		case text_align_t::right:
			format->SetTextAlignment( DWRITE_TEXT_ALIGNMENT_TRAILING );
			break;
		default:
			format->SetTextAlignment( DWRITE_TEXT_ALIGNMENT_LEADING );
			break;
		}
		format->SetWordWrapping( wrap ? DWRITE_WORD_WRAPPING_WRAP : DWRITE_WORD_WRAPPING_NO_WRAP );
		format->SetParagraphAlignment(
			wrap ? DWRITE_PARAGRAPH_ALIGNMENT_NEAR : DWRITE_PARAGRAPH_ALIGNMENT_CENTER
		);
		m_device->context( )->DrawTextW(
			value.data( ),
			static_cast< UINT32 >( value.size( ) ),
			format.Get( ),
			native_rect( area ),
			brush( color ),
			D2D1_DRAW_TEXT_OPTIONS_CLIP
		);
	}

	size_t c_renderer::measure_text( std::wstring_view value, float font_size, std::wstring_view font_family, DWRITE_FONT_WEIGHT font_weight, float maximum_width ) {
		if ( !m_device || value.empty( ) || font_size <= 0.0f )
			return { };

		Microsoft::WRL::ComPtr< IDWriteTextFormat > format;
		Microsoft::WRL::ComPtr< IDWriteTextLayout > layout;
		std::wstring owned_family( font_family );
		auto collection = font_family == L"Segoe UI" ? nullptr : m_device->font_collection( );
		if ( FAILED( m_device->text_factory( )->CreateTextFormat(
			owned_family.c_str( ),
			collection,
			font_weight,
			DWRITE_FONT_STYLE_NORMAL,
			DWRITE_FONT_STRETCH_NORMAL,
			font_size,
			L"en-us",
			format.GetAddressOf( )
		) ) )
			return { };
		format->SetWordWrapping( DWRITE_WORD_WRAPPING_WRAP );
		if ( FAILED( m_device->text_factory( )->CreateTextLayout(
			value.data( ),
			static_cast< UINT32 >( value.size( ) ),
			format.Get( ),
			maximum_width,
			16384.0f,
			layout.GetAddressOf( )
		) ) )
			return { };

		DWRITE_TEXT_METRICS metrics{ };
		if ( FAILED( layout->GetMetrics( &metrics ) ) )
			return { };

		return { metrics.widthIncludingTrailingWhitespace, metrics.height };
	}
}
