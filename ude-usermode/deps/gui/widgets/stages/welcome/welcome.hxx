#pragma once

namespace render::widgets::stages {
	class c_welcome_stage {
	public:
		c_welcome_stage( ) {
			wchar_t module_path[ MAX_PATH ]{ };
			const auto length = GetModuleFileNameW( nullptr, module_path, MAX_PATH );
			m_log_path.assign( module_path, length );
			const auto separator = m_log_path.find_last_of( L"\\/" );
			if ( separator != std::wstring::npos )
				m_log_path.resize( separator + 1 );
			m_log_path += L"ude-log.txt";

			FILE* file = nullptr;
			if ( _wfopen_s( &file, m_log_path.c_str( ), L"rt, ccs=UTF-8" ) != 0 || !file )
				return;

			wchar_t buffer[ 64 ]{ };
			if ( fgetws( buffer, static_cast< int >( std::size( buffer ) ), file ) ) {
				m_display_name.assign( buffer );
				while ( !m_display_name.empty( ) &&
					( m_display_name.back( ) == L'\r' || m_display_name.back( ) == L'\n' ) )
					m_display_name.pop_back( );
			}
			fclose( file );
			m_display_name_saved = !m_display_name.empty( );
		}

		static rect_t continue_button( rect_t panel ) {
			constexpr auto width = 112.0f;
			constexpr auto height = 28.0f;
			constexpr auto feature_card_left = 28.0f;
			constexpr auto feature_card_width = 865.0f;
			return {
				panel.x + feature_card_left + feature_card_width - width,
				panel.y + 22.0f,
				width,
				height
			};
		}

		bool draw(
			c_renderer& renderer,
			rect_t panel,
			rect_t title_area,
			point_t cursor,
			bool mouse_pressed,
			bool interactive,
			float opacity
		) {
			opacity = clamp01( opacity );
			update_submission( );
			if ( interactive && !m_display_name_saved && !m_showing_thank_you )
				update_keyboard( );

			const auto button = continue_button( panel );
			const auto button_hovered = interactive && m_display_name_saved && contains( cursor, button );
			const auto button_progress = update_continue_color( );
			const auto can_continue = interactive && m_display_name_saved && button_progress >= 0.999f;
			draw_continue_button( renderer, button, button_hovered, button_progress, opacity );

			const auto center_y = panel.y + panel.height * 0.5f - 60.0f;
			const rect_t centered_heading{
				panel.x + 24.0f,
				center_y - 50.0f,
				panel.width - 48.0f,
				64.0f
			};
			draw_text(
				renderer, L"Undetected-Easy", centered_heading, 28.0f,
				color_t::from_rgba( 8, 130, 217 ), text_align_t::center,
				fonts::bold_medium, DWRITE_FONT_WEIGHT_BOLD, opacity
			);
			draw_text(
				renderer, L"Catch Detections before they can catch you.",
				{ centered_heading.x, center_y + 1.0f, centered_heading.width, 34.0f },
				18.0f, color_t::from_rgba( 235, 241, 248 ), text_align_t::center,
				fonts::bold_medium, DWRITE_FONT_WEIGHT_BOLD, opacity
			);
			draw_text(
				renderer, L"Detections reversed from EasyAntiCheat, Vanguard, and more.",
				{ centered_heading.x, center_y + 1.0f, centered_heading.width, 84.0f },
				18.0f, color_t::from_rgba( 235, 241, 248 ), text_align_t::center,
				fonts::bold_medium, DWRITE_FONT_WEIGHT_BOLD, opacity
			);

			if ( m_display_name_saved )
				draw_returning_user( renderer, panel, title_area, button, centered_heading, center_y, opacity );
			else
				draw_name_input( renderer, panel, center_y, opacity );

			return can_continue && mouse_pressed && contains( cursor, button );
		}

	private:
		static float clamp01( float value ) {
			return value < 0.0f ? 0.0f : ( value > 1.0f ? 1.0f : value );
		}

		static float smooth_step( float value ) {
			value = clamp01( value );
			return value * value * ( 3.0f - 2.0f * value );
		}

		static bool contains( point_t cursor, rect_t area ) {
			return cursor.x >= area.x && cursor.x < area.x + area.width &&
				cursor.y >= area.y && cursor.y < area.y + area.height;
		}

		static color_t faded( color_t color, float opacity ) {
			color.a *= clamp01( opacity );
			return color;
		}

		static void draw_text(
			c_renderer& renderer,
			std::wstring_view value,
			rect_t area,
			float size,
			color_t color,
			text_align_t alignment,
			std::wstring_view family,
			DWRITE_FONT_WEIGHT weight,
			float opacity
		) {
			renderer.text( value, area, size, faded( color, opacity ), alignment, family, weight );
		}

		void update_keyboard( ) {
			auto pressed = [ & ]( int key ) {
				const auto down = ( GetAsyncKeyState( key ) & 0x8000 ) != 0;
				const auto result = down && !m_key_was_down[ key ];
				m_key_was_down[ key ] = down;
				return result;
			};

			const auto shift_down = ( GetAsyncKeyState( VK_SHIFT ) & 0x8000 ) != 0;
			for ( auto key = 'A'; key <= 'Z'; ++key ) {
				if ( pressed( key ) && m_display_name.size( ) < 24 )
					m_display_name.push_back( static_cast< wchar_t >( shift_down ? key : key + 32 ) );
			}
			for ( auto key = '0'; key <= '9'; ++key ) {
				if ( pressed( key ) && m_display_name.size( ) < 24 )
					m_display_name.push_back( static_cast< wchar_t >( key ) );
			}
			if ( pressed( VK_SPACE ) && !m_display_name.empty( ) && m_display_name.size( ) < 24 )
				m_display_name.push_back( L' ' );
			if ( pressed( VK_OEM_MINUS ) && m_display_name.size( ) < 24 )
				m_display_name.push_back( shift_down ? L'_' : L'-' );
			if ( pressed( VK_BACK ) && !m_display_name.empty( ) )
				m_display_name.pop_back( );
			if ( pressed( VK_RETURN ) && !m_display_name.empty( ) ) {
				while ( !m_display_name.empty( ) && m_display_name.back( ) == L' ' )
					m_display_name.pop_back( );
				if ( !m_display_name.empty( ) ) {
					m_showing_thank_you = true;
					m_thank_you_started = std::chrono::steady_clock::now( );
				}
			}
		}

		void update_submission( ) {
			if ( !m_showing_thank_you )
				return;

			const auto elapsed = std::chrono::duration< float >(
				std::chrono::steady_clock::now( ) - m_thank_you_started
			).count( );
			if ( elapsed < 2.5f )
				return;

			FILE* file = nullptr;
			if ( _wfopen_s( &file, m_log_path.c_str( ), L"wt, ccs=UTF-8" ) == 0 && file ) {
				fputws( m_display_name.c_str( ), file );
				fclose( file );
				m_display_name_saved = true;
				m_continue_color_animating = true;
				m_continue_color_started = std::chrono::steady_clock::now( );
			}
			m_showing_thank_you = false;
		}

		float update_continue_color( ) {
			if ( !m_display_name_saved )
				return 0.0f;
			if ( !m_continue_color_animating )
				return 1.0f;

			const auto elapsed = std::chrono::duration< float >(
				std::chrono::steady_clock::now( ) - m_continue_color_started
			).count( );
			if ( elapsed >= 0.75f ) {
				m_continue_color_animating = false;
				return 1.0f;
			}
			return smooth_step( elapsed / 0.75f );
		}

		void draw_continue_button(
			c_renderer& renderer,
			rect_t button,
			bool hovered,
			float progress,
			float opacity
		) {
			auto blend = [ progress ]( int from, int to ) {
				return static_cast< std::uint8_t >( from + ( to - from ) * progress );
			};
			const auto target_red = hovered ? 28 : 8;
			const auto target_green = hovered ? 151 : 130;
			const auto target_blue = hovered ? 235 : 217;

			renderer.filled_rounded_rectangle(
				{ button.x - 2.0f, button.y - 2.0f, button.width + 4.0f, button.height + 4.0f },
				button.height * 0.5f + 2.0f,
				faded( color_t::from_rgba(
					blend( 76, 8 ), blend( 82, 130 ), blend( 90, 217 ),
					static_cast< std::uint8_t >( ( hovered ? 50.0f : 28.0f ) * progress )
				), opacity )
			);
			renderer.filled_rounded_rectangle(
				button,
				button.height * 0.5f,
				faded( color_t::from_rgba(
					blend( 76, target_red ), blend( 82, target_green ), blend( 90, target_blue )
				), opacity )
			);
			draw_text(
				renderer, L"Continue", button, 14.0f,
				color_t::from_rgba( blend( 180, 255 ), blend( 184, 255 ), blend( 190, 255 ) ),
				text_align_t::center, fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT, opacity
			);
		}

		void draw_returning_user(
			c_renderer& renderer,
			rect_t panel,
			rect_t title_area,
			rect_t button,
			rect_t centered_heading,
			float center_y,
			float opacity
		) {
			const auto welcome_text = std::wstring( L"Welcome back, " ) + m_display_name;
			const auto ude_size = renderer.measure_text(
				L"UDE", 26.0f, fonts::bold_medium, DWRITE_FONT_WEIGHT_MEDIUM
			);
			const auto welcome_left = title_area.x + ude_size.width + 16.0f;
			const auto welcome_right = button.x - 16.0f;
			draw_text(
				renderer, welcome_text,
				{ welcome_left, button.y, welcome_right - welcome_left, button.height },
				14.0f, color_t::from_rgba( 145, 155, 168 ), text_align_t::center,
				fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT, opacity
			);
			draw_text(
				renderer, L"Press Continue to start.",
				{ centered_heading.x, center_y + 1.0f, centered_heading.width, 134.0f },
				18.0f, color_t::from_rgba( 235, 241, 248 ), text_align_t::center,
				fonts::bold_medium, DWRITE_FONT_WEIGHT_BOLD, opacity
			);
		}

		void draw_name_input( c_renderer& renderer, rect_t panel, float center_y, float opacity ) {
			const rect_t box{
				panel.x + panel.width * 0.5f - 150.0f,
				center_y + 62.0f,
				300.0f,
				38.0f
			};
			renderer.rounded_rectangle(
				{ box.x + 0.5f, box.y + 0.5f, box.width - 1.0f, box.height - 1.0f },
				8.0f, faded( color_t::from_rgba( 14, 81, 149 ), opacity ), 1.0f
			);
			const rect_t text_area{ box.x + 14.0f, box.y, box.width - 28.0f, box.height };

			if ( m_showing_thank_you ) {
				const auto elapsed = std::chrono::duration< float >(
					std::chrono::steady_clock::now( ) - m_thank_you_started
				).count( );
				const auto transition = smooth_step( elapsed / 2.5f );
				draw_text(
					renderer, m_display_name, text_area, 14.0f,
					color_t::from_rgba( 235, 241, 248 ), text_align_t::left,
					fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT, opacity * ( 1.0f - transition )
				);
			}
			else if ( m_display_name.empty( ) ) {
				draw_text(
					renderer, L"What should we call you?", text_area, 14.0f,
					color_t::from_rgba( 220, 229, 238 ), text_align_t::center,
					fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT, opacity
				);
			}
			else {
				draw_text(
					renderer, m_display_name, text_area, 14.0f,
					color_t::from_rgba( 235, 241, 248 ), text_align_t::left,
					fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT, opacity
				);
			}

			const auto blink_time = std::chrono::duration_cast< std::chrono::milliseconds >(
				std::chrono::steady_clock::now( ).time_since_epoch( )
			).count( );
			if ( !m_showing_thank_you && ( blink_time / 500 ) % 2 == 0 ) {
				const auto text_size = renderer.measure_text(
					m_display_name, 14.0f, fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
				);
				renderer.filled_rectangle(
					{ text_area.x + text_size.width + 1.0f, box.y + 10.0f, 1.0f, 18.0f },
					faded( color_t::from_rgba( 8, 130, 217 ), opacity )
				);
			}
		}

		std::wstring m_log_path;
		std::wstring m_display_name;
		bool m_display_name_saved = false;
		bool m_showing_thank_you = false;
		bool m_continue_color_animating = false;
		std::chrono::steady_clock::time_point m_thank_you_started{ };
		std::chrono::steady_clock::time_point m_continue_color_started{ };
		std::array< bool, 256 > m_key_was_down{ };
	};
}
