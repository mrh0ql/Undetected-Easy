#pragma once

namespace render {
	void draw_callback( c_renderer& renderer ) {
		static rect_t panel{ 20.0f, 16.0f, 922.0f, 558.0f };
		constexpr auto corner_radius = 17.0f;
		constexpr auto icon_size = 42.0f;
		constexpr auto top_bar_height = 52.0f;
		static auto shield = renderer.load_image( L"assets\\shield.png" );
		static bool dragging = false;
		static bool button_was_down = false;
		static point_t drag_offset{ };
		static widgets::stage_t current_stage = widgets::stage_t::welcome;
		static bool switching_stage = false;
		static std::chrono::steady_clock::time_point stage_switch_started{ };
		static widgets::stages::c_welcome_stage welcome_stage;
		static widgets::stages::c_dashboard_stage dashboard_stage;

		POINT screen_cursor{ };
		GetCursorPos( &screen_cursor );
		const point_t cursor{
			static_cast< float >( screen_cursor.x - GetSystemMetrics( SM_XVIRTUALSCREEN ) ),
			static_cast< float >( screen_cursor.y - GetSystemMetrics( SM_YVIRTUALSCREEN ) )
		};
		const auto button_down = ( GetAsyncKeyState( VK_LBUTTON ) & 0x8000 ) != 0;
		const auto button_pressed = button_down && !button_was_down;
		const rect_t top_bar{ panel.x, panel.y, panel.width, top_bar_height };
		const auto continue_button = widgets::stages::c_welcome_stage::continue_button( panel );
		auto contains = [ & ]( rect_t area ) {
			return cursor.x >= area.x && cursor.x < area.x + area.width &&
				cursor.y >= area.y && cursor.y < area.y + area.height;
		};

		const auto over_welcome_control = current_stage == widgets::stage_t::welcome &&
			contains( continue_button );
		if ( button_pressed && !over_welcome_control && contains( top_bar ) ) {
			dragging = true;
			drag_offset = { cursor.x - panel.x, cursor.y - panel.y };
		}
		if ( !button_down )
			dragging = false;

		if ( dragging ) {
			panel.x = cursor.x - drag_offset.x;
			panel.y = cursor.y - drag_offset.y;
			const auto available_width = static_cast< float >( GetSystemMetrics( SM_CXVIRTUALSCREEN ) );
			const auto available_height = static_cast< float >( GetSystemMetrics( SM_CYVIRTUALSCREEN ) );
			const auto maximum_x = available_width > panel.width ? available_width - panel.width : 0.0f;
			const auto maximum_y = available_height > panel.height ? available_height - panel.height : 0.0f;
			panel.x = panel.x < 0.0f ? 0.0f : ( panel.x > maximum_x ? maximum_x : panel.x );
			panel.y = panel.y < 0.0f ? 0.0f : ( panel.y > maximum_y ? maximum_y : panel.y );
		}
		button_was_down = button_down;

		renderer.interactive_area(
			current_stage == widgets::stage_t::dashboard
				? panel
				: rect_t{ panel.x, panel.y, panel.width, top_bar_height }
		);
		renderer.filled_rounded_rectangle(
			panel, corner_radius, color_t::from_rgba( 24, 24, 24 )
		);
		constexpr auto border_thickness = 1.5f;
		const rect_t inner_panel{
			panel.x + border_thickness,
			panel.y + border_thickness,
			panel.width - border_thickness * 2.0f,
			panel.height - border_thickness * 2.0f
		};
		renderer.filled_rounded_rectangle(
			inner_panel,
			corner_radius - border_thickness,
			color_t::from_rgba( 24, 24, 24 )
		);

		if ( renderer.push_rounded_clip( inner_panel, corner_radius - border_thickness ) ) {
			auto draw_corner_glow = [ & ]( point_t center ) {
				renderer.filled_circle( center, 260.0f, color_t::from_rgba( 60, 130, 220, 8 ) );
				renderer.filled_circle( center, 220.0f, color_t::from_rgba( 60, 130, 220, 10 ) );
				renderer.filled_circle( center, 180.0f, color_t::from_rgba( 60, 130, 220, 13 ) );
				renderer.filled_circle( center, 140.0f, color_t::from_rgba( 60, 130, 220, 16 ) );
			};
			draw_corner_glow( { panel.x - 8.0f, panel.y + panel.height + 8.0f } );
			draw_corner_glow( { panel.x + panel.width + 8.0f, panel.y - 8.0f } );

			constexpr auto dot_spacing = 20.0f;
			constexpr auto outer_dot_radius = 3.0f;
			constexpr auto inner_dot_radius = 2.0f;
			const point_t pattern_center{ inner_panel.width * 0.5f, inner_panel.height * 0.5f };
			const auto maximum_distance = std::sqrt(
				pattern_center.x * pattern_center.x + pattern_center.y * pattern_center.y
			);
			const auto animation_time = std::chrono::duration< float >(
				std::chrono::steady_clock::now( ).time_since_epoch( )
			).count( );
			for ( auto y = 0.0f; y < inner_panel.height; y += dot_spacing ) {
				for ( auto x = 0.0f; x < inner_panel.width; x += dot_spacing ) {
					const auto dx = x - pattern_center.x;
					const auto dy = y - pattern_center.y;
					const auto distance = std::sqrt( dx * dx + dy * dy );
					const auto distance_fade = ( std::max )( 0.0f, 1.0f - distance / maximum_distance );
					const auto pulse = 0.5f + 0.5f * std::sin(
						animation_time * 2.0f + ( x + y ) * 0.05f
					);
					const auto alpha = 0.1f * distance_fade * pulse;
					if ( alpha <= 0.005f )
						continue;
					const auto alpha_byte = static_cast< std::uint8_t >( alpha * 255.0f );
					const point_t dot{ inner_panel.x + x + 1.0f, inner_panel.y + y + 1.0f };
					renderer.filled_circle(
						dot, outer_dot_radius, color_t::from_rgba( 8, 130, 217, alpha_byte )
					);
					renderer.filled_circle(
						dot, inner_dot_radius, color_t::from_rgba( 24, 24, 24, alpha_byte )
					);
				}
			}
			renderer.pop_clip( );
		}

		const rect_t icon{
			inner_panel.x + 45.0f,
			inner_panel.y + 15.0f,
			icon_size,
			icon_size
		};
		renderer.draw_image( shield, icon );
		const rect_t title_area{
			icon.x + icon.width + 8.0f,
			icon.y - 1.0f,
			280.0f,
			icon.height - 1.0f
		};
		constexpr point_t title_outline_offsets[] = {
			{ -1.0f, -1.0f }, { 0.0f, -1.0f }, { 1.0f, -1.0f },
			{ -1.0f,  0.0f },                     { 1.0f,  0.0f },
			{ -1.0f,  1.0f }, { 0.0f,  1.0f }, { 1.0f,  1.0f }
		};
		for ( auto offset : title_outline_offsets ) {
			auto outlined_area = title_area;
			outlined_area.x += offset.x;
			outlined_area.y += offset.y;
			renderer.text(
				L"UDE", outlined_area, 26.0f, color_t::from_rgba( 24, 24, 24 ),
				text_align_t::left, fonts::bold_medium, DWRITE_FONT_WEIGHT_MEDIUM
			);
		}
		renderer.text(
			L"UDE", title_area, 26.0f, color_t::from_rgba( 8, 130, 217 ),
			text_align_t::left, fonts::bold_medium, DWRITE_FONT_WEIGHT_MEDIUM
		);

		auto stage_opacity = 1.0f;
		if ( switching_stage ) {
			const auto elapsed = std::chrono::duration< float >(
				std::chrono::steady_clock::now( ) - stage_switch_started
			).count( );
			const auto progress = elapsed < 0.0f ? 0.0f : ( elapsed > 2.0f ? 1.0f : elapsed / 2.0f );
			const auto eased = progress * progress * ( 3.0f - 2.0f * progress );
			stage_opacity = 1.0f - eased;
			if ( elapsed >= 2.0f ) {
				current_stage = widgets::stage_t::dashboard;
				switching_stage = false;
				stage_opacity = 1.0f;
			}
		}

		if ( current_stage == widgets::stage_t::welcome ) {
			renderer.push_opacity( stage_opacity );
			const auto advance = welcome_stage.draw(
				renderer,
				panel,
				title_area,
				cursor,
				button_pressed,
				!switching_stage,
				1.0f
			);
			renderer.pop_opacity( );
			if ( advance && !switching_stage ) {
				switching_stage = true;
				stage_switch_started = std::chrono::steady_clock::now( );
			}
		}
		else if ( current_stage == widgets::stage_t::dashboard ) {
			dashboard_stage.draw( renderer, panel, cursor, button_pressed );
		}
	}
}
