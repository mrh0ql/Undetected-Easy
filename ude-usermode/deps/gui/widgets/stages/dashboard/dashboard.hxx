#pragma once

namespace render::widgets::stages {
	enum class dashboard_setup_state {
		idle,
		running,
		enabling_test_signing,
		restarting,
		missing_driver,
		test_signing_required,
		pdb_failed,
		service_failed,
		driver_connection_failed,
		driver_ping_failed,
		callback_setup_failed,
		restart_required,
		success
	};

	inline std::atomic< dashboard_setup_state > g_dashboard_setup_state{
		dashboard_setup_state::idle
	};
	inline std::mutex g_dashboard_setup_mutex;
	inline std::wstring g_dashboard_driver_path;
	inline std::array< std::atomic_bool, 10 > g_dashboard_scan_selected{
		true, true, true, true, true, true, true, true, true, true
	};
	inline std::atomic_bool g_dashboard_scan_selection_submitted = false;
	inline std::atomic< float > g_dashboard_scan_progress = 0.0f;
	inline std::atomic< unsigned long > g_dashboard_detection_count = 0;
	inline std::atomic_bool g_dashboard_scan_complete = false;
	inline std::atomic< long long > g_dashboard_scan_started_ms = 0;
	struct dashboard_detection_result {
		std::wstring title;
		bool detected = false;
		std::vector< std::wstring > reasons;
	};
	inline std::mutex g_dashboard_results_mutex;
	inline std::vector< dashboard_detection_result > g_dashboard_results;

	inline void set_dashboard_results( std::vector< dashboard_detection_result > results ) {
		std::lock_guard lock( g_dashboard_results_mutex );
		g_dashboard_results = std::move( results );
	}

	inline void set_dashboard_driver_path( std::wstring path ) {
		std::lock_guard lock( g_dashboard_setup_mutex );
		g_dashboard_driver_path = std::move( path );
	}

	inline void run_dashboard_setup( ) {
		std::wstring driver_path;
		{
			std::lock_guard lock( g_dashboard_setup_mutex );
			driver_path = g_dashboard_driver_path;
		}

		if ( driver_path.empty( ) ) {
			g_dashboard_setup_state.store( dashboard_setup_state::missing_driver );
			return;
		}
		if ( !g_service->test_signing_enabled( ) ) {
			g_dashboard_setup_state.store( dashboard_setup_state::test_signing_required );
			return;
		}

		utility::print( obf( "[ + ]" ), obf( "downloading ntoskrnl pdb!" ) );
		if ( !g_pdb->load( ) ) {
			utility::print( obf( "[ - ]" ), obf( "failed to load pdb" ) );
			g_dashboard_setup_state.store( dashboard_setup_state::pdb_failed );
			return;
		}

		utility::print( obf( "[ + ]" ), obf( "loaded %d symbols\n" ), g_pdb->m_symbols.size( ) );
		if ( !g_service->create( driver_path.c_str( ) ) ) {
			utility::print( obf( "[ - ]" ), obf( "failed to load service" ) );
			g_driver->close( );
			g_service->unload( );
			g_dashboard_setup_state.store( dashboard_setup_state::service_failed );
			return;
		}

		utility::print( obf( "[ + ]" ), obf( "started service!\n" ) );
		if ( !g_driver->setup( ) ) {
			utility::print( obf( "[ - ]" ), obf( "failed to connect to driver" ) );
			g_driver->close( );
			g_service->unload( );
			g_dashboard_setup_state.store( dashboard_setup_state::driver_connection_failed );
			return;
		}

		if ( !g_driver->ping( ) ) {
			utility::print( obf( "[ - ]" ), obf( "failed to ping driver" ) );
			g_driver->close( );
			g_service->unload( );
			g_dashboard_setup_state.store( dashboard_setup_state::driver_ping_failed );
			return;
		}

		if ( !g_driver->setup_image_callback( blocklist::g_policy ) ) {
			utility::print( obf( "[ - ]" ), obf( "failed to setup image callback" ) );
			g_driver->close( );
			g_service->unload( );
			g_dashboard_setup_state.store( dashboard_setup_state::callback_setup_failed );
			return;
		}

		utility::print(
			obf( "[ + ]" ),
			obf( "uploaded %zu vulnerable-driver rules and registered image callback" ),
			blocklist::g_policy.rules.size( )
		);
		utility::print( obf( "[ + ]" ), obf( "connected to driver!" ) );
		g_dashboard_setup_state.store( dashboard_setup_state::success );
	}

	inline void start_dashboard_setup_once( ) {
		auto expected = dashboard_setup_state::idle;
		if ( !g_dashboard_setup_state.compare_exchange_strong(
			expected,
			dashboard_setup_state::running
		) )
			return;
		std::thread( [ ] { run_dashboard_setup( ); } ).detach( );
	}

	class c_dashboard_stage {
	public:
		void draw( c_renderer& renderer, rect_t panel, point_t cursor, bool mouse_pressed ) {
			if ( m_section == dashboard_section::content ) {
				draw_scan_content( renderer, panel, cursor, mouse_pressed );
				return;
			}
			if ( m_section == dashboard_section::scanning ) {
				draw_scan_progress( renderer, panel, cursor, mouse_pressed );
				return;
			}
			if ( m_section == dashboard_section::results ) {
				draw_results( renderer, panel );
				return;
			}

			start_dashboard_setup_once( );
			const auto state = g_dashboard_setup_state.load( );
			switch ( state ) {
			case dashboard_setup_state::idle:
			case dashboard_setup_state::running:
				draw_loading( renderer, panel, L"Preparing your environment..." );
				break;
			case dashboard_setup_state::enabling_test_signing:
				draw_loading( renderer, panel, L"Enabling test signing..." );
				break;
			case dashboard_setup_state::restarting:
				draw_loading( renderer, panel, L"Restarting Windows..." );
				break;
			case dashboard_setup_state::missing_driver:
				draw_status(
					renderer, panel, status_icon::error,
					L"Driver file missing",
					L"Start UDE with the path to ude-driver.sys.",
					{ }, cursor, mouse_pressed
				);
				break;
			case dashboard_setup_state::test_signing_required:
				if ( draw_status(
					renderer, panel, status_icon::warning,
					L"Test signing is required",
					L"Enable test signing to load the driver. A restart will be required.",
					L"Enable test signing", cursor, mouse_pressed
				) )
					enable_test_signing( );
				break;
			case dashboard_setup_state::pdb_failed:
				if ( draw_status(
					renderer, panel, status_icon::error,
					L"Symbol download failed",
					L"Check your internet connection and try again.",
					L"Retry", cursor, mouse_pressed
				) )
					retry_setup( );
				break;
			case dashboard_setup_state::service_failed:
				if ( draw_status(
					renderer, panel, status_icon::error,
					L"Driver service failed",
					L"Run UDE as administrator and verify the driver file.",
					L"Retry", cursor, mouse_pressed
				) )
					retry_setup( );
				break;
			case dashboard_setup_state::driver_connection_failed:
				if ( draw_status(
					renderer, panel, status_icon::error,
					L"Driver connection failed",
					L"The service started, but UDE could not connect to the driver.",
					L"Retry", cursor, mouse_pressed
				) )
					retry_setup( );
				break;
			case dashboard_setup_state::driver_ping_failed:
				if ( draw_status(
					renderer, panel, status_icon::error,
					L"Driver did not respond",
					L"The driver connection was created but failed its health check.",
					L"Retry", cursor, mouse_pressed
				) )
					retry_setup( );
				break;
			case dashboard_setup_state::callback_setup_failed:
				if ( draw_status(
					renderer, panel, status_icon::error,
					L"Image callback setup failed",
					L"UDE could not upload the vulnerable-driver blocklist to the driver.",
					L"Retry", cursor, mouse_pressed
				) )
					retry_setup( );
				break;
			case dashboard_setup_state::restart_required:
				if ( draw_status(
					renderer, panel, status_icon::warning,
					L"Restart required",
					L"Test signing is enabled. Restart Windows to apply the change.",
					L"Restart now", cursor, mouse_pressed
				) )
					restart_windows( );
				break;
			case dashboard_setup_state::success: {
				auto opacity = 1.0f;
				if ( m_content_transitioning ) {
					const auto elapsed = std::chrono::duration< float >(
						std::chrono::steady_clock::now( ) - m_content_transition_started
					).count( );
					if ( elapsed >= 2.0f ) {
						m_section = dashboard_section::content;
						m_content_transitioning = false;
						break;
					}
					const auto progress = elapsed / 2.0f;
					const auto eased = progress * progress * ( 3.0f - 2.0f * progress );
					opacity = 1.0f - eased;
				}
				renderer.push_opacity( opacity );
				const auto advance = draw_status(
					renderer, panel, status_icon::success,
					L"Setup complete",
					L"UDE connected to the driver successfully.",
					L"Continue", cursor, mouse_pressed && !m_content_transitioning, 1.0f
				);
				renderer.pop_opacity( );
				if ( advance ) {
					m_content_transitioning = true;
					m_content_transition_started = std::chrono::steady_clock::now( );
				}
				break;
			}
			}
		}

	private:
		enum class dashboard_section { setup, content, scanning, results };
		enum class status_icon { error, warning, success };

		static color_t faded( color_t color, float opacity ) {
			opacity = opacity < 0.0f ? 0.0f : ( opacity > 1.0f ? 1.0f : opacity );
			color.a *= opacity;
			return color;
		}

		static void draw_blue_spinner_arc(
			c_renderer& renderer,
			point_t center,
			float radius,
			float rotation
		) {
			constexpr auto arc_length = 1.95f;
			constexpr auto segment_count = 16;
			constexpr auto segment_length = arc_length / static_cast< float >( segment_count );
			constexpr auto overlap = 0.025f;
			renderer.arc(
				center, radius, rotation - arc_length, arc_length,
				color_t::from_rgba( 45, 125, 230, 28 ), 5.5f
			);

			for ( auto index = 0; index < segment_count; ++index ) {
				const auto linear = static_cast< float >( index + 1 ) /
					static_cast< float >( segment_count );
				const auto blend = linear * linear * ( 3.0f - 2.0f * linear );
				auto channel = [ blend ]( int from, int to ) {
					return static_cast< std::uint8_t >( from + ( to - from ) * blend );
				};
				const auto start = rotation - arc_length + index * segment_length - overlap;
				renderer.arc(
					center,
					radius,
					start,
					segment_length + overlap * 2.0f,
					color_t::from_rgba(
						channel( 40, 115 ),
						channel( 110, 190 ),
						channel( 205, 255 ),
						channel( 28, 255 )
					),
					1.25f + blend * 1.05f
				);
			}
		}

		static bool contains( point_t cursor, rect_t area ) {
			return cursor.x >= area.x && cursor.x < area.x + area.width &&
				cursor.y >= area.y && cursor.y < area.y + area.height;
		}

		void draw_scan_content(
			c_renderer& renderer,
			rect_t panel,
			point_t cursor,
			bool mouse_pressed
		) {
			auto content_fade = 0.0f;
			if ( m_scan_continue_pressed ) {
				const auto elapsed = std::chrono::duration< float >(
					std::chrono::steady_clock::now( ) - m_scan_continue_started
				).count( );
				if ( elapsed >= 2.0f ) {
					m_section = dashboard_section::scanning;
					g_dashboard_scan_selection_submitted.store( true );
					return;
				}
				if ( elapsed > 1.0f ) {
					const auto progress = elapsed - 1.0f;
					content_fade = progress * progress * ( 3.0f - 2.0f * progress );
				}
			}
			renderer.push_opacity( 1.0f - content_fade );
			constexpr std::wstring_view names[] = {
				L"Module integrity", L"Execution integrity", L"Memory integrity",
				L"Process integrity", L"Pool integrity", L"Device surface",
				L"Service integrity", L"CPU integrity", L"Object integrity",
				L"DPC integrity"
			};
			constexpr std::wstring_view descriptions[ ] = {
				L"Validates loaded modules", L"Validates execution",
				L"Validates protected memory", L"Validates active processes",
				L"Validates allocated pools", L"Validates device objects",
				L"Validates system services", L"Validates processor state",
				L"Validates kernel objects", L"Validates deferred procedure calls"
			};
			constexpr auto card_width = 390.0f;
			constexpr auto card_height = 58.0f;
			constexpr auto column_gap = 38.0f;
			constexpr auto row_gap = 11.0f;
			const auto content_width = card_width * 2.0f + column_gap;
			const auto content_left = panel.x + ( panel.width - content_width ) * 0.5f;

			for ( auto index = 0; index < 10; ++index ) {
				const auto column = index / 5;
				const auto row = index % 5;
				const rect_t card{
					content_left + column * ( card_width + column_gap ),
					panel.y + 96.0f + row * ( card_height + row_gap ),
					card_width,
					card_height
				};
				if ( mouse_pressed && contains( cursor, card ) && !m_scan_continue_pressed ) {
					const auto selected = g_dashboard_scan_selected[ index ].load( );
					g_dashboard_scan_selected[ index ].store( !selected );
				}
				const auto selected = g_dashboard_scan_selected[ index ].load( );
				const auto hovered = contains( cursor, card );
				renderer.filled_rounded_rectangle(
					card, 9.0f,
					hovered ? color_t::from_rgba( 29, 39, 50 ) : color_t::from_rgba( 26, 34, 44 )
				);
				renderer.rounded_rectangle(
					{ card.x + 0.5f, card.y + 0.5f, card.width - 1.0f, card.height - 1.0f },
					8.5f, color_t::from_rgba( 40, 57, 74 ), 1.0f
				);

				const rect_t icon{ card.x + 12.0f, card.y + 12.0f, 36.0f, 36.0f };
				renderer.filled_rounded_rectangle(
					icon, 8.0f,
					selected ? color_t::from_rgba( 8, 130, 217 ) : color_t::from_rgba( 62, 75, 89 )
				);
				const point_t icon_center{ icon.x + 18.0f, icon.y + 18.0f };
				renderer.circle( icon_center, 8.0f, color_t::from_rgba( 230, 241, 252 ), 1.4f );
				renderer.line(
					{ icon_center.x - 4.0f, icon_center.y },
					{ icon_center.x - 1.0f, icon_center.y + 4.0f },
					color_t::from_rgba( 230, 241, 252 ), 1.4f
				);
				renderer.line(
					{ icon_center.x - 1.0f, icon_center.y + 4.0f },
					{ icon_center.x + 5.0f, icon_center.y - 4.0f },
					color_t::from_rgba( 230, 241, 252 ), 1.4f
				);

				renderer.text(
					names[ index ],
					{ card.x + 60.0f, card.y + 6.0f, card.width - 124.0f, 26.0f },
					15.0f, color_t::from_rgba( 232, 239, 247 ), text_align_t::left,
					fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
				);
				renderer.text(
					descriptions[ index ],
					{ card.x + 60.0f, card.y + 30.0f, card.width - 124.0f, 20.0f },
					12.0f, color_t::from_rgba( 125, 141, 158 ), text_align_t::left,
					fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
				);

				const rect_t toggle{ card.x + card.width - 50.0f, card.y + 19.0f, 38.0f, 20.0f };
				renderer.filled_rounded_rectangle(
					toggle, 10.0f,
					selected ? color_t::from_rgba( 8, 130, 217 ) : color_t::from_rgba( 82, 93, 105 )
				);
				renderer.filled_circle(
					{ selected ? toggle.x + 28.0f : toggle.x + 10.0f, toggle.y + 10.0f },
					7.0f, color_t::from_rgba( 245, 248, 251 )
				);
			}

			auto selected_count = 0;
			for ( const auto& selected : g_dashboard_scan_selected )
				selected_count += selected.load( ) ? 1 : 0;
			const auto submitted = m_scan_continue_pressed;
			const rect_t footer{
				content_left,
				panel.y + 450.0f,
				content_width,
				48.0f
			};
			renderer.filled_rounded_rectangle(
				footer, 10.0f, color_t::from_rgba( 25, 32, 41 )
			);
			renderer.rounded_rectangle(
				{ footer.x + 0.5f, footer.y + 0.5f, footer.width - 1.0f, footer.height - 1.0f },
				9.5f, color_t::from_rgba( 39, 53, 68 ), 1.0f
			);
			const auto selection_text = std::to_wstring( selected_count ) + L" of 10 scans selected";
			renderer.text(
				selection_text,
				{ footer.x + 18.0f, footer.y, footer.width - 210.0f, footer.height },
				13.0f, color_t::from_rgba( 145, 158, 173 ), text_align_t::left,
				fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
			);
			const rect_t continue_button{
				footer.x + footer.width - 164.0f,
				footer.y + 8.0f,
				152.0f,
				32.0f
			};
			const auto enabled = selected_count > 0 && !submitted;
			const auto hovered = enabled && contains( cursor, continue_button );
			renderer.filled_rounded_rectangle(
				continue_button, 16.0f,
				enabled
					? ( hovered ? color_t::from_rgba( 28, 151, 235 ) : color_t::from_rgba( 8, 130, 217 ) )
					: color_t::from_rgba( 76, 82, 90 )
			);
			renderer.rounded_rectangle(
				{ continue_button.x + 0.5f, continue_button.y + 0.5f,
					continue_button.width - 1.0f, continue_button.height - 1.0f },
				15.5f,
				enabled ? color_t::from_rgba( 14, 81, 149 ) : color_t::from_rgba( 92, 99, 108 ),
				1.0f
			);
			renderer.text(
				L"Continue",
				continue_button, 13.0f,
				color_t::from_rgba( enabled ? 255 : 190, enabled ? 255 : 195, enabled ? 255 : 202 ),
				text_align_t::center, fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
			);
			if ( enabled && mouse_pressed && hovered ) {
				m_scan_continue_pressed = true;
				m_scan_continue_started = std::chrono::steady_clock::now( );
			}

			renderer.pop_opacity( );
		}

		void draw_scan_progress(
			c_renderer& renderer,
			rect_t panel,
			point_t cursor,
			bool mouse_pressed
		) {
			constexpr auto radius = 62.0f;
			const point_t center{
				panel.x + panel.width * 0.5f,
				panel.y + panel.height * 0.5f - 38.0f
			};
			const auto complete = g_dashboard_scan_complete.load( );
			const auto progress = ( std::min )( 100.0f, ( std::max )( 0.0f, g_dashboard_scan_progress.load( ) ) );
			const auto detections = g_dashboard_detection_count.load( );
			const auto now = std::chrono::steady_clock::now( );
			const auto time = std::chrono::duration< float >( now.time_since_epoch( ) ).count( );
			const auto rotation = time * 2.15f;
			const auto ring_color = complete
				? color_t::from_rgba( 55, 190, 125 )
				: color_t::from_rgba( 65, 150, 255 );
			auto results_fade = 0.0f;
			if ( m_results_transitioning ) {
				const auto elapsed = std::chrono::duration< float >(
					now - m_results_transition_started
				).count( );
				if ( elapsed >= 2.0f ) {
					m_section = dashboard_section::results;
					m_results_transitioning = false;
					return;
				}
				const auto transition = elapsed / 2.0f;
				results_fade = transition * transition * ( 3.0f - 2.0f * transition );
			}
			renderer.push_opacity( 1.0f - results_fade );

			if ( complete && !m_completion_started_set ) {
				m_completion_started_set = true;
				m_completion_started = now;
			}
			if ( complete )
				draw_confetti( renderer, panel, now );

			renderer.circle(
				center,
				radius,
				complete ? color_t::from_rgba( 55, 190, 125, 210 )
					: color_t::from_rgba( 40, 105, 190, 40 ),
				complete ? 2.0f : 1.0f
			);

			if ( !complete ) {
				draw_blue_spinner_arc( renderer, center, radius, rotation );
			}

			const auto percentage = std::to_wstring( static_cast< int >( progress + 0.5f ) ) + L"%";
			renderer.text(
				complete ? L"Done" : percentage,
				{ center.x - 70.0f, center.y - 20.0f, 140.0f, 40.0f },
				20.0f, complete ? ring_color : color_t::from_rgba( 232, 240, 249 ),
				text_align_t::center, fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
			);

			std::wstring estimate = L"Estimated time: calculating...";
			const auto started_ms = g_dashboard_scan_started_ms.load( );
			if ( !complete && started_ms > 0 && progress >= 1.0f ) {
				const auto now_ms = std::chrono::duration_cast< std::chrono::milliseconds >(
					now.time_since_epoch( )
				).count( );
				const auto elapsed_seconds = static_cast< float >( now_ms - started_ms ) / 1000.0f;
				const auto remaining = ( std::max )(
					0,
					static_cast< int >( elapsed_seconds * ( 100.0f - progress ) / progress + 0.5f )
				);
				if ( remaining < 60 ) {
					estimate = L"Estimated time: " + std::to_wstring( remaining ) + L"s";
				}
				else if ( remaining < 3600 ) {
					const auto minutes = remaining / 60;
					const auto seconds = remaining % 60;
					estimate = L"Estimated time: " + std::to_wstring( minutes ) + L"m " +
						std::to_wstring( seconds ) + L"s";
				}
				else {
					const auto hours = remaining / 3600;
					const auto minutes = ( remaining % 3600 ) / 60;
					estimate = L"Estimated time: " + std::to_wstring( hours ) + L"h " +
						std::to_wstring( minutes ) + L"m";
				}
			}
			else if ( complete ) {
				estimate = L"Scan completed successfully";
			}
			renderer.text(
				estimate,
				{ panel.x + 120.0f, center.y + radius + 22.0f, panel.width - 240.0f, 28.0f },
				14.0f, color_t::from_rgba( 155, 170, 187 ), text_align_t::center,
				fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
			);
			const auto detection_text = std::to_wstring( detections ) +
				( detections == 1 ? L" detection found" : L" detections found" );
			renderer.text(
				detection_text,
				{ panel.x + 120.0f, center.y + radius + 50.0f, panel.width - 240.0f, 28.0f },
				14.0f, detections ? color_t::from_rgba( 235, 170, 55 ) : color_t::from_rgba( 135, 151, 168 ),
				text_align_t::center, fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
			);

			if ( complete && m_completion_started_set ) {
				const auto completion_elapsed = std::chrono::duration< float >(
					now - m_completion_started
				).count( );
				if ( completion_elapsed >= 5.0f ) {
					const auto fade_progress = ( std::min )( 1.0f, ( completion_elapsed - 5.0f ) / 0.75f );
					const auto fade_in = fade_progress * fade_progress * ( 3.0f - 2.0f * fade_progress );
					const auto button_opacity = fade_in * ( 1.0f - results_fade );
					const rect_t continue_button{
						panel.x + panel.width - 141.0f,
						panel.y + 22.0f,
						112.0f,
						28.0f
					};
					const auto hovered = !m_results_transitioning && contains( cursor, continue_button );
					renderer.filled_rounded_rectangle(
						continue_button, 14.0f,
						faded(
							hovered ? color_t::from_rgba( 28, 151, 235 ) : color_t::from_rgba( 8, 130, 217 ),
							button_opacity
						)
					);
					renderer.rounded_rectangle(
						{ continue_button.x + 0.5f, continue_button.y + 0.5f,
							continue_button.width - 1.0f, continue_button.height - 1.0f },
						13.5f, faded( color_t::from_rgba( 14, 81, 149 ), button_opacity ), 1.0f
					);
					renderer.text(
						L"Continue", continue_button, 13.0f,
						faded( color_t::from_rgba( 255, 255, 255 ), button_opacity ),
						text_align_t::center, fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
					);
					if ( fade_in >= 0.999f && hovered && mouse_pressed ) {
						m_results_transitioning = true;
						m_results_transition_started = now;
					}
				}
			}

			renderer.pop_opacity( );
		}

		void draw_confetti(
			c_renderer& renderer,
			rect_t panel,
			std::chrono::steady_clock::time_point now
		) const {
			const auto elapsed = std::chrono::duration< float >( now - m_completion_started ).count( );
			if ( elapsed > 5.0f )
				return;
			const auto fade = elapsed > 4.0f ? 1.0f - ( elapsed - 4.0f ) : 1.0f;
			constexpr color_t colors[] = {
				color_t::from_rgba( 55, 184, 228 ), color_t::from_rgba( 24, 141, 215 ),
				color_t::from_rgba( 17, 117, 199 ), color_t::from_rgba( 25, 92, 158 )
			};
			for ( auto index = 0; index < 64; ++index ) {
				const auto seed = std::fmod( std::sin( index * 12.9898f ) * 43758.5453f, 1.0f );
				const auto normalized = seed < 0.0f ? seed + 1.0f : seed;
				const auto speed = 65.0f + static_cast< float >( index % 7 ) * 9.0f;
				const auto travel = std::fmod(
					static_cast< float >( index % 11 ) * 37.0f + elapsed * speed,
					panel.height - 105.0f
				);
				const auto x = panel.x + 38.0f + normalized * ( panel.width - 76.0f ) +
					std::sin( elapsed * 2.0f + index ) * 8.0f;
				const auto y = panel.y + 76.0f + travel;
				auto color = colors[ index % 4 ];
				color.a *= fade;
				renderer.filled_rectangle(
					{ x, y, index % 2 ? 4.0f : 6.0f, index % 3 ? 7.0f : 4.0f }, color
				);
			}
		}

		static void draw_results( c_renderer& renderer, rect_t panel ) {
			std::vector< dashboard_detection_result > results;
			{
				std::lock_guard lock( g_dashboard_results_mutex );
				results = g_dashboard_results;
			}
			const auto detections = g_dashboard_detection_count.load( );
			const rect_t summary{
				panel.x + 48.0f,
				panel.y + 70.0f,
				420.0f,
				430.0f
			};
			renderer.text(
				L"Scan results", { summary.x, summary.y, summary.width, 36.0f },
				24.0f, color_t::from_rgba( 236, 242, 248 ), text_align_t::center,
				fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
			);
			static auto failed_image = renderer.load_image( L"assets\\scan-failed.png" );
			static auto success_image = renderer.load_image( L"assets\\scan-success.png" );
			const rect_t shield_area{
				summary.x + ( summary.width - 220.0f ) * 0.5f,
				summary.y + 46.0f,
				220.0f,
				220.0f
			};
			if ( detections ) {
				renderer.draw_image(
					failed_image,
					{ shield_area.x + 25.0f, shield_area.y, 170.0f, 220.0f },
					0.38f
				);
			}
			else {
				renderer.draw_image( success_image, shield_area, 0.24f );
			}
			renderer.text(
				std::to_wstring( detections ),
				{ shield_area.x, summary.y + 102.0f, shield_area.width, 70.0f },
				48.0f, detections ? color_t::from_rgba( 235, 65, 75 ) : color_t::from_rgba( 55, 190, 125 ),
				text_align_t::center, fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
			);
			renderer.text(
				detections == 1 ? L"detection found" : L"detections found",
				{ shield_area.x, summary.y + 160.0f, shield_area.width, 28.0f },
				14.0f, color_t::from_rgba( 145, 158, 173 ), text_align_t::center,
				fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
			);
			constexpr std::wstring_view status_prefix = L"You are ";
			const auto status_value = detections
				? std::wstring_view( L"detected." )
				: std::wstring_view( L"undetected." );
			const auto status_prefix_size = renderer.measure_text(
				status_prefix, 13.0f, fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
			);
			const auto status_value_size = renderer.measure_text(
				status_value, 13.0f, fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
			);
			const auto status_x = summary.x +
				( summary.width - status_prefix_size.width - status_value_size.width ) * 0.5f;
			renderer.text(
				status_prefix,
				{ status_x, summary.y + 268.0f, status_prefix_size.width, 26.0f },
				13.0f, color_t::from_rgba( 145, 158, 173 ), text_align_t::left,
				fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
			);
			renderer.text(
				status_value,
				{ status_x + status_prefix_size.width, summary.y + 268.0f,
					status_value_size.width, 26.0f },
				13.0f, detections ? color_t::from_rgba( 235, 65, 75 ) : color_t::from_rgba( 8, 130, 217 ), text_align_t::left,
				fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
			);

			std::vector< std::wstring > reasons;
			for ( const auto& result : results ) {
				for ( const auto& reason : result.reasons ) {
					if ( std::find( reasons.begin( ), reasons.end( ), reason ) == reasons.end( ) )
						reasons.push_back( reason );
				}
			}
			const auto reason_count = reasons.size( );
			const auto reason_font_size = reason_count > 6 ? 8.0f : 9.0f;
			const auto reason_width = summary.width - 54.0f;
			auto reason_y = summary.y + 302.0f;
			for ( auto index = std::size_t{ 0 }; index < reason_count; ++index ) {
				const auto measured = renderer.measure_text(
					reasons[ index ], reason_font_size, fonts::poppins,
					DWRITE_FONT_WEIGHT_LIGHT, reason_width
				);
				const auto text_height = ( std::max )( measured.height, reason_font_size + 3.0f );
				renderer.filled_circle(
					{ summary.x + 24.0f, reason_y + reason_font_size * 0.55f }, 2.0f,
					color_t::from_rgba( 8, 130, 217 )
				);
				renderer.text(
					reasons[ index ],
					{ summary.x + 34.0f, reason_y, reason_width, text_height },
					reason_font_size, color_t::from_rgba( 150, 164, 180 ), text_align_t::left,
					fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT, true
				);
				reason_y += text_height + 4.0f;
			}

			const auto timeline_x = panel.x + 530.0f;
			const auto timeline_top = panel.y + 74.0f;
			if ( results.empty( ) ) {
				const point_t node{ timeline_x, timeline_top + 18.0f };
				renderer.circle( node, 11.0f, color_t::from_rgba( 55, 190, 125 ), 2.0f );
				renderer.text(
					L"No failed checks",
					{ timeline_x + 24.0f, timeline_top, 315.0f, 26.0f },
					15.0f, color_t::from_rgba( 235, 241, 248 ), text_align_t::left,
					fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
				);
				return;
			}

			const auto visible_count = ( std::min )( results.size( ), static_cast< std::size_t >( 10 ) );
			const auto item_spacing = 43.0f;
			for ( auto index = std::size_t{ 0 }; index < visible_count; ++index ) {
				const auto y = timeline_top + static_cast< float >( index ) * item_spacing;
				const point_t node{ timeline_x, y + 11.0f };
				if ( index + 1 < visible_count ) {
					renderer.line(
						{ node.x, node.y + 12.0f },
						{ node.x, node.y + item_spacing - 12.0f },
						color_t::from_rgba( 14, 81, 149, 175 ), 2.0f
					);
				}
				renderer.circle( node, 11.0f, color_t::from_rgba( 14, 81, 149 ), 2.0f );
				if ( results[ index ].detected ) {
					renderer.line(
						{ node.x - 4.0f, node.y - 4.0f }, { node.x + 4.0f, node.y + 4.0f },
						color_t::from_rgba( 255, 255, 255 ), 1.5f
					);
					renderer.line(
						{ node.x + 4.0f, node.y - 4.0f }, { node.x - 4.0f, node.y + 4.0f },
						color_t::from_rgba( 255, 255, 255 ), 1.5f
					);
				}
				else {
					renderer.line(
						{ node.x - 5.0f, node.y }, { node.x - 1.0f, node.y + 4.0f },
						color_t::from_rgba( 255, 255, 255 ), 1.6f
					);
					renderer.line(
						{ node.x - 1.0f, node.y + 4.0f }, { node.x + 6.0f, node.y - 5.0f },
						color_t::from_rgba( 255, 255, 255 ), 1.6f
					);
				}
				renderer.text(
					results[ index ].title,
					{ timeline_x + 24.0f, y - 3.0f, 315.0f, 22.0f },
					13.0f, color_t::from_rgba( 235, 241, 248 ), text_align_t::left,
					fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
				);
				const auto status = results[ index ].detected ? L"Detected" : L"No detections";
				renderer.text(
					status,
					{ timeline_x + 24.0f, y + 16.0f, 315.0f, 18.0f },
					9.5f,
					results[ index ].detected ? color_t::from_rgba( 235, 65, 75 ) : color_t::from_rgba( 70, 175, 120 ),
					text_align_t::left,
					fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
				);
			}
		}

		void retry_setup( ) {
			if ( m_action_running.load( ) )
				return;
			g_driver->close( );
			g_service->unload( );
			g_dashboard_setup_state.store( dashboard_setup_state::idle );
		}

		void enable_test_signing( ) {
			if ( m_action_running.exchange( true ) )
				return;
			g_dashboard_setup_state.store( dashboard_setup_state::enabling_test_signing );
			std::thread( [ this ] {
				const auto enabled = g_service->request_test_signing( );
				g_dashboard_setup_state.store(
					enabled ? dashboard_setup_state::restart_required : dashboard_setup_state::service_failed
				);
				m_action_running.store( false );
			} ).detach( );
		}

		void restart_windows( ) {
			if ( m_action_running.exchange( true ) )
				return;
			g_dashboard_setup_state.store( dashboard_setup_state::restarting );
			std::thread( [ this ] {
				if ( !g_service->request_restart( ) ) {
					g_dashboard_setup_state.store( dashboard_setup_state::restart_required );
					m_action_running.store( false );
				}
			} ).detach( );
		}

		static void draw_loading( c_renderer& renderer, rect_t panel, std::wstring_view message ) {
			constexpr auto radius = 62.0f;
			const point_t center{
				panel.x + panel.width * 0.5f,
				panel.y + panel.height * 0.5f - 20.0f
			};
			const auto time = std::chrono::duration< float >(
				std::chrono::steady_clock::now( ).time_since_epoch( )
			).count( );
			const auto rotation = time * 2.15f;
			renderer.circle( center, radius, color_t::from_rgba( 40, 105, 190, 40 ), 1.0f );
			draw_blue_spinner_arc( renderer, center, radius, rotation );
			renderer.text(
				message,
				{ panel.x + 120.0f, center.y + radius + 24.0f, panel.width - 240.0f, 32.0f },
				14.0f, color_t::from_rgba( 160, 174, 190 ), text_align_t::center,
				fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
			);
		}

		static bool draw_status(
			c_renderer& renderer,
			rect_t panel,
			status_icon icon,
			std::wstring_view title,
			std::wstring_view description,
			std::wstring_view action,
			point_t cursor,
			bool mouse_pressed,
			float opacity = 1.0f
		) {
			const point_t center{ panel.x + panel.width * 0.5f, panel.y + panel.height * 0.5f - 68.0f };
			color_t icon_color = color_t::from_rgba( 220, 65, 72 );
			if ( icon == status_icon::warning )
				icon_color = color_t::from_rgba( 235, 170, 55 );
			else if ( icon == status_icon::success )
				icon_color = color_t::from_rgba( 55, 190, 125 );
			icon_color = faded( icon_color, opacity );

			renderer.circle( center, 24.0f, icon_color, 2.0f );
			if ( icon == status_icon::success ) {
				renderer.line( { center.x - 10.0f, center.y }, { center.x - 3.0f, center.y + 8.0f }, icon_color, 2.4f );
				renderer.line( { center.x - 3.0f, center.y + 8.0f }, { center.x + 12.0f, center.y - 9.0f }, icon_color, 2.4f );
			}
			else if ( icon == status_icon::warning ) {
				renderer.line( { center.x, center.y - 10.0f }, { center.x, center.y + 4.0f }, icon_color, 2.0f );
				renderer.filled_circle( { center.x, center.y + 11.0f }, 1.5f, icon_color );
			}
			else {
				renderer.line( { center.x - 8.0f, center.y - 8.0f }, { center.x + 8.0f, center.y + 8.0f }, icon_color, 2.0f );
				renderer.line( { center.x + 8.0f, center.y - 8.0f }, { center.x - 8.0f, center.y + 8.0f }, icon_color, 2.0f );
			}

			renderer.text(
				title,
				{ panel.x + 100.0f, center.y + 38.0f, panel.width - 200.0f, 36.0f },
				22.0f, faded( color_t::from_rgba( 238, 243, 249 ), opacity ), text_align_t::center,
				fonts::poppins, DWRITE_FONT_WEIGHT_SEMI_BOLD
			);
			renderer.text(
				description,
				{ panel.x + 100.0f, center.y + 66.0f, panel.width - 200.0f, 44.0f },
				14.0f, faded( color_t::from_rgba( 145, 158, 173 ), opacity ), text_align_t::center,
				fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
			);

			if ( action.empty( ) )
				return false;
			const rect_t button{ center.x - 82.0f, center.y + 122.0f, 164.0f, 32.0f };
			const auto hovered = contains( cursor, button );
			renderer.filled_rounded_rectangle(
				button, 16.0f,
				faded(
					hovered ? color_t::from_rgba( 28, 151, 235 ) : color_t::from_rgba( 8, 130, 217 ),
					opacity
				)
			);
			renderer.rounded_rectangle(
				{ button.x + 0.5f, button.y + 0.5f, button.width - 1.0f, button.height - 1.0f },
				15.5f, faded( color_t::from_rgba( 14, 81, 149 ), opacity ), 1.0f
			);
			renderer.text(
				action, button, 13.0f, faded( color_t::from_rgba( 255, 255, 255 ), opacity ),
				text_align_t::center, fonts::poppins, DWRITE_FONT_WEIGHT_LIGHT
			);
			return hovered && mouse_pressed;
		}

		std::atomic_bool m_action_running = false;
		dashboard_section m_section = dashboard_section::setup;
		bool m_content_transitioning = false;
		std::chrono::steady_clock::time_point m_content_transition_started{ };
		bool m_scan_continue_pressed = false;
		std::chrono::steady_clock::time_point m_scan_continue_started{ };
		bool m_completion_started_set = false;
		std::chrono::steady_clock::time_point m_completion_started{ };
		bool m_results_transitioning = false;
		std::chrono::steady_clock::time_point m_results_transition_started{ };
	};
}
