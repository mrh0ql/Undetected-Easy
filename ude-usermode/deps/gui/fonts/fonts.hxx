#pragma once

#include <dwrite_3.h>
#include <wrl/client.h>

namespace fonts {
	inline constexpr auto awesome = L"Font Awesome 7 Free Solid";
	inline constexpr auto icomoon = L"icomoon";
	inline constexpr auto manrope = L"Manrope";
	inline constexpr auto poppins = L"Poppins";
	inline constexpr auto bold = L"Manrope";
	inline constexpr auto medium = L"Cooper Md BT";
	inline constexpr auto bold_medium = L"Cooper Black BT";

	class c_font_collection {
	public:
		bool initialize( IDWriteFactory* factory );
		void shutdown( );

		IDWriteFontCollection* get( ) const { return m_collection.Get( ); }

	private:
		Microsoft::WRL::ComPtr< IDWriteFontCollection1 > m_collection;
	};
}
