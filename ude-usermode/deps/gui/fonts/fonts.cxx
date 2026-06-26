#include "fonts.hxx"
#include <Windows.h>
#include <array>
#include <string>

namespace fonts {
	namespace {
		std::wstring executable_directory( ) {
			wchar_t module_path[ MAX_PATH ]{ };
			auto length = GetModuleFileNameW( nullptr, module_path, MAX_PATH );
			if ( !length || length == MAX_PATH )
				return { };

			std::wstring directory( module_path, length );
			auto separator = directory.find_last_of( L"\\/" );
			if ( separator == std::wstring::npos )
				return { };

			directory.resize( separator + 1 );
			return directory;
		}
	}

	bool c_font_collection::initialize( IDWriteFactory* factory ) {
		if ( !factory || m_collection )
			return false;

		Microsoft::WRL::ComPtr< IDWriteFactory5 > factory5;
		Microsoft::WRL::ComPtr< IDWriteFontSetBuilder1 > builder;
		if ( FAILED( factory->QueryInterface( IID_PPV_ARGS( factory5.GetAddressOf( ) ) ) ) ||
			FAILED( factory5->CreateFontSetBuilder( builder.GetAddressOf( ) ) ) )
			return false;

		const auto directory = executable_directory( ) + L"fonts\\";
		constexpr std::array font_files{
			L"fa-solid-900.otf",
			L"icomoon.ttf",
			L"manrope-semibold.ttf",
			L"poppins-semibold.ttf",
			L"coopermi.ttf",
			L"cooperb.ttf"
		};

		for ( auto file_name : font_files ) {
			Microsoft::WRL::ComPtr< IDWriteFontFile > font_file;
			const auto path = directory + file_name;
			if ( FAILED( factory->CreateFontFileReference( path.c_str( ), nullptr, font_file.GetAddressOf( ) ) ) ||
				FAILED( builder->AddFontFile( font_file.Get( ) ) ) )
				return false;
		}

		Microsoft::WRL::ComPtr< IDWriteFontSet > font_set;
		if ( FAILED( builder->CreateFontSet( font_set.GetAddressOf( ) ) ) ||
			FAILED( factory5->CreateFontCollectionFromFontSet( font_set.Get( ), m_collection.GetAddressOf( ) ) ) ) {
			shutdown( );
			return false;
		}

		return true;
	}

	void c_font_collection::shutdown( ) {
		m_collection.Reset( );
	}
}
