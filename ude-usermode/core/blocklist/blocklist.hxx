#pragma once

#include <Windows.h>
#include <urlmon.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment( lib, "urlmon.lib" )

namespace blocklist {
	constexpr auto microsoft_blocklist_url = L"https://aka.ms/VulnerableDriverBlockList";

	enum class rule_kind { direct_deny, denied_signer_file_attribute, denied_signer };

	struct rule_t {
		rule_kind kind = rule_kind::direct_deny;
		std::string id;
		std::string signer_id;
		std::string friendly_name;
		std::string hash;
		std::string file_name;
		std::string internal_name;
		std::string product_name;
		std::string file_description;
		std::string minimum_file_version;
		std::string maximum_file_version;
	};

	struct policy_t {
		std::string version;
		std::vector< rule_t > rules;
		size_t direct_deny_count = 0;
		size_t signer_file_attribute_count = 0;
		size_t denied_signer_count = 0;
	};

	inline policy_t g_policy;

	namespace detail {
		inline std::string attribute( std::string_view tag, std::string_view name ) {
			std::string needle( name );
			needle += "=\"";
			auto position = tag.find( needle );
			if ( position == std::string_view::npos ) return { };
			position += needle.size( );
			const auto end = tag.find( '"', position );
			return end == std::string_view::npos ? std::string{ } :
				std::string( tag.substr( position, end - position ) );
		}

		inline rule_t parse_file_rule( std::string_view tag, rule_kind kind ) {
			rule_t rule;
			rule.kind = kind;
			rule.id = attribute( tag, "ID" );
			rule.friendly_name = attribute( tag, "FriendlyName" );
			rule.hash = attribute( tag, "Hash" );
			rule.file_name = attribute( tag, "FileName" );
			rule.internal_name = attribute( tag, "InternalName" );
			rule.product_name = attribute( tag, "ProductName" );
			rule.file_description = attribute( tag, "FileDescription" );
			rule.minimum_file_version = attribute( tag, "MinimumFileVersion" );
			rule.maximum_file_version = attribute( tag, "MaximumFileVersion" );
			return rule;
		}

		inline std::vector< std::string_view > tags( const std::string& xml, std::string_view opening ) {
			std::vector< std::string_view > result;
			auto position = std::string::size_type{ 0 };
			while ( ( position = xml.find( opening, position ) ) != std::string::npos ) {
				const auto end = xml.find( '>', position + opening.size( ) );
				if ( end == std::string::npos ) break;
				result.emplace_back( xml.data( ) + position, end - position + 1 );
				position = end + 1;
			}
			return result;
		}

		inline bool extract_policy_xml( const std::filesystem::path& archive, const std::filesystem::path& destination ) {
			wchar_t windows_directory[ MAX_PATH ]{ };
			if ( !GetWindowsDirectoryW( windows_directory, MAX_PATH ) ) return false;
			const auto tar = std::filesystem::path( windows_directory ) / L"System32" / L"tar.exe";
			if ( !std::filesystem::exists( tar ) ) return false;
			std::wstring command = L"\"" + tar.wstring( ) + L"\" -xf \"" + archive.wstring( ) +
				L"\" -C \"" + destination.wstring( ) +
				L"\" VulnerableDriverBlockList/DriverPolicy_Enforced.xml";
			STARTUPINFOW startup{ };
			startup.cb = sizeof( startup );
			PROCESS_INFORMATION process{ };
			if ( !CreateProcessW( nullptr, command.data( ), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
				nullptr, nullptr, &startup, &process ) ) return false;
			const auto wait = WaitForSingleObject( process.hProcess, 30000 );
			DWORD exit_code = ERROR_GEN_FAILURE;
			GetExitCodeProcess( process.hProcess, &exit_code );
			CloseHandle( process.hThread );
			CloseHandle( process.hProcess );
			const auto extracted = destination / L"VulnerableDriverBlockList" / L"DriverPolicy_Enforced.xml";
			return wait == WAIT_OBJECT_0 && std::filesystem::exists( extracted );
		}

		inline bool parse_policy( const std::filesystem::path& path, policy_t& policy ) {
			std::ifstream stream( path, std::ios::binary );
			if ( !stream ) return false;
			std::string xml{ std::istreambuf_iterator< char >( stream ), std::istreambuf_iterator< char >( ) };
			if ( xml.find( "<SiPolicy" ) == std::string::npos || xml.find( "<FileRules>" ) == std::string::npos ) return false;
			policy = { };
			const auto version_begin = xml.find( "<VersionEx>" );
			if ( version_begin != std::string::npos ) {
				const auto value_begin = version_begin + sizeof( "<VersionEx>" ) - 1;
				const auto value_end = xml.find( "</VersionEx>", value_begin );
				if ( value_end != std::string::npos ) policy.version = xml.substr( value_begin, value_end - value_begin );
			}

			for ( const auto tag : tags( xml, "<Deny " ) ) {
				auto rule = parse_file_rule( tag, rule_kind::direct_deny );
				if ( rule.id.empty( ) ) continue;
				policy.rules.push_back( std::move( rule ) );
				++policy.direct_deny_count;
			}

			std::unordered_map< std::string, rule_t > file_attributes;
			for ( const auto tag : tags( xml, "<FileAttrib " ) ) {
				auto rule = parse_file_rule( tag, rule_kind::denied_signer_file_attribute );
				if ( !rule.id.empty( ) ) file_attributes.emplace( rule.id, std::move( rule ) );
			}

			std::unordered_set< std::string > denied_signers;
			for ( const auto tag : tags( xml, "<DeniedSigner " ) ) {
				auto signer_id = attribute( tag, "SignerId" );
				if ( !signer_id.empty( ) ) denied_signers.insert( std::move( signer_id ) );
			}

			auto signer_position = std::string::size_type{ 0 };
			while ( ( signer_position = xml.find( "<Signer ", signer_position ) ) != std::string::npos ) {
				const auto opening_end = xml.find( '>', signer_position );
				const auto closing = xml.find( "</Signer>", opening_end );
				if ( opening_end == std::string::npos || closing == std::string::npos ) break;
				const std::string_view opening_tag( xml.data( ) + signer_position, opening_end - signer_position + 1 );
				const auto signer_id = attribute( opening_tag, "ID" );
				if ( denied_signers.contains( signer_id ) ) {
					const std::string signer_block = xml.substr( signer_position, closing + sizeof( "</Signer>" ) - 1 - signer_position );
					auto referenced_attribute = false;
					for ( const auto reference : tags( signer_block, "<FileAttribRef " ) ) {
						const auto found = file_attributes.find( attribute( reference, "RuleID" ) );
						if ( found == file_attributes.end( ) ) continue;
						auto rule = found->second;
						rule.signer_id = signer_id;
						policy.rules.push_back( std::move( rule ) );
						++policy.signer_file_attribute_count;
						referenced_attribute = true;
					}
					if ( !referenced_attribute ) {
						rule_t rule;
						rule.kind = rule_kind::denied_signer;
						rule.signer_id = signer_id;
						rule.friendly_name = attribute( opening_tag, "Name" );
						policy.rules.push_back( std::move( rule ) );
					}
				}
				signer_position = closing + sizeof( "</Signer>" ) - 1;
			}
			policy.denied_signer_count = denied_signers.size( );
			return policy.direct_deny_count != 0 && policy.denied_signer_count != 0;
		}
	}

	inline bool download_and_parse( policy_t& policy, std::string* error = nullptr ) {
		auto fail = [ & ]( const char* message ) { if ( error ) *error = message; return false; };
		wchar_t temporary_path[ MAX_PATH ]{ };
		if ( !GetTempPathW( MAX_PATH, temporary_path ) ) return fail( "failed to locate the temporary directory" );
		const auto root = std::filesystem::path( temporary_path ) / L"ude-driver-blocklist";
		const auto archive = root / L"VulnerableDriverBlockList.zip";
		const auto xml = root / L"VulnerableDriverBlockList" / L"DriverPolicy_Enforced.xml";
		std::error_code filesystem_error;
		std::filesystem::remove_all( root, filesystem_error );
		filesystem_error.clear( );
		if ( !std::filesystem::create_directories( root, filesystem_error ) && filesystem_error )
			return fail( "failed to create the blocklist temporary directory" );
		if ( FAILED( URLDownloadToFileW( nullptr, microsoft_blocklist_url, archive.c_str( ), 0, nullptr ) ) ) {
			std::filesystem::remove_all( root, filesystem_error );
			return fail( "failed to download Microsoft's vulnerable-driver blocklist" );
		}
		if ( !detail::extract_policy_xml( archive, root ) ) {
			std::filesystem::remove_all( root, filesystem_error );
			return fail( "failed to extract Microsoft's vulnerable-driver policy XML" );
		}
		if ( !detail::parse_policy( xml, policy ) ) {
			std::filesystem::remove_all( root, filesystem_error );
			return fail( "Microsoft's vulnerable-driver policy XML was invalid" );
		}
		std::filesystem::remove_all( root, filesystem_error );
		return true;
	}
}
