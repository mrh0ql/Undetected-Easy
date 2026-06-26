#pragma once

namespace signatures {
	struct pph_signature_t {
		unsigned long long m_target;
	};

	struct mov_branch_signature_t {
		const char* m_type;
		unsigned long long m_target;
		unsigned long m_size;
	};

	struct push_ret_signature_t {
		const char* m_type;
		unsigned long long m_target;
		unsigned long m_size;
	};

	struct rip_indirect_branch_signature_t {
		const char* m_type;
		LONG m_displacement;
		unsigned long m_size;
	};

	struct relative_branch_signature_t {
		const char* m_type;
		unsigned long long m_target;
		unsigned long m_size;
	};

	struct rip_register_branch_signature_t {
		const char* m_type;
		LONG m_displacement;
		unsigned long m_size;
		bool m_dereference;
	};

	bool decode_mov_imm64_register( const unsigned char* bytes, unsigned long size, unsigned long offset, unsigned long* register_index, unsigned long long* immediate, unsigned long* instruction_size ) {
		if ( !bytes || !register_index || !immediate || !instruction_size || offset + 10 > size )
			return false;

		if ( bytes[ offset ] != 0x48 && bytes[ offset ] != 0x49 )
			return false;

		if ( bytes[ offset + 1 ] < 0xb8 || bytes[ offset + 1 ] > 0xbf )
			return false;

		memcpy( immediate, bytes + offset + 2, sizeof( *immediate ) );

		*register_index = ( bytes[ offset + 1 ] - 0xb8 ) + ( bytes[ offset ] == 0x49 ? 8 : 0 );
		*instruction_size = 10;
		return true;
	}

	bool match_memory_branch_register( const unsigned char* bytes, unsigned long size, unsigned long offset, unsigned long register_index, bool* is_call, unsigned long* instruction_size ) {
		if ( !bytes || !is_call || !instruction_size || register_index > 15 || offset >= size )
			return false;

		auto register_low = register_index & 7;
		auto register_high = ( register_index & 8 ) != 0;
		auto cursor = offset;

		if ( register_high ) {
			if ( cursor >= size || bytes[ cursor ] != 0x41 )
				return false;

			cursor++;
		}

		if ( cursor >= size || bytes[ cursor ] != 0xff )
			return false;

		cursor++;

		if ( register_low == 4 ) {
			if ( cursor + 2 > size )
				return false;

			if ( bytes[ cursor ] == 0x24 && bytes[ cursor + 1 ] == 0x24 ) {
				*is_call = false;
				*instruction_size = cursor + 2 - offset;
				return true;
			}

			if ( bytes[ cursor ] == 0x14 && bytes[ cursor + 1 ] == 0x24 ) {
				*is_call = true;
				*instruction_size = cursor + 2 - offset;
				return true;
			}

			return false;
		}

		if ( register_low == 5 ) {
			if ( cursor + 2 > size || bytes[ cursor + 1 ] != 0x00 )
				return false;

			if ( bytes[ cursor ] == 0x65 ) {
				*is_call = false;
				*instruction_size = cursor + 2 - offset;
				return true;
			}

			if ( bytes[ cursor ] == 0x55 ) {
				*is_call = true;
				*instruction_size = cursor + 2 - offset;
				return true;
			}

			return false;
		}

		if ( cursor >= size )
			return false;

		if ( bytes[ cursor ] == 0x20 + register_low ) {
			*is_call = false;
			*instruction_size = cursor + 1 - offset;
			return true;
		}

		if ( bytes[ cursor ] == 0x10 + register_low ) {
			*is_call = true;
			*instruction_size = cursor + 1 - offset;
			return true;
		}

		return false;
	}

	bool is_pph_signature_shape( const unsigned char* bytes, unsigned long size, unsigned long offset ) {
		if ( !bytes || offset + 14 > size )
			return false;

		return bytes[ offset ] == 0xff &&
			bytes[ offset + 1 ] == 0x25 &&
			bytes[ offset + 2 ] == 0x00 &&
			bytes[ offset + 3 ] == 0x00 &&
			bytes[ offset + 4 ] == 0x00 &&
			bytes[ offset + 5 ] == 0x00;
	}

	bool match_pph_signature( const unsigned char* live_bytes, unsigned long size, unsigned long offset, pph_signature_t* signature ) {
		if ( !signature || !is_pph_signature_shape( live_bytes, size, offset ) )
			return false;

		memset( signature, 0, sizeof( *signature ) );
		memcpy( &signature->m_target, live_bytes + offset + 6, sizeof( signature->m_target ) );
		return true;
	}

	bool match_mov_branch_signature( const unsigned char* bytes, unsigned long size, unsigned long offset, mov_branch_signature_t* signature ) {
		if ( !bytes || !signature || offset >= size )
			return false;

		memset( signature, 0, sizeof( *signature ) );

		unsigned long register_index = 0;
		unsigned long long immediate = 0;
		unsigned long mov_size = 0;
		if ( decode_mov_imm64_register( bytes, size, offset, &register_index, &immediate, &mov_size ) ) {
			bool is_call = false;
			unsigned long branch_size = 0;
			if ( match_memory_branch_register( bytes, size, offset + mov_size, register_index, &is_call, &branch_size ) ) {
				signature->m_type = is_call ? "mov_reg_imm64_call_mem_reg" : "mov_reg_imm64_jmp_mem_reg";
				signature->m_target = immediate;
				signature->m_size = mov_size + branch_size;
				return true;
			}
		}

		if ( offset + 12 <= size && bytes[ offset ] == 0x48 && bytes[ offset + 1 ] >= 0xb8 && bytes[ offset + 1 ] <= 0xbf ) {
			unsigned long long immediate = 0;
			memcpy( &immediate, bytes + offset + 2, sizeof( immediate ) );

			auto register_index = bytes[ offset + 1 ] - 0xb8;
			auto branch_opcode = bytes[ offset + 11 ];

			if ( bytes[ offset + 10 ] == 0xff && ( branch_opcode == 0xe0 + register_index || branch_opcode == 0xd0 + register_index ) ) {
				signature->m_type = branch_opcode == 0xe0 + register_index ? "mov_reg_imm64_jmp_reg" : "mov_reg_imm64_call_reg";
				signature->m_target = immediate;
				signature->m_size = 12;
				return true;
			}
		}

		if ( offset + 13 <= size && bytes[ offset ] == 0x49 && bytes[ offset + 1 ] >= 0xb8 && bytes[ offset + 1 ] <= 0xbf && bytes[ offset + 10 ] == 0x41 && bytes[ offset + 11 ] == 0xff ) {
			unsigned long long immediate = 0;
			memcpy( &immediate, bytes + offset + 2, sizeof( immediate ) );

			auto register_index = bytes[ offset + 1 ] - 0xb8;
			auto branch_opcode = bytes[ offset + 12 ];

			if ( branch_opcode == 0xe0 + register_index || branch_opcode == 0xd0 + register_index ) {
				signature->m_type = branch_opcode == 0xe0 + register_index ? "mov_reg_imm64_jmp_reg" : "mov_reg_imm64_call_reg";
				signature->m_target = immediate;
				signature->m_size = 13;
				return true;
			}
		}

		return false;
	}

	bool match_push_ret_signature( const unsigned char* bytes, unsigned long size, unsigned long offset, push_ret_signature_t* signature ) {
		if ( !bytes || !signature || offset >= size )
			return false;

		memset( signature, 0, sizeof( *signature ) );

		if ( bytes[ offset ] == 0x68 && offset + 6 <= size && bytes[ offset + 5 ] == 0xc3 ) {
			unsigned long immediate = 0;
			memcpy( &immediate, bytes + offset + 1, sizeof( immediate ) );

			signature->m_type = "push_imm32_ret";
			signature->m_target = static_cast< unsigned long long >( static_cast< LONG >( immediate ) );
			signature->m_size = 6;
			return memory::is_canonical_kernel_address( signature->m_target );
		}

		if ( bytes[ offset ] == 0x68 && offset + 14 <= size && bytes[ offset + 5 ] == 0xc7 && bytes[ offset + 6 ] == 0x44 && bytes[ offset + 7 ] == 0x24 && bytes[ offset + 8 ] == 0x04 && bytes[ offset + 13 ] == 0xc3 ) {
			unsigned long low = 0;
			unsigned long high = 0;
			memcpy( &low, bytes + offset + 1, sizeof( low ) );
			memcpy( &high, bytes + offset + 9, sizeof( high ) );

			signature->m_type = "push_imm64_split_ret";
			signature->m_target = ( static_cast< unsigned long long >( high ) << 32 ) | low;
			signature->m_size = 14;
			return true;
		}

		if ( offset + 12 <= size && bytes[ offset ] == 0x48 && bytes[ offset + 1 ] >= 0xb8 && bytes[ offset + 1 ] <= 0xbf ) {
			unsigned long long immediate = 0;
			memcpy( &immediate, bytes + offset + 2, sizeof( immediate ) );

			auto register_index = bytes[ offset + 1 ] - 0xb8;
			if ( bytes[ offset + 10 ] == 0x50 + register_index && bytes[ offset + 11 ] == 0xc3 ) {
				signature->m_type = "mov_reg_imm64_push_reg_ret";
				signature->m_target = immediate;
				signature->m_size = 12;
				return true;
			}
		}

		if ( offset + 13 <= size && bytes[ offset ] == 0x49 && bytes[ offset + 1 ] >= 0xb8 && bytes[ offset + 1 ] <= 0xbf ) {
			unsigned long long immediate = 0;
			memcpy( &immediate, bytes + offset + 2, sizeof( immediate ) );

			auto register_index = bytes[ offset + 1 ] - 0xb8;
			if ( bytes[ offset + 10 ] == 0x41 && bytes[ offset + 11 ] == 0x50 + register_index && bytes[ offset + 12 ] == 0xc3 ) {
				signature->m_type = "mov_reg_imm64_push_reg_ret";
				signature->m_target = immediate;
				signature->m_size = 13;
				return true;
			}
		}

		unsigned long register_index = 0;
		unsigned long long immediate = 0;
		unsigned long mov_size = 0;
		if ( offset + 15 <= size && decode_mov_imm64_register( bytes, size, offset, &register_index, &immediate, &mov_size ) ) {
			auto register_low = register_index & 7;
			auto register_high = ( register_index & 8 ) != 0;
			auto stack_rex = static_cast< unsigned char >( 0x48 | ( register_high ? 0x04 : 0x00 ) );
			auto stack_modrm = static_cast< unsigned char >( 0x04 | ( register_low << 3 ) );

			if ( bytes[ offset + mov_size ] == stack_rex && bytes[ offset + mov_size + 1 ] == 0x89 && bytes[ offset + mov_size + 2 ] == stack_modrm && bytes[ offset + mov_size + 3 ] == 0x24 && bytes[ offset + mov_size + 4 ] == 0xc3 ) {
				signature->m_type = "mov_reg_imm64_write_rsp_ret";
				signature->m_target = immediate;
				signature->m_size = mov_size + 5;
				return true;
			}

			if ( bytes[ offset + mov_size ] == stack_rex && bytes[ offset + mov_size + 1 ] == 0x87 && bytes[ offset + mov_size + 2 ] == stack_modrm && bytes[ offset + mov_size + 3 ] == 0x24 && bytes[ offset + mov_size + 4 ] == 0xc3 ) {
				signature->m_type = "mov_reg_imm64_xchg_rsp_ret";
				signature->m_target = immediate;
				signature->m_size = mov_size + 5;
				return true;
			}
		}

		if ( offset + 13 <= size && bytes[ offset ] == 0x48 && bytes[ offset + 1 ] == 0x83 && bytes[ offset + 2 ] == 0xec && bytes[ offset + 3 ] == 0x08 ) {
			if ( bytes[ offset + 4 ] == 0x48 && bytes[ offset + 5 ] == 0xc7 && bytes[ offset + 6 ] == 0x04 && bytes[ offset + 7 ] == 0x24 && bytes[ offset + 12 ] == 0xc3 ) {
				unsigned long immediate32 = 0;
				memcpy( &immediate32, bytes + offset + 8, sizeof( immediate32 ) );

				signature->m_type = "sub_rsp_mov_qword_rsp_imm32_ret";
				signature->m_target = static_cast< unsigned long long >( static_cast< LONG >( immediate32 ) );
				signature->m_size = 13;
				return memory::is_canonical_kernel_address( signature->m_target );
			}

			unsigned long stack_register_index = 0;
			unsigned long long stack_immediate = 0;
			unsigned long stack_mov_size = 0;
			if ( offset + 19 <= size && decode_mov_imm64_register( bytes, size, offset + 4, &stack_register_index, &stack_immediate, &stack_mov_size ) ) {
				auto register_low = stack_register_index & 7;
				auto register_high = ( stack_register_index & 8 ) != 0;
				auto stack_rex = static_cast< unsigned char >( 0x48 | ( register_high ? 0x04 : 0x00 ) );
				auto stack_modrm = static_cast< unsigned char >( 0x04 | ( register_low << 3 ) );
				auto store_offset = offset + 4 + stack_mov_size;

				if ( bytes[ store_offset ] == stack_rex && bytes[ store_offset + 1 ] == 0x89 && bytes[ store_offset + 2 ] == stack_modrm && bytes[ store_offset + 3 ] == 0x24 && bytes[ store_offset + 4 ] == 0xc3 ) {
					signature->m_type = "sub_rsp_mov_reg_imm64_write_rsp_ret";
					signature->m_target = stack_immediate;
					signature->m_size = 4 + stack_mov_size + 5;
					return true;
				}
			}
		}

		return false;
	}

	bool match_rip_register_branch_signature( const unsigned char* bytes, unsigned long size, unsigned long offset, rip_register_branch_signature_t* signature ) {
		if ( !bytes || !signature || offset + 9 > size )
			return false;

		memset( signature, 0, sizeof( *signature ) );

		auto rex = bytes[ offset ];
		if ( rex != 0x48 && rex != 0x4c )
			return false;

		if ( bytes[ offset + 1 ] != 0x8d && bytes[ offset + 1 ] != 0x8b )
			return false;

		auto modrm = bytes[ offset + 2 ];
		if ( ( modrm & 0xc7 ) != 0x05 )
			return false;

		auto register_index = static_cast< unsigned long >( ( modrm >> 3 ) & 7 ) + ( rex == 0x4c ? 8 : 0 );
		auto register_low = register_index & 7;
		auto register_high = ( register_index & 8 ) != 0;
		auto branch_offset = offset + 7;

		if ( register_high ) {
			if ( offset + 10 > size || bytes[ branch_offset ] != 0x41 || bytes[ branch_offset + 1 ] != 0xff )
				return false;

			auto branch_opcode = bytes[ branch_offset + 2 ];
			if ( branch_opcode != 0xe0 + register_low && branch_opcode != 0xd0 + register_low )
				return false;

			signature->m_size = 10;
			signature->m_type = branch_opcode == 0xe0 + register_low ?
				( bytes[ offset + 1 ] == 0x8d ? "lea_rip_jmp_reg" : "mov_rip_jmp_reg" ) :
				( bytes[ offset + 1 ] == 0x8d ? "lea_rip_call_reg" : "mov_rip_call_reg" );
		}
		else {
			if ( bytes[ branch_offset ] != 0xff )
				return false;

			auto branch_opcode = bytes[ branch_offset + 1 ];
			if ( branch_opcode != 0xe0 + register_low && branch_opcode != 0xd0 + register_low )
				return false;

			signature->m_size = 9;
			signature->m_type = branch_opcode == 0xe0 + register_low ?
				( bytes[ offset + 1 ] == 0x8d ? "lea_rip_jmp_reg" : "mov_rip_jmp_reg" ) :
				( bytes[ offset + 1 ] == 0x8d ? "lea_rip_call_reg" : "mov_rip_call_reg" );
		}

		unsigned long displacement = 0;
		memcpy( &displacement, bytes + offset + 3, sizeof( displacement ) );

		signature->m_displacement = static_cast< LONG >( displacement );
		signature->m_dereference = bytes[ offset + 1 ] == 0x8b;
		return true;
	}

	bool match_rip_indirect_branch_signature( const unsigned char* bytes, unsigned long size, unsigned long offset, rip_indirect_branch_signature_t* signature ) {
		if ( !bytes || !signature || offset + 6 > size || bytes[ offset ] != 0xff )
			return false;

		memset( signature, 0, sizeof( *signature ) );

		if ( bytes[ offset + 1 ] != 0x25 && bytes[ offset + 1 ] != 0x15 )
			return false;

		unsigned long displacement = 0;
		memcpy( &displacement, bytes + offset + 2, sizeof( displacement ) );

		signature->m_type = bytes[ offset + 1 ] == 0x25 ? "jmp_rip_indirect" : "call_rip_indirect";
		signature->m_displacement = static_cast< LONG >( displacement );
		signature->m_size = 6;
		return true;
	}

	bool match_relative_branch_signature( const unsigned char* bytes, unsigned long size, unsigned long offset, unsigned long long instruction_address, relative_branch_signature_t* signature ) {
		if ( !bytes || !signature || offset >= size )
			return false;

		memset( signature, 0, sizeof( *signature ) );

		if ( ( bytes[ offset ] == 0xe9 || bytes[ offset ] == 0xe8 ) && offset + 5 <= size ) {
			unsigned long displacement = 0;
			memcpy( &displacement, bytes + offset + 1, sizeof( displacement ) );

			signature->m_type = bytes[ offset ] == 0xe9 ? "jmp_rel32" : "call_rel32";
			signature->m_target = instruction_address + 5 + static_cast< LONG >( displacement );
			signature->m_size = 5;
			return memory::is_canonical_kernel_address( signature->m_target );
		}

		if ( bytes[ offset ] == 0xeb && offset + 2 <= size ) {
			auto displacement = static_cast< char >( bytes[ offset + 1 ] );
			signature->m_type = "jmp_rel8";
			signature->m_target = instruction_address + 2 + displacement;
			signature->m_size = 2;
			return memory::is_canonical_kernel_address( signature->m_target );
		}

		return false;
	}

}
