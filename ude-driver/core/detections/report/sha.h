struct sha1_digest_t {
	unsigned char m_bytes[ 20 ];
};

class c_sha1 {
public:
	c_sha1( ) {
		reset( );
	}

	void reset( ) {
		m_state[ 0 ] = 0x67452301ul;
		m_state[ 1 ] = 0xefcdab89ul;
		m_state[ 2 ] = 0x98badcfeul;
		m_state[ 3 ] = 0x10325476ul;
		m_state[ 4 ] = 0xc3d2e1f0ul;
		m_count = 0;
		memset( m_buffer, 0, sizeof( m_buffer ) );
	}

	void update( const void* data, size_t length ) {
		auto input = static_cast< const unsigned char* >( data );
		auto index = static_cast< size_t >( ( m_count >> 3 ) & 63 );
		m_count += static_cast< unsigned long long >( length ) << 3;

		auto part_length = 64 - index;
		size_t offset = 0;

		if ( length >= part_length ) {
			memcpy( &m_buffer[ index ], input, part_length );
			transform( m_buffer );

			for ( offset = part_length; offset + 63 < length; offset += 64 )
				transform( &input[ offset ] );

			index = 0;
		}

		if ( offset < length )
			memcpy( &m_buffer[ index ], &input[ offset ], length - offset );
	}

	sha1_digest_t final( ) {
		static const unsigned char padding[ 64 ] = { 0x80 };
		unsigned char bits[ 8 ]{ };

		for ( auto index = 0; index < 8; index++ )
			bits[ 7 - index ] = static_cast< unsigned char >( ( m_count >> ( index * 8 ) ) & 0xff );

		auto index = static_cast< size_t >( ( m_count >> 3 ) & 63 );
		auto pad_length = index < 56 ? 56 - index : 120 - index;

		update( padding, pad_length );
		update( bits, sizeof( bits ) );

		sha1_digest_t digest{ };
		for ( auto state_index = 0; state_index < 5; state_index++ ) {
			digest.m_bytes[ state_index * 4 + 0 ] = static_cast< unsigned char >( ( m_state[ state_index ] >> 24 ) & 0xff );
			digest.m_bytes[ state_index * 4 + 1 ] = static_cast< unsigned char >( ( m_state[ state_index ] >> 16 ) & 0xff );
			digest.m_bytes[ state_index * 4 + 2 ] = static_cast< unsigned char >( ( m_state[ state_index ] >> 8 ) & 0xff );
			digest.m_bytes[ state_index * 4 + 3 ] = static_cast< unsigned char >( m_state[ state_index ] & 0xff );
		}

		return digest;
	}

	static sha1_digest_t hash_buffer( const void* data, size_t length ) {
		c_sha1 context;
		context.update( data, length );
		return context.final( );
	}

private:
	static unsigned long rotate_left( unsigned long value, unsigned long bits ) {
		return ( value << bits ) | ( value >> ( 32 - bits ) );
	}

	void transform( const unsigned char block[ 64 ] ) {
		unsigned long words[ 80 ]{ };

		for ( auto index = 0; index < 16; index++ ) {
			words[ index ] =
				( static_cast< unsigned long >( block[ index * 4 + 0 ] ) << 24 ) |
				( static_cast< unsigned long >( block[ index * 4 + 1 ] ) << 16 ) |
				( static_cast< unsigned long >( block[ index * 4 + 2 ] ) << 8 ) |
				static_cast< unsigned long >( block[ index * 4 + 3 ] );
		}

		for ( auto index = 16; index < 80; index++ )
			words[ index ] = rotate_left( words[ index - 3 ] ^ words[ index - 8 ] ^ words[ index - 14 ] ^ words[ index - 16 ], 1 );

		auto a = m_state[ 0 ];
		auto b = m_state[ 1 ];
		auto c = m_state[ 2 ];
		auto d = m_state[ 3 ];
		auto e = m_state[ 4 ];

		for ( auto index = 0; index < 80; index++ ) {
			unsigned long function = 0;
			unsigned long constant = 0;

			if ( index < 20 ) {
				function = ( b & c ) | ( ( ~b ) & d );
				constant = 0x5a827999ul;
			}
			else if ( index < 40 ) {
				function = b ^ c ^ d;
				constant = 0x6ed9eba1ul;
			}
			else if ( index < 60 ) {
				function = ( b & c ) | ( b & d ) | ( c & d );
				constant = 0x8f1bbcdcul;
			}
			else {
				function = b ^ c ^ d;
				constant = 0xca62c1d6ul;
			}

			auto temporary = rotate_left( a, 5 ) + function + e + constant + words[ index ];
			e = d;
			d = c;
			c = rotate_left( b, 30 );
			b = a;
			a = temporary;
		}

		m_state[ 0 ] += a;
		m_state[ 1 ] += b;
		m_state[ 2 ] += c;
		m_state[ 3 ] += d;
		m_state[ 4 ] += e;
	}

	unsigned long m_state[ 5 ]{ };
	unsigned long long m_count = 0;
	unsigned char m_buffer[ 64 ]{ };
};

bool equal_digest( const sha1_digest_t& left, const sha1_digest_t& right ) {
	return RtlCompareMemory( left.m_bytes, right.m_bytes, sizeof( left.m_bytes ) ) == sizeof( left.m_bytes );
}
