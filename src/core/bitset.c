#include <ipxe/bitset.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

int bitset_init ( struct bitset * bitset, size_t bit_size ) {
	bitset->bit_size = bit_size;

	size_t needed_bytes = bitset_needed_room ( bit_size );
	if ( ( bitset->data = zalloc ( needed_bytes ) ) == NULL )
		return -ENOMEM;

	return 0;
}

size_t bitset_find_diff ( struct bitset * bitset_a,
			  struct bitset * bitset_b ) {
	assert ( bitset_a->bit_size == bitset_b->bit_size );

	const size_t size_t_bits = sizeof ( size_t ) * CHAR_BIT;

	/** Look for differences using size_t chunks first */
	size_t i = 0;
	for ( ; i < bitset_a->bit_size / size_t_bits; i++ ) {
		size_t a_val = ( ( size_t* )bitset_a->data )[i];
		size_t b_val = ( ( size_t* )bitset_b->data )[i];
		if ( a_val != b_val ) {
			int set_i = ffs ( a_val ^ b_val );
			/** ffs returns 0 if no bit is set */
			assert ( set_i );
			set_i = size_t_bits - 1 - ( set_i - 1 );
			return i * size_t_bits + set_i + 1;
		}
	}

	i *= sizeof ( size_t );

	/** Look for differences using size_t chunks first */
	for ( ; i < bitset_needed_room ( bitset_a->bit_size ); i++ ) {
		uint8_t a_val = bitset_a->data[i];
		uint8_t b_val = bitset_b->data[i];
		if ( a_val != b_val ) {
			int set_i = ffs ( a_val ^ b_val );
			assert ( set_i );
			set_i = CHAR_BIT - 1 - ( set_i - 1 );
			return i * CHAR_BIT + set_i + 1;
		}
	}

	return 0;
}

bool bitset_set ( struct bitset * bitset, size_t i, bool value ) {
	assert ( i < bitset->bit_size );

	/* Update the count of set bits */
	int former_state = bitset_get ( bitset, i );
	int delta = ( int )value - former_state;
	bitset->set_count += delta;

	/* Update the bit itself */
	uint8_t bit_i = CHAR_BIT - 1 - ( i % CHAR_BIT );
	uint8_t *bstate = &bitset->data[ i / CHAR_BIT ];
	*bstate = ( *bstate & ~( 1 << bit_i ) ) | !!value << bit_i;
	return delta;
}
