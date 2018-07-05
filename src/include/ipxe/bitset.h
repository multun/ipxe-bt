#pragma once

/** @file
 *
 * A BitTorrent compliant Bitset.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <strings.h>

/**
 * A bitset, built for BitTorrent.
 * This implies indexing bits from an awkward end.
 */
struct bitset {
	/** Count of bits set to one */
	size_t set_count;
	/** Size of the bitset, in bits */
	size_t bit_size;
	/** Size of the bitset, in bits */
	uint8_t * data;
};

/** Computes the byte size of a bitset.
 *
 * @v bit_size		Size of the bitset, in bits
 * @ret byte_size	Size of the bitset, in bytes
 */
static inline __attribute__ (( pure ))
size_t bitset_needed_room ( size_t bit_size ) {
	return ( bit_size + CHAR_BIT - 1 ) / CHAR_BIT;
}

/** Gets the value of the nth bit.
 *
 * @v bitset		Bitset to work on
 * @v i			Index of the bit to look for
 * @ret val		Value of the bit at index i
 */
static inline __unused bool bitset_get ( struct bitset *bitset, size_t i ) {
	assert ( i < bitset->bit_size );
	return bitset->data[ i / CHAR_BIT ] & 0x80 >> ( i % CHAR_BIT );
}

/** Sets the value of the nth bit. Also update the set bits count.
 *
 * @v bitset		Bitset to work on
 * @v i			Index of the bit to set
 * @v value		New value
 * @ret changed		Whether the bit changed
 */
extern bool bitset_set ( struct bitset * bitset, size_t i, bool value );

/** Initialize a bitset.
 *
 * @v bitset		Bitset to work on
 * @v bit_size		Number of bits to initialize for
 * @ret rc		Return status code
 */
extern int bitset_init ( struct bitset * bitset, size_t bit_size );

/** Frees a bitset.
 *
 * @v bitset		Bitset to work on.
 */
static inline void bitset_free ( struct bitset * bitset ) {
	free ( bitset->data );
}

/** Sets all bits to zero.
 *
 * @v bitset		Bitset to work on.
 */
static inline void bitset_clear ( struct bitset * bitset ) {
	bitset->set_count = 0;
	memset ( bitset->data, 0, bitset_needed_room ( bitset->bit_size ) );
}

/** Recompute the number of set bits.
 *
 * @v bitset		Bitset to work on.
 */
static inline void bitset_init_set_count ( struct bitset * bitset ) {
	bitset->set_count = 0;
	for ( size_t i = 0; i < bitset_needed_room ( bitset->bit_size ); i++ ) {
		/** Brian Kernighan's way of counting set bits */
		for ( uint8_t val = bitset->data[ i ]; val != 0;
		      bitset->set_count++ )
			val &= val - 1;
	}
}

/** Finds a difference between two bitsets.
 *
 * @v bitset_a		First bitset to compare
 * @v bitset_b		Second bitset to compare
 * @ret diff_i		Index of the first diff + 1, or 0 if none is found.
 */
size_t bitset_find_diff ( struct bitset * bitset_a,
			  struct bitset * bitset_b );
