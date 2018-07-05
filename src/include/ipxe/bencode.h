#pragma once

/** @file
 *
 * bencode parser
 *
 * Bencode is the format used by bittorrent to exchange metadata.
 * It's just like json, except there's a byte unique representation
 * for any input tree.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

/** A general purpose buffer */
struct btbuf {
	char * begin;
	char * end;
};

static inline size_t btbuf_size ( struct btbuf * buf ) {
	return buf->end - buf->begin;
}

/** A bencode dictionnary entry */
struct bdict {
	struct bdata * key;
	struct bdata * value;
	struct bdict * next;
};

/** A bencode list entry */
struct blist_node {
	struct bdata * value;
	struct blist_node * next;
};

/** A bencode list container */
struct blist {
	struct blist_node * tail;
	size_t size;
};

/** A bencode integer. These are specified as signed bignums.
 *  Nobody cares, lets use regular integers.
 */
typedef signed long bint_t;
#define BINT_F "%ld"
#define BINT_MAX LONG_MAX

/** A generic bencode node */
struct bdata {
	enum btype {
		BINT,
		BSTR,
		BDICT,
		BLIST,
	} type;

	union {
		bint_t i;
		struct btbuf str;
		struct bdict * dict;
		struct blist list;
	} data;

	/** Range of the original file over which this node spans */
	struct btbuf range;
};


/** Parse some data within a bencode buffer
 *
 *  Data isn't copied into the parsed tree:
 *  btbufs still reffer to the source buffer.
 *
 * @v buf		Buffer to parse from
 * @ret benc		Resulting tree like structure
 */
extern struct bdata *bencode_parse ( const struct btbuf * buf );

/** Frees a bencode tree
 *
 * @v benc		Tree to free
 */
extern void bencode_free ( struct bdata * benc );

/** Prints a json representation of the bencoded data
 *
 * @v benc		Tree to print
 */
extern void bdata_json_print ( const struct bdata * benc );

/** Returns the value matching some string key.
 *
 * @v dict		Dict to search in
 * @v key		Key to look for
 * @ret node		First matching value, or NULL
 */
extern struct bdata * bdict_find ( const struct bdict * dict, char * key );
