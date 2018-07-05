#pragma once

#include <ipxe/interface.h>
#include <ipxe/sha1.h>

#include "bittorrent.h"

#define PROTO_NAME "BitTorrent protocol"
#define PROTO_NAME_LEN ( sizeof ( PROTO_NAME ) - 1 )

#define BTTYPE( F )                                                            \
	F ( CHOKE )                                                            \
	F ( UNCHOKE )                                                          \
	F ( INTERESTED )                                                       \
	F ( NOT_INTERESTED )                                                   \
	F ( HAVE )                                                             \
	F ( BITFIELD )                                                         \
	F ( REQUEST )                                                          \
	F ( PIECE )                                                            \
	F ( CANCEL )                                                           \
	F ( PORT )                                                             \
	F ( INVALID )

#define BTTYPE_ENUM( N ) BTTYPE_##N,

enum bttype { BTTYPE ( BTTYPE_ENUM ) };

#undef BTTYPE_ENUM

struct bthandshake {
	unsigned char plen;
	char pstr[ PROTO_NAME_LEN ];
	unsigned char reserved[ 8 ];
	uint8_t info_hash[ SHA1_DIGEST_SIZE ];
	char peer_id[ PEERID_SIZE ];
} __attribute__ ( ( packed ) );

struct btheader {
	uint32_t size;
	unsigned char type;
} __attribute__ ( ( packed ) );

#define BTHEADER( Size, Type )			\
	( struct btheader ) {			\
		.size = htonl ( ( Size ) - 4 ),	\
		.type = ( Type ),		\
	}

#define BTSIMPLE( Type ) BTHEADER ( sizeof ( struct btheader ), Type )

struct btrequest {
	struct btheader header;
	uint32_t index;
	uint32_t begin;
	uint32_t length;
} __attribute__ ( ( packed ) );

#define BTREQUEST( Index, Begin, Length )                                      \
	( struct btrequest ) {                                                 \
		.header = BTHEADER ( sizeof ( struct btrequest ),              \
				     BTTYPE_REQUEST ),                         \
		.index = htonl ( Index ), .begin = htonl ( Begin ),            \
		.length = htonl ( Length ),                                    \
	}

struct bthave {
	struct btheader header;
	uint32_t have_id;
} __attribute__ ( ( packed ) );

#define BTHAVE( Id )						\
	( struct bthave ) {					\
		.header = BTHEADER ( sizeof ( struct bthave ),	\
				     BTTYPE_HAVE ),		\
		.have_id = htonl ( Id ),			\
	}

struct btpiece {
	struct btheader header;
	uint32_t index;
	uint32_t begin;
} __attribute__ ( ( packed ) );
