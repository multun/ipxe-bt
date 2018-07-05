#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <ipxe/bitset.h>
#include <ipxe/base64.h>
#include <ipxe/bittorrent.h>
#include <ipxe/entropy.h>
#include <ipxe/vsprintf.h>

void torrent_info_free ( struct torrent_info *info ) {
	for (size_t i = 0; i < info->piece_count; i++)
		bitset_free ( &info->pieces[i].block_state );
	free ( info->pieces );

	uri_put ( info->image_uri );
	bencode_free ( info->tree );
	image_put ( info->image );
}

static struct uri *torrent_info_parse_uri ( struct bdata *mi ) {
	struct bdata *announce_bstr;
	struct btbuf *announce_buf;
	char *zstr;
	struct uri *announce_uri;

	if ( !( announce_bstr = bdict_find ( mi->data.dict, "announce" ) ) )
		return NULL;

	announce_buf = &announce_bstr->data.str;

	/** unfortunately, the bencoded string isn't null terminated and the uri
	    parser only accepts these */
	if ( !( zstr = strndup ( announce_buf->begin,
				 announce_buf->end - announce_buf->begin ) ) )
		return NULL;

	if ( !( announce_uri = parse_uri ( zstr ) ) )
		return NULL;

	free ( zstr );

	return announce_uri;
}

static int metadata_init_sha ( struct bdata *mi, uint8_t *out ) {
	struct bdata *info = bdict_find ( mi->data.dict, "info" );
	if ( !info )
		return -EINVAL;

	struct digest_algorithm *const digest = &sha1_algorithm;
	uint8_t ctx[ digest->ctxsize ];

	digest_init ( digest, ctx );
	size_t size = info->range.end - info->range.begin;
	digest_update ( digest, ctx, info->range.begin, size );
	digest_final ( digest, ctx, out );

	return 0;
}

// TODO: fill the array with non ascii chars, which is less annoying
static void random_char_fill ( char *buf, size_t size ) {
	const size_t sample_bits = sizeof ( random() ) * CHAR_BIT;

	/** base64 outputs one char for each 6 bits group */
	size_t sample_count = ( size * 6 + sample_bits - 6 ) / sample_bits;

	/** sample_count should be very small */
	long int random_buf[ sample_count ];

	for ( size_t i = 0; i < sample_count; i++ )
		random_buf[ i ] = random ();

	size_t randbuf_size = sample_count * sizeof ( long int );
	size_t res_len = base64_encoded_len ( randbuf_size );

	// creating an intermediary buffer enables avoiding base64_encode not to
	// output enough characters
	char res_buf[ res_len ];
	base64_encode ( random_buf, randbuf_size, res_buf, res_len );
	strncpy ( buf, res_buf, size );
}

static void metadata_init_peerid ( char *peerid ) {
	const size_t prefix_off = sizeof ( PEERID_PREFIX ) - 1;

	strcat ( peerid, PEERID_PREFIX );
        random_char_fill ( peerid + prefix_off, PEERID_SIZE - prefix_off );

	/** random char fill does not add a terminating null byte */
	peerid[ PEERID_SIZE ] = '\0';
}

static int bdata_read_int ( struct bdata *tree, size_t *res ) {
	if ( !tree || tree->type != BINT || tree->data.i < 0 )
		return -EINVAL;

	*res = tree->data.i;
	return 0;
}

static int torrent_info_parse ( struct bdata *tree,
				struct torrent_info *info ) {
	int rc;

	struct bdata *info_tree = bdict_find ( tree->data.dict, "info" );
	if ( !info_tree || info_tree->type != BDICT ) {
		rc = -EINVAL;
		goto err_parsing;
	}

        /** Length is the total file size */
	if ( ( rc = bdata_read_int (
		   bdict_find ( info_tree->data.dict, "length" ),
		   &info->total_length ) ) != 0 ) {
		rc = -EINVAL;
		goto err_parsing;
	}

        /** Piece length is the size of a single piece */
	if ( ( rc = bdata_read_int (
		   bdict_find ( info_tree->data.dict, "piece length" ),
		   &info->piece_length ) ) != 0 ) {
		rc = -EINVAL;
		goto err_parsing;
	}

        /** Find the key containing piece hashes */
	struct bdata *piece_hashes =
	    bdict_find ( info_tree->data.dict, "pieces" );

        /** Pieces are mandatory */
	if ( !piece_hashes || piece_hashes->type != BSTR ) {
		rc = -EINVAL;
		goto err_parsing;
	}

	size_t piece_hashes_size = btbuf_size ( &piece_hashes->data.str );

	/** The number of pieces is calculated from the size of the buffer
	    containing piece hashes */
	if ( !piece_hashes_size ||
	     ( piece_hashes_size % SHA1_DIGEST_SIZE ) != 0 ) {
		rc = -EINVAL;
		goto err_parsing;
	}

	info->piece_count = piece_hashes_size / SHA1_DIGEST_SIZE;

	INIT_LIST_HEAD ( &info->pending_pieces );
	INIT_LIST_HEAD ( &info->busy_pieces );

	/* if we get something else than the exact number of pieces needed to
	 * store the total torrent size, it is an error */
	if ( ( info->total_length + info->piece_length - 1 )
             / info->piece_length != info->piece_count ) {
		rc = -EINVAL;
		goto err_parsing;
	}

	if ( ( info->pieces = calloc ( info->piece_count,
				       sizeof ( struct torrent_piece ) ) )
	      == NULL )
            goto err_pieces_alloc;

	if ( ( rc = bitset_init ( &info->received_pieces,
				  info->piece_count ) ) != 0 )
            goto err_bitset_alloc;

        size_t cur_length = 0;
	/* initialize pieces using the bencoded hash array */
	for ( size_t i = 0; i < info->piece_count; i++ ) {
		size_t length = info->piece_length;
		if ( cur_length + length > info->total_length ) {
			assert ( i == info->piece_count - 1 );
			length = info->total_length - cur_length;
		}

                cur_length += length;

		struct torrent_piece *cur_piece = &info->pieces[ i ];
		cur_piece->id = i;
		cur_piece->length = length;

		list_add_tail ( &cur_piece->list, &info->pending_pieces );

		bitset_init ( &cur_piece->block_state,
			      ( length + BLOCK_SIZE - 1 ) / BLOCK_SIZE );

		char *hash_start =
		    piece_hashes->data.str.begin + SHA1_DIGEST_SIZE * i;
		memcpy ( &cur_piece->hash, hash_start, SHA1_DIGEST_SIZE );
	}

	// TODO: cleanup on error
	return 0;

err_bitset_alloc:
        free ( info->pieces );
err_pieces_alloc:
err_parsing:
        return rc;
}

int torrent_info_init ( struct torrent_info *info, struct uri *uri ) {
	int rc;
	struct image *image;
	if ( !( image = find_image ( uri->host ) ) )
		return -ENOENT;

	info->image_uri = uri_get ( uri );
	info->image = image_get ( image );

	/** TODO: Ensure this is OK */
	char *img_begin = user_to_virt ( image->data, 0 );

	struct btbuf img_buf = {
		.begin = img_begin,
		.end = img_begin + image->len,
	};

	if ( !( info->tree = bencode_parse ( &img_buf ) ) ) {
		rc = -EINVAL;
		goto err_parse;
	}

	if ( info->tree->type != BDICT ) {
		rc = -EINVAL;
		goto err_bdata_type;
	}

	if ( ( rc = torrent_info_parse ( info->tree, info ) ) != 0 )
		goto err_info;

	if ( !( info->announce_uri = torrent_info_parse_uri ( info->tree ) ) ) {
		rc = -EINVAL;
		goto err_announce;
	}

	if ( ( rc = metadata_init_sha ( info->tree, info->info_hash ) ) != 0 )
		goto err_hash;

	metadata_init_peerid ( info->peerid );

	return 0;

// TODO: cleanup
err_hash:
err_info:
err_announce:
err_bdata_type:
err_parse:
	image_put ( info->image );
	uri_put ( uri );
	return rc;
}

static inline size_t torrent_announce_query ( char * buf, size_t buf_size,
					      char * encoded_sha,
					      struct torrent_info * info,
					      const char * event ) {
	size_t left = info->total_length - info->downloaded;
	size_t printed = snprintf ( buf, buf_size,
				    "compact=1"
				    "&peer_id=%s"
				    "&info_hash=%s"
				    "&port=%d"

				    "&left=%zd"
				    "&downloaded=%zd"
				    "&uploaded=%zd",
				    info->peerid, encoded_sha, info->port, left,
				    info->downloaded, info->uploaded );

	/* When there's an event, append it at the end of the URL */
	if ( event != NULL )
		printed += snprintf ( buf ? ( buf + printed ) : buf,
				      buf ? ( buf_size - printed ) : buf_size,
				      "&event=%s", event );

	return printed;
}

static void sha1_hex_format ( uint8_t *source, char *buf ) {
	for ( size_t i = 0; i < SHA1_DIGEST_SIZE; i++ )
		buf += ssnprintf ( buf, /* %XX <NULL> */ 4, "%%%02X",
				   source[ i ] );
}

struct uri *torrent_announce_uri ( struct torrent_info *info,
				   enum torrent_state state ) {
	const char * announce_type_map[] = {
		[TORRENT_STARTING] = "started",
		[TORRENT_RUNNING] = NULL,
		[TORRENT_STOPPING] = "stopped",
	};

	assert ( state <= TORRENT_STOPPING );

	const char * event = announce_type_map[ state ];

	// the info hash has to be uri-encoded
	const size_t encoded_sha_len = SHA1_DIGEST_SIZE * 3 + 1;
	char encoded_sha[ encoded_sha_len ];
	sha1_hex_format ( info->info_hash, encoded_sha );

	// precompute the buffer size
	size_t announce_uri_size =
	    torrent_announce_query ( NULL, 0, encoded_sha, info, event ) + 1;

	// create a buffer on the stack and fill it
	char query[ announce_uri_size ];
	torrent_announce_query ( query, announce_uri_size, encoded_sha, info,
				 event );

	// copy the already first part of the uri, patch it to add the query
	// part and duplicate it
	struct uri new_uri = *info->announce_uri;
	new_uri.query = query;

	// set the escaping flag
	struct uri *res = uri_dup ( &new_uri );
	uri_set_raw ( res, URI_QUERY, true );
	return res;
}
