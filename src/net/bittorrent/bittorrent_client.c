#include <byteswap.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <ipxe/in.h>
#include <ipxe/iobuf.h>
#include <ipxe/open.h>
#include <ipxe/timer.h>
#include <ipxe/tcpip.h>
#include <ipxe/bittorrent.h>
#include <ipxe/bittorrent_client.h>
#include <ipxe/fault.h>

typedef int ( *bt_client_transmitter ) ( struct bt_client *client );
typedef int ( *bt_client_receiver ) ( struct bt_client *client,
				      struct io_buffer *iobuf );

#define TX_QUEUE_SIZE 10
#define TX_CHUNK_SIZE 400

struct bt_client {
	struct torrent_client base_client;

	// the local peer is choked by the remote one
	unsigned int choked : 1;

	// the local peer is choking the remote one
	unsigned int choking : 1;

	// the local peer is interested by the remote one
	unsigned int interested : 1;

	// the local peer is interesting according to the remote one
	unsigned int interesting : 1;

	/** have we already asked for a block */
	unsigned int block_requested : 1;

	/** whether the remote peer thinks it is unchoked */
	unsigned int unchoked_remote : 1;

	/* the bitset of what has already been announced. When this bitset
	   has less set bits than the actual owned pieces bitset, we announce
	   the missing pieces */
	struct bitset announced_pieces;

	struct retry_timer rx_timer;
	struct retry_timer block_rx_timer;

	bt_client_transmitter tx;
	bt_client_receiver rx;

	size_t rx_cursor;
	union {
		struct bthandshake handshake;
		struct btheader header;
		/* the piece shares the received header */
		struct btpiece piece;
		uint32_t have_id;
	} rx_data;

	struct interface peer;

	struct pending_request {
		uint32_t index;
		uint32_t begin;
		uint32_t length;
	}   __attribute__ (( packed )) tx_queue[TX_QUEUE_SIZE];

	size_t tx_cursor;
	size_t pending_requests;
};


#define BTCLIENT_RX_TIMEOUT ( 10 * TICKS_PER_SEC )
#define BTCLIENT_CONN_RX_TIMEOUT ( 10 * TICKS_PER_SEC )
#define BTCLIENT_BLOCK_RX_TIMEOUT ( 10 * TICKS_PER_SEC )

/* maximum blocks to be requested at once */
#define MAX_BLOCKS 3

static void btclient_close ( struct bt_client * client, int rc );
static int btclient_tx ( struct bt_client *client );

/* same as above, but unregisters the client on error */
static void btclient_tx_fatal ( struct bt_client * client ) {
	int rc;
	if ( ( rc = btclient_tx ( client ) ) == 0 )
		return;

	btclient_close ( client, rc );
	torrent_client_unregister ( &client->base_client );
}

static void btclient_reset_rx ( struct bt_client *client );
static void btclient_expect_rx ( struct bt_client *client,
				 bt_client_receiver receiver );

static int btclient_tx_handshake ( struct bt_client *client );
static int btclient_rx_handshake ( struct bt_client *client,
                                   struct io_buffer *io_buf );

static inline bool btclient_handshake_finished( struct bt_client * client ) {
	return client->tx == NULL && client->rx != btclient_rx_handshake;
}

static void btclient_free ( struct refcnt * refcnt ) {
	struct bt_client *client =
	    container_of ( refcnt, struct bt_client, base_client.refcnt );

	DBGC ( client, "BTCLIENT %p freed\n", client );

	torrent_client_free ( &client->base_client );
	free ( client );
}

static void btclient_retry ( struct bt_client * client ) {
	client->block_requested = false;

	btclient_tx_fatal ( client );
}

static void btclient_close ( struct bt_client * client, int rc ) {
	DBGC ( client, "BTCLIENT %p closing: %s\n", client, strerror ( rc ) );

	stop_timer ( &client->rx_timer );
	stop_timer ( &client->block_rx_timer );
	intf_shutdown ( &client->peer, rc );
}

static int btclient_tx_handshake ( struct bt_client * client ) {
	int rc;

	/* being enable to send a handshake means a SYN | ACK was received */
	stop_timer ( &client->rx_timer );

	const size_t buf_size = sizeof ( struct bthandshake );
	struct io_buffer * io_buf = alloc_iob ( buf_size );
	if ( !io_buf ) {
		rc = -ENOBUFS;
		goto err_alloc;
	}

	struct bthandshake * hs = iob_put ( io_buf, buf_size );
	struct torrent * torrent = client->base_client.torrent;

	hs->plen = PROTO_NAME_LEN;
	memcpy ( hs->pstr, PROTO_NAME, PROTO_NAME_LEN );
	memset ( hs->reserved, 0, sizeof ( hs->reserved ) );
	memcpy ( hs->peer_id, torrent->info.peerid, PEERID_SIZE );
	memcpy ( hs->info_hash, torrent->info.info_hash,
		 sizeof ( hs->info_hash ) );

	if ( ( rc = xfer_deliver_iob ( &client->peer,
				       iob_disown ( io_buf ) ) ) != 0 )
		goto err_deliver;

	DBGC ( client, "BTCLIENT %p sent handshake\n", client );

	client->tx = NULL;

	if ( btclient_handshake_finished ( client ) ) {
		client_set_state ( &client->base_client, rx_state,
				   rx_available );
		torrent_schedule ( client->base_client.torrent );
	}

	return 0;

err_deliver:
        free_iob ( io_buf );
err_alloc:
	DBGC ( client, "BTCLIENT %p failed to send handshake\n", client );
	return rc;
}

static bool iob_prog_pull_prepare ( size_t * current, size_t objective,
				    struct io_buffer * io_buf,
				    size_t * pulled_size ) {
	assert ( *current < objective );
	size_t left = objective - *current;

	size_t buf_len = iob_len ( io_buf );
	bool sufficient = buf_len >= left;

	*pulled_size = sufficient ? left : buf_len;

	if ( sufficient )
		*current = 0;
	else
		*current += *pulled_size;

	return sufficient;
}

// returns true and set current to 0 when done
static bool iob_prog_pull_copy ( size_t * current, size_t objective,
				 void * buffer, struct io_buffer * io_buf ) {
	size_t copy_size;
	bool sufficient =
	    iob_prog_pull_prepare ( current, objective, io_buf, &copy_size );

	memcpy ( ( char * )buffer + *current, io_buf->data, copy_size );

	iob_pull ( io_buf, copy_size );

	return sufficient;
}

static int btclient_rx_size ( struct bt_client * client,
			      struct io_buffer * io_buf );

static int btclient_rx_bitset ( struct bt_client * client,
				struct io_buffer * io_buf ) {
	struct bitset *piece_bitset = &client->base_client.remote_pieces;

	if ( !iob_prog_pull_copy ( &client->rx_cursor,
			      client->rx_data.header.size,
			      piece_bitset->data, io_buf ) )
		return 0;

	bitset_init_set_count ( piece_bitset );
	DBGC ( client, "BTCLIENT %p received bitset\n", client );
	torrent_schedule ( client->base_client.torrent );

	btclient_reset_rx ( client );
	return 0;
}

static int btclient_rx_have ( struct bt_client * client,
			      struct io_buffer * io_buf ) {
	uint32_t * have = &client->rx_data.have_id;
	if ( !iob_prog_pull_copy ( &client->rx_cursor, sizeof ( uint32_t ),
				   have, io_buf ) )
		return 0;

	*have = ntohl ( *have );

	DBGC ( client, "BTCLIENT %p received have notification: %d\n", client,
	       *have );

	torrent_schedule ( client->base_client.torrent );
	btclient_reset_rx ( client );
	return 0;
}

static int btclient_rx_piece_content ( struct bt_client *client,
				       struct io_buffer *io_buf ) {
	int rc;

	size_t *current = &client->rx_cursor;

	/* save the cursor before it's moved forward */
	size_t block_off = *current;

	size_t pull_size;
	bool sufficient = iob_prog_pull_prepare (
	    current, client->rx_data.header.size, io_buf, &pull_size );

	struct torrent_info *info = &client->base_client.torrent->info;
	struct btpiece *piece = &client->rx_data.piece;

	size_t offset = info->piece_length * piece->index +
			piece->begin * BLOCK_SIZE + block_off;

	DBGCIO ( client,
		 "BTCLIENT %p receiving piece %d "
		 "block %d offset %zd size %zd\n",
		 client, piece->index, piece->begin, block_off, pull_size );

	struct xfer_metadata meta;
	memset ( &meta, 0, sizeof ( meta ) );
	meta.flags = XFER_FL_ABS_OFFSET;
	meta.offset = offset;

	/* DBGCIO ( client, */
	/* 	 "BTCLIENT %p writting %zd bytes to %zd\n", */
	/* 	 client, pull_size, offset ); */

	if ( ( rc = xfer_deliver_raw_meta ( &client->base_client.torrent->xfer,
					    io_buf->data, pull_size,
					    &meta ) ) != 0 )
		goto err_deliver;

	iob_pull ( io_buf, pull_size );

	if ( !sufficient ) {
		/* What if a peer stops sending data while we're receiving a
		 * chunk? */
		if ( ( rc = inject_fault ( BTCLIENT_STALL_RATE ) ) != 0 ) {
			DBGC ( client, "BTCLIENT %p testing rx stall\n",
			       client );
			intf_restart ( &client->peer, rc );
		}

		return 0;
	}

	DBGC (
	    client, "BTCLIENT %p done receiving piece %d block %d length %d\n",
	    client, piece->index, piece->begin, client->rx_data.header.size );

	struct torrent_piece *pieces = client->base_client.torrent->info.pieces;
	struct torrent_piece *piece_md = &pieces[ piece->index ];
	if ( bitset_set ( &piece_md->block_state, piece->begin, true ) &&
	     piece_ready ( piece_md ) ) {
		stop_timer ( &client->block_rx_timer );
		torrent_received_piece ( &client->base_client, piece_md );
        }
	else
		btclient_retry ( client );

	btclient_reset_rx ( client );

	return 0;

err_deliver:
        return rc;
}

static int btclient_rx_request ( struct bt_client *client,
				 struct io_buffer *io_buf ) {
	struct pending_request *request =
	    &client->tx_queue[ client->pending_requests ];

	if ( !iob_prog_pull_copy ( &client->rx_cursor,
				   sizeof ( struct pending_request ), request,
				   io_buf ) )
		return 0;

	request->index = ntohl ( request->index );
	request->begin = ntohl ( request->begin );
	request->length = ntohl ( request->length );

	DBGC ( client,
	       "BTCLIENT %p received request: piece %d begin %d length "
	       "%d\n",
	       client, request->index, request->begin, request->length );

	struct torrent *torrent = client->base_client.torrent;
	if ( request->index >= torrent->info.piece_count ||
	     !bitset_get ( &torrent->info.received_pieces, request->index ) ) {
		DBGC ( client,
		       "BTCLIENT %p discarding request: piece "
		       "unavailable\n",
		       client );
		return -EPROTO;
	}

	struct torrent_piece *piece = &torrent->info.pieces[ request->index ];
	if ( request->begin > piece->length ||
	     request->begin + request->length > piece->length )
		return -EPROTO;

        assert ( client->pending_requests <= TX_QUEUE_SIZE );
	if ( client->pending_requests < TX_QUEUE_SIZE ) {
		client->pending_requests++;
		DBGC ( client, "BTCLIENT %p enqueueing request\n", client );
	} else
		DBGC ( client,
		       "BTCLIENT %p discarding request: overflowing queue\n",
		       client );

	btclient_reset_rx ( client );

	return btclient_tx ( client );
}

/* content of already received pieces need to be discarded. */
static int btclient_rx_discard ( struct bt_client *client,
				 struct io_buffer *io_buf ) {
	size_t pull_size;
	bool sufficient = iob_prog_pull_prepare ( &client->rx_cursor,
						  client->rx_data.header.size,
						  io_buf, &pull_size );

	iob_pull ( io_buf, pull_size );

	if ( !sufficient )
		return 0;

	btclient_reset_rx ( client );
	return 0;
}

static int btclient_rx_piece ( struct bt_client *client,
			       struct io_buffer *io_buf ) {
	struct btpiece *piece = &client->rx_data.piece;

	const size_t piece_metadata_size =
	    ( sizeof ( struct btpiece ) - sizeof ( struct btheader ) );

	if ( !iob_prog_pull_copy ( &client->rx_cursor, piece_metadata_size,
				   &piece->index, io_buf ) )
		return 0;

	uint32_t *block_size = &client->rx_data.header.size;
	*block_size -= piece_metadata_size;

	piece->index = ntohl ( piece->index );
	piece->begin = ntohl ( piece->begin );

	struct torrent_info *info = &client->base_client.torrent->info;

	if ( piece->index >= info->piece_count ||
	     piece->begin >= info->piece_length )
		return -EPROTO;

	/* we never request block with misaligned offsets */
	if ( piece->begin % BLOCK_SIZE != 0 ) {
		DBGC ( client, "BTCLIENT %p send some misaligned piece\n",
		       client );
		return -EPROTO;
	}

	piece->begin /= BLOCK_SIZE;

	struct torrent_piece *target = client->base_client.target;
	if ( !target || piece->index != target->id ||
	     piece->begin >= piece_block_count ( target ) ||
	     bitset_get ( &target->block_state, piece->begin ) ||
	     *block_size != piece_block_size ( target, piece->begin ) ) {
		/* if we're not interested in the data we're being sent, discard
		 * it. It sometimes happends in the wild, when a block gets
		 * requested twice and we switch target */
		btclient_expect_rx ( client, btclient_rx_discard );

		DBGC ( client,
		       "BTCLIENT %p discarding piece %d block %d length %d\n",
		       client, piece->index, piece->begin,
		       client->rx_data.header.size );
		return 0;
	}

	DBGC ( client,
	       "BTCLIENT %p started receiving piece %d block %d length %d\n",
	       client, piece->index, piece->begin,
	       client->rx_data.header.size );

        stop_timer ( &client->block_rx_timer );

	btclient_expect_rx ( client, btclient_rx_piece_content );
	return 0;
}

static int btclient_rx_type ( struct bt_client *client,
			      struct io_buffer *io_buf ) {
	int rc;
	struct btheader *header = &client->rx_data.header;
	header->type = *( unsigned char * )io_buf->data;
	iob_pull ( io_buf, 1 );

	header->size -= 1;

	if ( header->type >= BTTYPE_INVALID )
		goto err_proto;

	switch ( header->type ) {
	case BTTYPE_CHOKE:
		DBGC ( client, "BTCLIENT %p choked\n", client );
		client->choked = true;
	simple_message:
		btclient_reset_rx ( client );
		break;

	case BTTYPE_UNCHOKE:
		DBGC ( client, "BTCLIENT %p unchoked\n", client );
		client->choked = false;
		if ( ( rc = btclient_tx ( client ) ) != 0 )
                    goto err_tx;
		goto simple_message;

	case BTTYPE_INTERESTED:
		DBGC ( client, "BTCLIENT %p peer interested\n", client );
		client_set_state ( &client->base_client, unchoke_state,
				   unchoke_pending );
                torrent_schedule ( client->base_client.torrent );
		client->interesting = true;
		goto simple_message;

	case BTTYPE_NOT_INTERESTED:
		DBGC ( client, "BTCLIENT %p peer not interested\n", client );
		client_set_state ( &client->base_client, tx_state, tx_inactive );
		client->interesting = false;
		goto simple_message;

	case BTTYPE_HAVE:
		if ( header->size != sizeof ( uint32_t ) )
			goto err_proto;

		btclient_expect_rx ( client, btclient_rx_have );
		break;

	case BTTYPE_BITFIELD:
		if ( bitset_needed_room (
			 client->base_client.torrent->info.piece_count ) >
		     header->size )
			goto err_proto;

		btclient_expect_rx ( client, btclient_rx_bitset );
		break;

	case BTTYPE_PIECE:
		/** Size has to be greater as the piece contains data */
		if ( header->size <= ( sizeof ( struct btpiece ) -
				       sizeof ( struct btheader ) ) )
			goto err_proto;

		btclient_expect_rx ( client, btclient_rx_piece );
		break;

	case BTTYPE_REQUEST:
		if ( header->size != ( sizeof ( struct btrequest ) -
				       sizeof ( struct btheader ) ) )
			goto err_proto;

		if ( client->choking ) {
			DBGC ( client,
			       "BTCLIENT %p peer is being choked, discarding "
			       "request\n",
			       client );
			btclient_expect_rx ( client, btclient_rx_discard );
		} else
			btclient_expect_rx ( client, btclient_rx_request );

		break;

	case BTTYPE_CANCEL:
	case BTTYPE_PORT:
		/** Ignoring cancels should be ok */
		btclient_expect_rx ( client, btclient_rx_discard );
		break;
	}

	return 0;

err_tx:
	return rc;
err_proto:
	return -EPROTO;
}

static int btclient_rx_size ( struct bt_client *client,
			      struct io_buffer *io_buf ) {
	uint32_t *size = &client->rx_data.header.size;
	if ( !iob_prog_pull_copy ( &client->rx_cursor, sizeof ( uint32_t ),
				   size, io_buf ) )
		return 0;

	/** Zero-sized messages are keepalives */
	if ( *size == 0 ) {
		DBGC ( client, "BTCLIENT %p received keepalive\n", client );
		return 0;
	}

	*size = ntohl ( *size );
	btclient_expect_rx ( client, btclient_rx_type );

	return 0;
}

static void btclient_expect_rx ( struct bt_client *client,
				 bt_client_receiver receiver ) {
	start_timer_fixed ( &client->rx_timer, BTCLIENT_RX_TIMEOUT );
	client->rx = receiver;
}

static int btclient_rx_message ( struct bt_client *client,
				 struct io_buffer *io_buf __unused ) {
	btclient_expect_rx ( client, btclient_rx_size );
        return 0;
}

static void btclient_reset_rx ( struct bt_client *client ) {
	stop_timer ( &client->rx_timer );
	client->rx = btclient_rx_message;
}

static int btclient_rx_handshake ( struct bt_client *client,
				   struct io_buffer *io_buf ) {
	struct bthandshake *handshake = &client->rx_data.handshake;
	if ( !iob_prog_pull_copy ( &client->rx_cursor,
				   sizeof ( struct bthandshake ), handshake,
				   io_buf ) )
		return 0;

	DBGC ( client, "BTCLIENT %p received handshake\n", client );

        btclient_reset_rx ( client );

	if ( btclient_handshake_finished ( client ) ) {
		client_set_state ( &client->base_client, rx_state,
				   rx_available );
		torrent_schedule ( client->base_client.torrent );
	}

	return 0;
}

static int btclient_rx ( struct bt_client *client,
			 struct io_buffer *io_buf,
			 struct xfer_metadata *meta __unused ) {
	int rc;

	assert ( client->rx );

	/* Extend download attempt timer */
	start_timer_fixed ( &client->rx_timer, BTCLIENT_RX_TIMEOUT );

	/* Test our ability to recover from invalid data */
	if ( inject_corruption ( BTCLIENT_CORRUPT_RATE, io_buf->data,
				 iob_len ( io_buf ) ) != 0 )
		DBGC ( client, "BTCLIENT %p corrupted packet\n", client );

	while ( iob_len ( io_buf ) )
		if ( ( rc = client->rx ( client, io_buf ) ) != 0 )
			goto err_rx;

	free_iob ( io_buf );

	return 0;

err_rx:
	DBGC ( client, "BTCLIENT %p rx error, closing\n", client );
	btclient_close ( client, rc );
	torrent_client_unregister ( &client->base_client );
	return rc;
}

int btclient_connect ( struct torrent_client * base_client ) {
	int rc;

	base_client->type = &bt_client_type;

	struct bt_client *client = ( void * )base_client;
	if ( ( rc = xfer_open_socket ( &client->peer, SOCK_STREAM,
				       ( struct sockaddr * )&base_client->addr,
				       NULL ) ) != 0 )
		return rc;

	/* If applicable, restart the interface to test our ability to recover
	 * from an unresponsive peer */
	if ( inject_fault ( BTCLIENT_ANNUL_RATE ) ) {
		DBGC ( client, "BTCLIENT %p testing unresponsive xfer_open\n",
		       client );
		intf_restart ( &client->peer, 0 );
	}

	start_timer_fixed ( &client->rx_timer, BTCLIENT_CONN_RX_TIMEOUT );
	return 0;
}

static int btclient_tx_simple ( struct bt_client * client, enum bttype type ) {
	int rc;

	const size_t buf_size = sizeof ( struct btheader );
	struct io_buffer * io_buf = alloc_iob ( buf_size );
	if ( !io_buf ) {
		rc = -ENOBUFS;
		goto fail;
	}

	struct btheader * header = iob_put ( io_buf, buf_size );
	*header = BTHEADER ( sizeof ( struct btheader ), type );

	if ( ( rc = xfer_deliver_iob ( &client->peer,
				       iob_disown ( io_buf ) ) ) != 0 )
		goto fail;

	client->tx = NULL;

	return 0;

fail:
	return rc;
}

static size_t find_blocks ( struct torrent_piece * piece, size_t * blocks ) {
	size_t original_cursor = piece->block_cursor;
	size_t found_blocks = 0;
	size_t block_count = piece->block_state.bit_size;
        struct bitset * block_state = &piece->block_state;

	size_t cursor;
	do {
		cursor = piece->block_cursor;
		/* advance the cursor by one */
		piece->block_cursor = ( cursor + 1 ) % block_count;

		/* if the block under the cursor isn't here yet */
		if ( !bitset_get ( block_state, cursor ) ) {
			/* add it to the result array */
			blocks[ found_blocks++ ] = cursor;

			/* if we got all we want, exit */
			if ( found_blocks == MAX_BLOCKS )
				break;
		}

		/* if we got back to our starting point, exit, we won't find any
		 * more */
	} while ( piece->block_cursor != original_cursor );

	assert ( found_blocks <=
		 block_state->bit_size - block_state->set_count );

	return found_blocks;
}

static int btclient_tx_request ( struct bt_client * client ) {
	int rc;

	assert ( client->base_client.target );

	struct torrent_piece *target_piece = client->base_client.target;

	size_t blocks[ MAX_BLOCKS ];
	size_t block_count = find_blocks ( target_piece, blocks );

	/* if there are no more missing blocks, we should have switched
	   to another target*/
	assert ( block_count > 0 );

	DBGC ( client, "BTCLIENT %p requesting piece %zd block ", client,
	       target_piece->id );

	for ( size_t i = 0; i < block_count; i++ )
		DBGC ( client, "%zd%s", blocks[ i ],
		       ( i < block_count - 1 ) ? ", " : "\n" );


	const size_t buf_size = sizeof ( struct btrequest ) * block_count;
	struct io_buffer *io_buf = alloc_iob ( buf_size );
	if ( !io_buf ) {
		rc = -ENOBUFS;
		goto fail;
	}

	size_t piece_len = client->base_client.target->length;
	for ( size_t block_i = 0; block_i < block_count; block_i++ ) {
		size_t block_begin = blocks[ block_i ] * BLOCK_SIZE;
		size_t block_len = piece_len - block_begin;
		if ( block_len > BLOCK_SIZE )
			block_len = BLOCK_SIZE;

		size_t index = client->base_client.target->id;

		struct btrequest * request =
		    iob_put ( io_buf, sizeof ( struct btrequest ) );
		*request = BTREQUEST ( index, block_begin, block_len );
	}

	if ( ( rc = xfer_deliver_iob ( &client->peer,
				       iob_disown ( io_buf ) ) ) != 0 )
		goto fail;

	client->block_requested = true;

	start_timer_fixed ( &client->block_rx_timer, // TODO: check if relevant
			    BTCLIENT_BLOCK_RX_TIMEOUT );

	client->block_requested = true;

	client->tx = NULL;

	DBGC ( client, "BTCLIENT %p properly delivered request\n", client );
	return 0;

fail:
	DBGC ( client, "BTCLIENT %p failed with delivering a request: %s\n",
	       client, strerror ( rc ) );
	return rc;
}

static int btclient_tx_interested ( struct bt_client * client ) {
	client->interested = true;
	DBGC ( client, "BTCLIENT %p expressing interest\n", client );
	return btclient_tx_simple ( client, BTTYPE_INTERESTED );
}

static int btclient_needs_choke_update ( struct bt_client * client ) {
	return ( client->unchoked_remote == client->choking );
}

static int btclient_tx_choke_update ( struct bt_client * client ) {
	int rc;

	if ( !btclient_needs_choke_update ( client ) ) {
		DBGC ( client,
		       "BTCLIENT %p choke state already is up to date\n",
		       client );
		return 0;
	}

	if ( client->choking ) {
		DBGC ( client, "BTCLIENT %p sending choke\n", client );
	        rc = btclient_tx_simple ( client, BTTYPE_CHOKE );
	} else {
		DBGC ( client, "BTCLIENT %p sending unchoke\n", client );
		rc =  btclient_tx_simple ( client, BTTYPE_UNCHOKE );
	}

	if ( rc != 0 )
		return rc;

	client->unchoked_remote = !client->choking;
	return rc;
}

static bool btclient_needs_tx_have ( struct bt_client * client ) {
	struct torrent * torrent = client->base_client.torrent;
	return client->announced_pieces.set_count !=
	       torrent->info.received_pieces.set_count;
}

static int btclient_tx_have_id ( struct bt_client * client, size_t piece_id ) {
	int rc;

	const size_t buf_size = sizeof ( struct bthave );
	struct io_buffer *io_buf = alloc_iob ( buf_size );
	if ( !io_buf ) {
		rc = -ENOBUFS;
		goto fail;
	}

	struct bthave * have = iob_put ( io_buf, buf_size );
	*have = BTHAVE ( piece_id );

	if ( ( rc = xfer_deliver_iob ( &client->peer,
				       iob_disown ( io_buf ) ) ) != 0 )
 		goto fail;

 	DBGC ( client, "BTCLIENT %p announced piece %zd\n",
 	       client, piece_id );

	bitset_set ( &client->announced_pieces, piece_id, true );

	client->tx = NULL;

	return 0;

fail:
 	DBGC ( client, "BTCLIENT %p failed to announce piece %zd: %s\n",
 	       client, piece_id, strerror ( rc ) );
	return rc;
}

static int btclient_tx_have ( struct bt_client *client ) {
	assert ( btclient_needs_tx_have ( client ) );

	struct torrent * torrent = client->base_client.torrent;
	size_t missing_index =
		bitset_find_diff ( &client->announced_pieces,
				   &torrent->info.received_pieces );

	assert ( missing_index != 0 );

	return btclient_tx_have_id ( client, missing_index - 1 );
}

static int btclient_tx_piece ( struct bt_client *client ) {
	int rc;

	assert ( client->pending_requests );

	/* we need to take the first request and shift the whole stack
	   once done. A proper solution would be to use a ring buffer */
	struct pending_request *request = &client->tx_queue[ 0 ];

	assert ( client->tx_cursor <= request->length );

	size_t reserved_size;
	if ( client->tx_cursor == 0 ) {
		DBGCIO ( client,
			"BTCLIENT %p delivering piece at "
			"index %d begin %d length %d\n",
			client, request->index, request->begin,
			request->length );
		reserved_size = sizeof ( struct btpiece );
	} else
		reserved_size = 0;

	size_t chunk_size = TX_CHUNK_SIZE - reserved_size;
	size_t remaining = request->length - client->tx_cursor;
	if ( chunk_size > remaining )
		chunk_size = remaining;

	size_t buf_size = reserved_size + chunk_size;

	struct io_buffer *io_buf = alloc_iob ( buf_size );
	if ( !io_buf ) {
		rc = -ENOBUFS;
		goto fail;
	}

	if ( reserved_size ) {
		struct btpiece *piece = iob_put ( io_buf, reserved_size );
		piece->header = BTHEADER (
		    sizeof ( struct btpiece ) + request->length, BTTYPE_PIECE );
		piece->index = htonl ( request->index );
		piece->begin = htonl ( request->begin );
	}

	struct torrent *torrent = client->base_client.torrent;
	struct xfer_buffer *xferbuf = xfer_buffer ( &torrent->xfer );
	assert ( xferbuf != NULL );

	xferbuf_read ( xferbuf,
		       torrent->info.piece_length * request->index +
			   request->begin + client->tx_cursor,
		       iob_put ( io_buf, chunk_size ), chunk_size );

	if ( ( rc = xfer_deliver_iob ( &client->peer,
				       iob_disown ( io_buf ) ) ) != 0 )
 		goto fail;

	client->tx_cursor += chunk_size;
	if ( client->tx_cursor == request->length ) {
		client->tx_cursor = 0;

		DBGCIO ( client, "BTCLIENT %p delivered piece\n", client );

		client->base_client.torrent->info.downloaded += request->length;
		/* the torrent may want to stop seeding at some point */
		torrent_schedule ( torrent );

		client->pending_requests--;
		// FIXME: use a ring buffer
		memmove ( &client->tx_queue[ 0 ], &client->tx_queue[ 1 ],
			  sizeof ( struct pending_request ) *
			      client->pending_requests );
		client->tx = NULL;
	}

	return 0;

fail:
	return rc;
}

static bt_client_transmitter
btclient_transmit_decision ( struct bt_client *client ) {
	if ( client->tx )
		return client->tx;

        if ( btclient_needs_choke_update ( client ) )
		return ( client->tx = btclient_tx_choke_update );

	if ( btclient_needs_tx_have ( client ) )
		return ( client->tx = btclient_tx_have );

	/* if we have nothing to download anyway */
	if ( client->base_client.target == NULL )
		DBGC ( client, "BTCLIENT %p has no target\n", client );
	else {
		if ( !client->interested )
			return ( client->tx = btclient_tx_interested );

		if ( client->choked )
			DBGC ( client, "BTCLIENT %p is being choked\n",
			       client );
		else if ( !client->block_requested )
			return ( client->tx = btclient_tx_request );
	}

	if ( client->pending_requests )
		return ( client->tx = btclient_tx_piece );

	return NULL;
}

// Beware, client may be unregistered after the call
static int btclient_tx ( struct bt_client *client ) {
	int rc;

	if ( !xfer_window ( &client->peer ) ) {
		DBGC ( client, "BTCLIENT %p has no transfer window\n", client );
		return 0;
	}

	/* TODO: consider looping while there is a transfer window */
	DBGC ( client, "BTCLIENT %p has a transfer window of %zd\n", client,
	       xfer_window ( &client->peer ) );

	bt_client_transmitter transmitter;
	if ( ( transmitter = btclient_transmit_decision ( client ) ) ) {
		if ( ( rc = transmitter ( client ) ) != 0 )
			return rc;
	}

	return 0;
}

static void btclient_rx_timeout ( struct retry_timer *timer,
				  int over __unused ) {
	struct bt_client *client;

	client = container_of ( timer, struct bt_client, rx_timer );

	DBGC ( client, "BTCLIENT %p rx timed out, closing and unregistering\n",
	       client );
	btclient_close ( client, -ETIMEDOUT );
        torrent_client_unregister ( &client->base_client );
	return;
}

static void btclient_block_timeout ( struct retry_timer *timer,
				     int over __unused ) {
	struct bt_client *client;

	client = container_of ( timer, struct bt_client, block_rx_timer );

	DBGC ( client, "BTCLIENT %p retry timer triggered\n", client );
	btclient_retry ( client );
	return;
}

// gen_client may not ba alive after the call
int btclient_request ( struct torrent_client *gen_client,
		       struct torrent_piece *piece __unused ) {
	struct bt_client *client = ( void * )gen_client;

	client->block_requested = false;

	return btclient_tx ( client );
}

int btclient_announce_piece ( struct torrent_client * base_client,
                              struct torrent_piece * piece ) {
	struct bt_client * client = ( struct bt_client * ) base_client;

	/** don't send messages while already transmitting */
	if ( client->tx == NULL && xfer_window ( &client->peer ) != 0 )
		return btclient_tx_have_id ( client, piece->id );

	DBGC ( client, "BTCLIENT %p couldn't immediatly announce piece %d\n",
	       client, ( int ) piece->id );
	return 0;
}

static int btclient_set_choke ( struct torrent_client * base_client, bool state ) {
	struct bt_client * client = ( struct bt_client * ) base_client;
	if ( state == client->choking ) {
		DBGC ( client, "BTCLIENT %p called set_choking without "
		       "changing the state\n", client );
		return -EINVAL;
	}

	client->choking = state;
	/* the main handler will notice the state changed at the next transmit
	   decision */
	return btclient_tx ( client );
}

static void btclient_peer_close ( struct bt_client *client, int rc ) {
	DBGC ( client, "BTCLIENT %p remote peer closed connection\n", client );
	btclient_close ( client, rc );
	torrent_client_unregister ( &client->base_client );
}

static struct interface_operation bt_torrent_operations[] = {
    INTF_OP ( intf_close, struct bt_client *, btclient_peer_close ),
    INTF_OP ( xfer_deliver, struct bt_client *, btclient_rx ),
    INTF_OP ( xfer_window_changed, struct bt_client *, btclient_tx_fatal ),
};

static struct interface_descriptor bt_torrent_desc =
    INTF_DESC ( struct bt_client, peer, bt_torrent_operations );

struct torrent_client_operations bt_client_type = {
    .connect = btclient_connect,
    .request = btclient_request,
    .announce_piece = btclient_announce_piece,
    .set_choke = btclient_set_choke,

    // TODO: fix ugly hack
    .close = ( void ( * ) ( struct torrent_client *, int ) )btclient_close,
};

struct bt_client * btclient_create ( struct torrent *torrent,
                                     struct sockaddr *addr, int *dest_rc ) {
	int rc;

	struct bt_client *client = zalloc ( sizeof ( *client ) );
	if ( !client )
		return NULL;

	DBGC2 ( torrent, "BTCLIENT %p allocated\n", client );

	client->base_client.type = &bt_client_type;

	if ( ( rc = bitset_init ( &client->announced_pieces,
				  torrent->info.piece_count ) ) != 0 )
		goto err_announced_pieces_init;

        /* only allocates and initializes structures */
	if ( ( rc = torrent_client_init ( torrent, &client->base_client,
					  btclient_free, addr ) ) != 0 )
		goto err_client_init;

	client->choked = true;
	client->choking = true;

	client->tx = btclient_tx_handshake;
	btclient_expect_rx ( client, btclient_rx_handshake );

	timer_init ( &client->rx_timer, btclient_rx_timeout,
		     &client->base_client.refcnt );

	timer_init ( &client->block_rx_timer, btclient_block_timeout,
		     &client->base_client.refcnt );

	intf_init ( &client->peer, &bt_torrent_desc,
		    &client->base_client.refcnt );

	return client;

err_client_init:
        bitset_free ( &client->announced_pieces );
err_announced_pieces_init:
	free ( client );
	*dest_rc = rc;
	return NULL;
}

int btclient_accept ( struct bt_client *client,
		      struct sockaddr_tcpip *st_peer,
		      struct sockaddr_tcpip *st_local,
		      struct tcp_header *tcphdr ) {
	int rc;

	DBGC ( client, "BTCLIENT %p accepting\n", client );

	if ( ( rc = tcp_accept ( &client->peer, st_peer,
				 st_local, tcphdr ) ) != 0 )
		return rc;

	client_set_state ( &client->base_client, conn_state, connected );
	return 0;
}
