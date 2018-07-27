/*
 * Copyright (C) 2018 Victor Collod <victor.collod@lse.epita.fr>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <errno.h>
#include <ipxe/http.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/refcnt.h>
#include <ipxe/retry.h>
#include <ipxe/tcpip.h>
#include <ipxe/time.h>
#include <ipxe/timer.h>
#include <ipxe/uaccess.h>
#include <ipxe/xfer.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ipxe/bencode.h>
#include <ipxe/bittorrent.h>
#include <ipxe/bittorrent_client.h>
#include <ipxe/fault.h>
#include <ipxe/in.h>
#include <ipxe/open.h>
#include <ipxe/sha1.h>
#include <ipxe/socket.h>
#include <ipxe/tcp.h>
#include <ipxe/tcpip.h>
#include <ipxe/uri.h>
#include <ipxe/xfer.h>

#define TORRENT_ANNOUNCE_INTERVAL ( 30 * TICKS_PER_SEC )
#define MAX_ANNOUNCE_RETRY_COUNT 3

static void torrent_free ( struct refcnt *refcnt ) {
	struct torrent *torrent;

	torrent = container_of ( refcnt, struct torrent, refcnt );
	DBGC ( torrent, "TORRENT %p freed\n", torrent );

	xferbuf_free ( &torrent->tracker_response );
	torrent_info_free ( &torrent->info );
	free ( torrent );
}

static int torrent_announce ( struct torrent * torrent ) {
	struct uri *announce_uri =
	    torrent_announce_uri ( &torrent->info, torrent->state );

	int rc = http_open ( &torrent->tracker, &http_get, announce_uri, NULL,
			     NULL );

	/* Test our ability to recover from an unresponsive tracker */
	if ( inject_fault ( TORRENT_ANNUL_RATE ) ) {
		DBGC ( torrent,
		       "TORRENT %p testing unresponsive tracker recovery\n",
		       torrent );
		intf_restart ( &torrent->tracker, 0 );
	}

	if ( rc == 0 )
		start_timer_fixed ( &torrent->announce_timer,
				    TORRENT_ANNOUNCE_INTERVAL );

	uri_put ( announce_uri );
	return rc;
}

static void torrent_close ( struct torrent *torrent, int rc ) {
	DBGC ( torrent, "TORRENT %p completed (%s)\n", torrent,
	       strerror ( rc ) );

	struct torrent_client * client;
	struct torrent_client * tmp;

	stop_timer ( &torrent->connection_scheduler );
	stop_timer ( &torrent->unchoke_scheduler );
	stop_timer ( &torrent->piece_scheduler );
	stop_timer ( &torrent->termination_scheduler );

	list_for_each_entry_safe ( client, tmp, &torrent->clients_connected,
				   conn_state )
		torrent_client_close ( client, 0 );

	intf_shutdown ( &torrent->server, rc );

	if ( torrent->state == TORRENT_STOPPING )
		return;

	torrent->rc = rc;
	torrent->state = TORRENT_STOPPING;
	torrent_announce ( torrent );
}

static void torrent_finalize_close ( struct torrent * torrent ) {
	intf_shutdown ( &torrent->xfer, torrent->rc );
}

// TODO: move elsewhere
struct torrent_client *torrent_client_find ( struct torrent * torrent,
					     struct sockaddr * addr ) {
	struct torrent_client * client;
	list_for_each_entry ( client, &torrent->clients_all, all_list )
		if ( memcmp ( &client->addr, addr, sizeof ( *addr ) ) == 0 )
			return client;

	return NULL;
}

static int torrent_collect_peers ( struct torrent * torrent,
				   struct bdict * response ) {
	int rc;
	struct bdata * peer_str;

	/* {"complete":0,"incomplete":0,"interval":5,
	    "peers":"\u000A**\u0002\u0000\u0000"} */

	if ( bdict_find ( response, "failure reason" ) )
		return -EINVAL;

	if ( !( peer_str = bdict_find ( response, "peers" ) ) )
		return -EINVAL;

	if ( peer_str->type != BSTR )
		return -EINVAL;

	struct btbuf *peer_buf = &peer_str->data.str;
	size_t peer_buf_size = btbuf_size ( peer_buf );

	const size_t peer_size =
	    ( sizeof ( struct in_addr ) + sizeof ( uint16_t ) );

	/* this string is an array of binary ipv4 addresses */
	if ( peer_buf_size % peer_size != 0 )
		return -EINVAL;

	size_t peer_count = peer_buf_size / peer_size;

	for ( size_t i = 0; i < peer_count; i++ ) {
		uint32_t *ip = ( void * )peer_buf->begin + i * peer_size;
		uint16_t port = *( uint16_t * )( ip + 1 );

		struct sockaddr_in addr;
		memset ( &addr, 0, sizeof ( addr ) );
		addr.sin_family = AF_INET;
		addr.sin_port = port;
		addr.sin_addr.s_addr = *ip;

		if ( torrent_client_find ( torrent,
					   ( struct sockaddr * )&addr ) ) {
			DBGC (
			    torrent,
			    "TORRENT %p duplicate bt_client %s:%d, skipping\n",
			    torrent, inet_ntoa ( *( struct in_addr * )ip ),
			    ntohs ( port ) );
			continue;
		}

		struct bt_client *client;
		if ( ( client = btclient_create ( torrent,
						  ( struct sockaddr * )&addr,
						  &rc ) ) == NULL )
			goto err_create;

		DBGC ( client, "BTCLIENT %p created: %s:%d\n", client,
		       inet_ntoa ( *( struct in_addr * )ip ), ntohs ( port ) );

		torrent_client_register ( torrent,
					  ( struct torrent_client * ) client );
	}

	return 0;

err_create:
	return rc;
}

static int torrent_announce_deliver ( struct torrent *torrent,
				     struct io_buffer *iobuf,
				     struct xfer_metadata *meta ) {
	int rc;

	// Add data to buffer
	if ( ( rc = xferbuf_deliver ( &torrent->tracker_response, iobuf,
				      meta ) ) != 0 ) {
		torrent_close ( torrent, rc );
		return rc;
	}

	return 0;
}

static void torrent_announce_finished ( struct torrent *torrent, int rc ) {
	DBG ( "TORRENT %p tracker answer (%s)\n", torrent, strerror ( rc ) );

	/* Terminate download on error */
	if ( rc != 0 )
		goto err_download;

	/* Reset the retry count */
	torrent->announce_retry_count = 0;

	switch ( torrent->state ) {
	case TORRENT_STOPPING:
		/* If the torrent is stopping, don't update the peer list,
		   close the socket */
		intf_shutdown ( &torrent->tracker, rc );
		torrent_finalize_close ( torrent );
		return;
	case TORRENT_STARTING:
		torrent->state = TORRENT_RUNNING;
		break;
	default:
		break;
	}

	/* Shut down tracker interfaces, and prepare it to be reused */
	intf_restart ( &torrent->tracker, rc );

	struct xfer_buffer *response_xferbuf = &torrent->tracker_response;
	struct btbuf response_buf = {
		.begin = response_xferbuf->data,
		.end = ( char * )response_xferbuf->data + response_xferbuf->len,
	};

	struct bdata *response = bencode_parse ( &response_buf );
	if ( response == NULL ) {
		rc = -EINVAL;
		goto err_parse;
	}

	if ( response->type != BDICT ) {
		rc = -EINVAL;
		goto err_parse_peers;
	}

	if ( ( rc = torrent_collect_peers ( torrent, response->data.dict ) ) !=
	     0 )
		goto err_parse_peers;

	/* reset the buffer for next announces */
	xferbuf_free ( &torrent->tracker_response );
	memset ( &torrent->tracker_response, 0,
		 sizeof ( torrent->tracker_response ) );
	xferbuf_malloc_init ( &torrent->tracker_response );

	/* Trigger the scheduler so that it can use newly retrieved peers */
	torrent_schedule ( torrent, connection );

	return;

err_parse_peers:
	bencode_free ( response );
err_parse:
err_download:
	torrent_close ( torrent, rc );
}

/** Torrent data transfer interface operations */
static struct interface_operation tracker_operations[] = {
	INTF_OP ( xfer_deliver, struct torrent *, torrent_announce_deliver ),
	INTF_OP ( intf_close, struct torrent *, torrent_announce_finished ),
};

/** Block download data transfer interface descriptor */
static struct interface_descriptor tracker_desc =
	INTF_DESC ( struct torrent, tracker, tracker_operations );

static struct torrent_piece *
find_best_piece ( struct torrent_client ** res_client,
		  struct torrent * torrent ) {
	size_t piece_count = torrent->info.piece_count;

	// TODO: this is a really dumb vla, remove it
	struct piece_stats {
		struct torrent_client *client;
		size_t count;
	} stats[ piece_count ];

	memset ( stats, 0, sizeof ( struct piece_stats ) * piece_count );

	struct torrent_info *info = &torrent->info;

	struct torrent_client *client;
	struct torrent_piece *cur_piece;

	size_t imin = 0;
	list_for_each_entry ( cur_piece, &torrent->info.pending_pieces, list ) {
		size_t i = cur_piece->id;
		list_for_each_entry ( client, &torrent->clients_rx_available,
				      rx_state ) {
			if ( bitset_get ( &client->remote_pieces, i ) ) {
				stats[ i ].client = client;
				stats[ i ].count++;
			}
		}

		if ( stats[ i ].client && stats[ i ].count != 0 &&
		     ( stats[ imin ].count == 0 ||
		       stats[ i ].count < stats[ imin ].count ) )
			imin = i;
	}

	if ( stats[ imin ].client == NULL ) {
		DBGC ( torrent, "TORRENT %p couldn't find any free piece\n",
		       torrent );
		return NULL;
	}

	*res_client = stats[ imin ].client;
	return &info->pieces[ imin ];
}

static void torrent_hash_range ( struct torrent * torrent,
                                 unsigned char * shabuf,
                                 size_t begin, size_t end ) {
	struct xfer_buffer *xbuf = xfer_buffer ( &torrent->xfer );

	struct digest_algorithm *const digest = &sha1_algorithm;
	uint8_t ctx[ digest->ctxsize ];

        const size_t block_size = 1024;
        char tmp_buf[block_size];

	digest_init ( digest, ctx );

	/* TODO: find a way to hash data inside the user buffer,
	   without copying it */

        size_t len = end - begin;

	for ( size_t i = 0; i < len; i += block_size ) {
		size_t cur_block_size = len - i;
		if ( cur_block_size > block_size )
			cur_block_size = block_size;

		xferbuf_read ( xbuf, begin + i, tmp_buf, cur_block_size );
		digest_update ( digest, ctx, tmp_buf, cur_block_size );
	}

	digest_final ( digest, ctx, shabuf );
}

static void torrent_finished ( struct torrent * torrent ) {
	DBGC ( torrent, "TORRENT %p finished downloading\n", torrent );

	unsigned char shabuf[ SHA1_DIGEST_SIZE ];
	torrent_hash_range ( torrent, shabuf, 0, torrent->info.total_length );

	DBGC ( torrent, "TORRENT %p hash: ", torrent );

	for ( size_t i = 0; i < SHA1_DIGEST_SIZE; i++ )
		DBGC ( torrent, "%02x", shabuf[ i ] );

	DBGC ( torrent, "\n" );

	torrent_close ( torrent, 0 );
}

void torrent_connection_scheduler ( struct retry_timer *timer,
				    int __unused over ) {

	struct torrent *torrent =
	    container_of ( timer, struct torrent, connection_scheduler );

	DBGC ( torrent, "TORRENT %p connection scheduler stepping\n", torrent );

	struct torrent_client * client, * tmp;
	list_for_each_entry_safe ( client, tmp, &torrent->clients_disconnected,
				   conn_state )
		torrent_client_connect ( client );
}

void torrent_unchoke_scheduler ( struct retry_timer *timer,
				 int __unused over ) {

	struct torrent *torrent =
	    container_of ( timer, struct torrent, unchoke_scheduler );

	DBGC ( torrent, "TORRENT %p unchoke scheduler stepping\n", torrent );

        struct torrent_client * client, * tmp;
	list_for_each_entry_safe (
	    client, tmp, &torrent->clients_unchoke_pending, unchoke_state ) {
		torrent_client_set_choke ( client, false );
	}
}

void torrent_termination_scheduler ( struct retry_timer *timer,
				     int __unused over ) {

	struct torrent *torrent =
	    container_of ( timer, struct torrent, termination_scheduler );

	DBGC ( torrent, "TORRENT %p termination scheduler stepping\n", torrent );

	int seed_ratio = torrent->seed_ratio;
	if ( seed_ratio > 0 ) {
		if ( 100 * torrent->info.uploaded /
		     torrent->info.total_length ) {
			goto torrent_done;
		}
	} else if ( list_empty ( &torrent->info.pending_pieces ) )
		goto torrent_done;

	return;

torrent_done:
	torrent_finished ( torrent );
	return;
}

void torrent_piece_scheduler ( struct retry_timer *timer, int __unused over ) {
	struct torrent *torrent =
	    container_of ( timer, struct torrent, piece_scheduler );

	DBGC ( torrent, "TORRENT %p piece scheduler stepping\n", torrent );

	if ( list_empty ( &torrent->info.pending_pieces ) ) {
		DBGC ( torrent, "TORRENT %p no remaining piece\n", torrent );
		return;
	}

	struct torrent_client *best_client;
	struct torrent_piece *best_piece =
	    find_best_piece ( &best_client, torrent );
	if ( best_piece ) {
		DBGC ( best_client, "TORRENT_CLIENT %p requesting piece %zd\n",
		       ( void * )best_client, best_piece->id );
		torrent_client_request ( best_client, best_piece );
	}
}

/** Job control interface operations */
static struct interface_operation torrent_xfer_operations[] = {
	INTF_OP ( intf_close, struct torrent *, torrent_close ),
};

/** Job control interface operations */
static struct interface_descriptor torrent_xfer_desc =
	INTF_DESC ( struct torrent, xfer, torrent_xfer_operations );

int torrent_notify_connect ( struct torrent *torrent,
			     struct sockaddr_tcpip *st_peer,
			     struct sockaddr_tcpip *st_local,
			     struct tcp_header *tcphdr ) {
	int rc;

	struct torrent_client *client;
	list_for_each_entry ( client, &torrent->clients_disconnected,
			      conn_state )
		if ( client->type == &bt_client_type &&
		     tcpip_sock_compare ( &client->addr, st_peer ) )
			goto found_client;

	if ( ( client = ( struct torrent_client * )btclient_create (
		   torrent, ( struct sockaddr * )st_peer, &rc ) ) == NULL )
		return rc;

	torrent_client_register ( torrent, client );

found_client:
	return btclient_accept ( ( struct bt_client * ) client,
				 st_peer, st_local, tcphdr );
}

/** Torrent data transfer interface operations */
static struct interface_operation torrent_listen_operations[] = {
	INTF_OP ( tcp_notify_connect, struct torrent *, torrent_notify_connect ),
};

/** Block download data transfer interface descriptor */
static struct interface_descriptor torrent_listen_desc =
	INTF_DESC ( struct torrent, server, torrent_listen_operations );

static void torrent_announce_expired ( struct retry_timer * timer,
				       int __unused over ) {
        int rc;
	struct torrent * torrent;
	torrent = container_of ( timer, struct torrent, announce_timer );

	if ( ++torrent->announce_retry_count == MAX_ANNOUNCE_RETRY_COUNT ) {
		torrent_finalize_close ( torrent );
		return;
	}

	if ( ( rc = torrent_announce ( torrent ) ) != 0 ) {
		DBGC ( torrent, "TORRENT %p announce failed: %s\n",
		       torrent, strerror ( rc ) );
		goto err_announce;
	}

	return;

err_announce:
	torrent_close ( torrent, rc );
}


/**
 * Initiate a BitTorrent download
 *
 * @v xfer		Data transfer interface
 * @v uri		Uniform Resource Identifier
 * @ret rc		Return status code
 */
static int torrent_open ( struct interface *xfer, struct uri *uri ) {
	struct torrent *torrent;
	int rc;

	DBG ( "TORRENT opening a new torrent\n" );

	torrent = zalloc ( sizeof ( *torrent ) );
	if ( !torrent ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	if ( ( rc = torrent_info_init ( &torrent->info, uri ) ) != 0 )
		goto err_metadata;

	xferbuf_malloc_init ( &torrent->tracker_response );
	ref_init ( &torrent->refcnt, torrent_free );

	intf_init ( &torrent->xfer, &torrent_xfer_desc, &torrent->refcnt );

	intf_init ( &torrent->server, &torrent_listen_desc, &torrent->refcnt );
	intf_init ( &torrent->tracker, &tracker_desc, &torrent->refcnt );

	timer_init ( &torrent->announce_timer, torrent_announce_expired,
		     &torrent->refcnt );

	timer_init ( &torrent->connection_scheduler,
		     torrent_connection_scheduler,
		     &torrent->refcnt );

	timer_init ( &torrent->unchoke_scheduler,
		     torrent_unchoke_scheduler,
		     &torrent->refcnt );

	timer_init ( &torrent->piece_scheduler,
		     torrent_piece_scheduler,
		     &torrent->refcnt );

	timer_init ( &torrent->termination_scheduler,
		     torrent_termination_scheduler,
		     &torrent->refcnt );

	INIT_LIST_HEAD ( &torrent->clients_all );

	INIT_LIST_HEAD ( &torrent->clients_connected );
	INIT_LIST_HEAD ( &torrent->clients_disconnected );
	INIT_LIST_HEAD ( &torrent->clients_tx_inactive );
	INIT_LIST_HEAD ( &torrent->clients_tx_active );
	INIT_LIST_HEAD ( &torrent->clients_unchoke_pending );
	INIT_LIST_HEAD ( &torrent->clients_unchoke_idle );
	INIT_LIST_HEAD ( &torrent->clients_rx_busy );
	INIT_LIST_HEAD ( &torrent->clients_rx_available );

	struct sockaddr_tcpip local_addr;
	memset ( &local_addr, 0, sizeof ( local_addr ) );
        torrent->info.port = 9000;
	local_addr.st_port = htons ( torrent->info.port );
	if ( ( rc = tcp_listen ( &torrent->server,
				 ( struct sockaddr * )&local_addr ) ) )
		goto err_listen;

	intf_plug_plug ( xfer, &torrent->xfer );

	if ( ( rc = torrent_announce ( torrent ) ) != 0 )
		goto err_announce;

	torrent->seed_ratio = 200;
	/* torrent->seed_ratio = -1; */

	return 0;

err_announce:
err_listen:
err_metadata:
err_alloc:
	free ( torrent );
	return rc;
}

void torrent_received_piece ( struct torrent_client *client,
			      struct torrent_piece *piece ) {
	struct torrent * torrent = client->torrent;

	assert ( torrent );
	assert ( piece == client->target );

	unsigned char shabuf[ SHA1_DIGEST_SIZE ];
	size_t piece_len = torrent->info.piece_length;
	size_t piece_begin = piece_len * piece->id;
	torrent_hash_range ( torrent, shabuf, piece_begin,
			     piece_begin + piece->length );

	if ( memcmp ( shabuf, piece->hash, sizeof ( shabuf ) ) != 0 ) {
		DBGC ( client, "TORRENT_CLIENT %p received currupted piece %zd\n",
		       client, piece->id );
		bitset_clear ( &piece->block_state );
		list_del ( &piece->list );
		list_add_tail ( &piece->list, &torrent->info.pending_pieces );
	} else {
		/** Remove the piece from the busy list and
		    add it to the received bitset */
		list_del ( &piece->list );
		bitset_set ( &torrent->info.received_pieces, piece->id, true );

		struct torrent_client *cur_client;
		list_for_each_entry ( cur_client,
				      &client->torrent->clients_connected,
				      conn_state )
			torrent_client_announce_piece ( cur_client, piece );

		torrent->info.downloaded += piece->length;
	}

	/* put the client back into the available pool */
	client->target = NULL;
	client_set_state ( client, rx_state, rx_available );

	/* we need to distribute pieces or stop the torrent if done */
	if ( list_empty ( &torrent->info.pending_pieces ) )
		torrent_schedule ( torrent, termination );
	else
		torrent_schedule ( torrent, piece );
}

void torrent_sent_data ( struct torrent_client * client, size_t size ) {

	struct torrent * torrent = client->torrent;

	torrent->info.downloaded += size;
	/* the torrent may want to stop seeding at some point */
	torrent_schedule ( torrent, piece );
}


/** BitTorrent URI opener */
struct uri_opener bittorrent_uri_opener __uri_opener = {
    .scheme = "torrent",
    .open = torrent_open,
};
