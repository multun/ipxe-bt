#pragma once

#include <ipxe/interface.h>
#include <ipxe/iobuf.h>
#include <ipxe/refcnt.h>
#include <ipxe/retry.h>
#include <ipxe/socket.h>
#include <ipxe/xfer.h>
#include <ipxe/tcp.h>
#include <ipxe/tcpip.h>

#include <stdbool.h>

#include "bittorrent_proto.h"
#include <ipxe/bitset.h>

struct torrent_info;
struct torrent_piece;
struct torrent_client;

struct torrent_client_operations {
	int ( *connect ) ( struct torrent_client *client );

	int ( *request ) ( struct torrent_client *client,
			   struct torrent_piece *piece );

	int ( *announce_piece ) ( struct torrent_client *client,
				  struct torrent_piece *piece );

	int ( *set_choke ) ( struct torrent_client *client, bool state );

	void ( *close ) ( struct torrent_client *client, int rc );
};

struct torrent_client {
	struct refcnt refcnt;

	struct torrent *torrent;

	struct torrent_client_operations *type;
	struct sockaddr_tcpip addr;

	struct torrent_piece *target;

	struct list_head all_list;

	/* any peer starts out as being disconnected, inactive, busy and
	   unchoke_idle which means its conn_state item will be into the
	   disconnected list, ... */
	struct list_head conn_state;
	struct list_head rx_state;
	struct list_head tx_state;
	struct list_head unchoke_state;

	/* a bitset of the pieces the remote peer has */
	struct bitset remote_pieces;
};

#define client_set_state( Client, State, NewValue ) \
	do { \
		DBGC ( Client, "TORRENT_CLIENT %p changed its " #State \
		       " to " #NewValue "\n", Client ); \
		inline_client_set_state ( \
			&(Client)->State, \
			&(Client)->torrent->clients_ ##NewValue); \
	} while (0)

static inline void inline_client_set_state ( struct list_head *item,
					     struct list_head *destination ) {
	list_del ( item );
	list_add_tail ( item, destination );
}

static inline void torrent_client_unregister ( struct torrent_client *client ) {
	list_del ( &client->all_list );
	list_del ( &client->conn_state );
	list_del ( &client->rx_state );
	list_del ( &client->tx_state );
	list_del ( &client->unchoke_state );

	ref_put ( &client->torrent->refcnt );
        client->torrent = NULL;

	ref_put ( &client->refcnt );
}

static inline void torrent_client_close ( struct torrent_client *client,
					  int rc ) {
	client->type->close ( client, rc );
}

static inline void
torrent_client_announce_piece ( struct torrent_client *client,
				struct torrent_piece *piece ) {
	if ( ! client->type->announce_piece )
		return;

	client->type->announce_piece ( client, piece  );
}

static inline int torrent_client_connect ( struct torrent_client *client ) {
	int rc;
	if ( ( rc = client->type->connect ( client ) ) == 0 )
		client_set_state ( client, conn_state, connected );

	return rc;
}

static inline int torrent_client_set_choke ( struct torrent_client *client, bool state ) {
	int rc;
	if ( ( rc = client->type->set_choke ( client, state ) ) == 0 ) {
		/* if unchoking the client, it isn't waiting to be unchoked
		   anymore */
		if ( state == false )
			client_set_state ( client, unchoke_state,
					   unchoke_idle );
        }

	return rc;
}

static inline void torrent_client_register ( struct torrent *torrent,
					     struct torrent_client *client ) {
	client->torrent = torrent;
	ref_get ( &torrent->refcnt );

	list_add_tail ( &client->all_list, &torrent->clients_all );
	list_add_tail ( &client->tx_state, &torrent->clients_tx_inactive );
	list_add_tail ( &client->rx_state, &torrent->clients_rx_busy );
	list_add_tail ( &client->conn_state, &torrent->clients_disconnected );
	list_add_tail ( &client->unchoke_state, &torrent->clients_unchoke_idle );
	ref_get ( &client->refcnt );
}

static inline void torrent_client_free ( struct torrent_client *client ) {
	bitset_free ( &client->remote_pieces );
}

static inline int
torrent_client_init ( struct torrent *torrent, struct torrent_client *client,
		      void ( *free ) ( struct refcnt *refcnt ),
		      struct sockaddr *addr ) {

	int rc;

	if ( ( rc = bitset_init ( &client->remote_pieces,
				  torrent->info.piece_count ) ) != 0 )
		return rc;

	memcpy ( &client->addr, addr, sizeof ( *addr ) );

	ref_init ( &client->refcnt, free );

	return 0;
}

static inline int torrent_client_request ( struct torrent_client *client,
					   struct torrent_piece *piece ) {
	client_set_state ( client, rx_state, rx_busy );

	assert ( !client->target );
	client->target = piece;

        list_del ( &piece->list );
        list_add_tail ( &piece->list, &client->torrent->info.pending_pieces );
	return client->type->request ( client, piece );
}

extern struct torrent_client_operations bt_client_type;

struct bt_client;

extern struct bt_client *btclient_create ( struct torrent *torrent,
					   struct sockaddr *addr, int *rc );

extern int btclient_accept ( struct bt_client *client,
			     struct sockaddr_tcpip *st_peer,
			     struct sockaddr_tcpip *st_local,
			     struct tcp_header *tcphdr );
