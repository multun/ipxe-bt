#pragma once

#include <ipxe/bencode.h>
#include <ipxe/bitset.h>
#include <ipxe/image.h>
#include <ipxe/interface.h>
#include <ipxe/process.h>
#include <ipxe/retry.h>
#include <ipxe/sha1.h>
#include <ipxe/uri.h>
#include <ipxe/xferbuf.h>
#include <limits.h>
#include <stdbool.h>

#define PEERID_SIZE 20
#define PEERID_PREFIX "IT-"

#define BLOCK_SIZE ( 1 << 14 )
#define ANNOUNCE_INTERVAL ( 2 * 60 * TICKS_PER_SEC )

struct torrent_piece {
	size_t id;

	struct list_head list;

	uint8_t hash[ SHA1_DIGEST_SIZE ];
	size_t length;

	// the index of the last requested block
	size_t block_cursor;

	// a bitset of the state of each individual block
	struct bitset block_state;
};

static inline size_t piece_received_blocks ( struct torrent_piece * piece) {
	return piece->block_state.set_count;
}

static inline size_t piece_block_count ( struct torrent_piece * piece ) {
	return piece->block_state.bit_size;
}

static inline bool piece_ready ( struct torrent_piece * piece ) {
	return piece_block_count ( piece ) == piece_received_blocks ( piece );
}

struct torrent_info {
	struct uri * image_uri;
	struct uri * announce_uri;
	struct image * image;
	struct bdata * tree;
	uint8_t info_hash[ SHA1_DIGEST_SIZE ];
	char peerid[ PEERID_SIZE + 1 ];
	int port;

	/* only validated data is taken into account */
	size_t downloaded;
	size_t uploaded;

	/* all pieces initialy are into the pending_pieces list, move to
	   busy_pieces when a client tries to fetch it, get removed when
	   succeeding, or go back to pending if failing */
	struct list_head pending_pieces;
	struct list_head busy_pieces;

	struct torrent_piece * pieces;
	struct bitset received_pieces;

	size_t piece_count;

	size_t total_length;
	size_t piece_length;
};

struct tracker_metadata {
	size_t interval;
	size_t complete;
	size_t incomplete;
};

#define TORRENT_MAX_CLIENTS 50

struct torrent {
	/** Reference count */
	struct refcnt refcnt;

	/** Used when fetching peers */
	struct interface tracker;
	struct xfer_buffer tracker_response;

	struct interface xfer;
	struct torrent_info info;

	/** Stats sent when announcing */
	struct tracker_metadata tracker_metadata;

	// TODO: update count
	size_t clients_count;

	struct list_head clients_all;

	struct list_head clients_connected;
	struct list_head clients_disconnected;

	/* inactive clients do not accept requests, nor unchoke peers */
	struct list_head clients_tx_inactive;
	struct list_head clients_tx_active;

	/* unchoke_pending clients are waiting for approval */
	struct list_head clients_unchoke_pending;
	struct list_head clients_unchoke_idle;

	/* busy clients are currently downloading a piece */
	struct list_head clients_rx_busy;
	/* available clients are connected and have no allocated piece */
	struct list_head clients_rx_available;

	struct retry_timer connection_scheduler;
	struct retry_timer unchoke_scheduler;
	struct retry_timer piece_scheduler;
	struct retry_timer termination_scheduler;

	struct interface server;
	struct retry_timer announce_timer;
	size_t announce_retry_count;

	/* negative means stop once done, 100 * ratio otherwise */
	int seed_ratio;

	/* Used to change what kind of announce would be sent to the tracker */
	enum torrent_state {
		TORRENT_STARTING = 0,
		TORRENT_RUNNING,
		TORRENT_STOPPING,
	} state;

	int rc;
};

static inline size_t
piece_block_size ( struct torrent_piece * piece, size_t block_id ) {
       size_t rest = piece->length - BLOCK_SIZE * block_id;
       return rest < BLOCK_SIZE ? rest : BLOCK_SIZE;
}

void torrent_info_free ( struct torrent_info * info );
int torrent_info_init ( struct torrent_info * info, struct uri * uri );
struct uri * torrent_announce_uri ( struct torrent_info * info,
				    enum torrent_state state );

void torrent_step ( struct torrent * torrent );

#define torrent_schedule( Torrent, Component )                                 \
	start_timer_nodelay ( &( Torrent )->Component ## _scheduler )

struct torrent_client;

// shall not drop refs to any client, as it's meant to be called from these
void torrent_received_piece ( struct torrent_client * client,
			      struct torrent_piece * piece );

void torrent_sent_data ( struct torrent_client * client, size_t size );
