#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/timer.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/init.h>
#include <ipxe/retry.h>
#include <ipxe/refcnt.h>
#include <ipxe/pending.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/netdevice.h>
#include <ipxe/profile.h>
#include <ipxe/process.h>
#include <ipxe/tcpip.h>
#include <ipxe/tcp.h>

/** @file
 *
 * TCP protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @page tcp_implementation TCP Implementation details
 *
 * ipxe's TCP stack supports SACK, timestamps, and is usualy mostly used for
 * receiving data. It means the tx side should be kept minimal unless it needs
 * to be more efficient.
 *
 * Here's what the tx queue looks like:
 *
 * @code
 *
 *   +-------+   +------+    +-------+   +------+
 *   |ACK    |   |ACKed |    |ACK    |   |tx    |                  tx_segments
 *   |pending|   |      |    |pending|   |queued|
 *   +-------+   +------+    +-------+   +------+_
 *   !       \ /         \   !        \  !        '-,   tx_edge
 *   !        !            \ !          \!           '-, !
 *   !        !              !           !              '!
 *   +-----------------+ +---------------------------------------+
 *   |                 | |                                       | tx_data_queue
 *   |                 | |                                       |
 *   +-----------------+ +---------------------------------------+
 *
 * @endcode
 *
 */

/** A pointer to some byte of an io_buffer */
struct iobuf_cursor {
	struct io_buffer *iobuf;
	size_t offset;
};

/** A segment awaiting acknowledgement */
struct tcp_tx_queued_segment {
	/** List of all segments */
	struct list_head list;
	/** Either the tx pending queue, or the ACK pending queue
	    If the segment was acknowledged, this head isn't in any list, and
	    must be NULLed out using tcp_segment_mark_acknowledged */
	struct list_head queue_list;
	/** Data associated with the segment */
	struct iobuf_cursor buffer;
	/** Sequence number of the first byte */
	uint32_t seq;
	/** Data length */
	uint32_t len;

	/** When the segment was last transmitted */
	uint32_t ts;
	/** Number of times the segment was transmitted */
	uint8_t transmission_count;

	/** TCP Flags */
	uint8_t flags;
};

static inline void
tcp_segment_mark_acknowledged ( struct tcp_tx_queued_segment *segment ) {
        segment->queue_list = ( struct list_head ) { 0 };
}

static inline bool
tcp_segment_is_acknowledged ( struct tcp_tx_queued_segment *segment ) {
	struct list_head *list = &segment->queue_list;

	/* One of the pointers being NULL would denote corruption */
	assert ( ( list->prev == NULL ) == ( list->next == NULL ) );
	return list->prev == NULL && list->next == NULL;
}

static uint32_t tcp_segment_seq_len ( uint32_t len, int flags ) {
	if ( flags & ( TCP_SYN | TCP_FIN ) ) {
	        len++;
	}

	return len;
}

/** A TCP connection */
struct tcp_connection {
	/** Reference counter */
	struct refcnt refcnt;
	/** List of TCP connections */
	struct list_head list;

	/** Flags */
	unsigned int flags;

	/** Data transfer interface */
	struct interface xfer;

	/** Remote socket address */
	struct sockaddr_tcpip peer;
	/** Local port */
	unsigned int local_port;
	/** Maximum segment size */
	size_t mss;

	/** Current TCP state */
	unsigned int tcp_state;
	/** Previous TCP state
	 *
	 * Maintained only for debug messages
	 */
	unsigned int prev_tcp_state;
	/** Oldest unacknowledged sequence number
	 *
	 * Equivalent to SND.UNA in RFC 793 terminology
	 */
	uint32_t snd_una;
	/** Maximum sequence number ever sent
	 *
	 * Differs from snd_max when retransmission occurs
	 */
	uint32_t snd_max;
	/** Next sequence number to be sent
	 *
	 * Equivalent to SND.NXT in RFC 793 terminology
	 */
	uint32_t snd_nxt;
	/** Send window
	 *
	 * Equivalent to SND.WND in RFC 793 terminology
	 */
	uint32_t snd_win;
	/** Current acknowledgement number
	 *
	 * Equivalent to RCV.NXT in RFC 793 terminology
	 */
	uint32_t rcv_ack;
	/** Receive window
	 *
	 * Equivalent to RCV.WND in RFC 793 terminology
	 */
	uint32_t rcv_win;
	/** Received timestamp value
	 *
	 * Updated when a packet is received; copied to ts_recent when
	 * the window is advanced.
	 */
	uint32_t ts_val;
	/** Most recent received timestamp that advanced the window
	 *
	 * Equivalent to TS.Recent in RFC 1323 terminology.
	 */
	uint32_t ts_recent;
	/** Send window scale
	 *
	 * Equivalent to Snd.Wind.Scale in RFC 1323 terminology
	 */
	uint8_t snd_win_scale;
	/** Receive window scale
	 *
	 * Equivalent to Rcv.Wind.Scale in RFC 1323 terminology
	 */
	uint8_t rcv_win_scale;

	/** Selective acknowledgement list (in host-endian order) */
	struct tcp_sack_block sack[TCP_SACK_MAX];

	/** Queue of buffers awaiting transmission, referenced by segments */
	struct list_head tx_data_queue;

	/** List of segments within the window */
	struct list_head tx_segments;

	/** Queue of segments awaiting transmission */
	struct list_head tx_queue;

	/** Queue of segments to check for retransmission */
	struct list_head tx_ack_pending;

	/** Pointer to the first unsegmented byte of the tx buffer */
	struct iobuf_cursor tx_unsegmented;

	// TODO: get rid of this, report a window of the size of a segment to the user
	/** Number of unsegmented bytes, needed to report the actual window */
	size_t tx_unsegmented_len;

	/* Queued but not yet acknowledged flags */
	uint8_t tx_queued_flags;

	uint32_t tx_timeout;

	/** Receive queue */
	struct list_head rx_queue;
	/** Transmission process */
	struct process process;
	/** Keepalive timer */
	struct retry_timer keepalive;
	/** Shutdown (TIME_WAIT) timer */
	struct retry_timer wait;

	/** Pending operations for SYN and FIN */
	struct pending_operation pending_flags;
	/** Pending operations for transmit queue */
	struct pending_operation pending_data;
};

static size_t tcp_inflight ( struct tcp_connection * conn ) {
	return conn->snd_nxt - conn->snd_una;
}

/** A TCP connection */
struct tcp_listening_connection {
	/** Reference counter */
	struct refcnt refcnt;
	/** List of listening TCP connections */
	struct list_head list;

	/** Notification transfer interface */
	struct interface xfer;
	/** Local port */
	unsigned int local_port;
};

/** TCP flags */
enum tcp_flags {
	/** TCP data transfer interface has been closed */
	TCP_XFER_CLOSED = 0x0001,
	/** TCP timestamps are enabled */
	TCP_TS_ENABLED = 0x0002,
	/** TCP acknowledgement is pending */
	TCP_ACK_PENDING = 0x0004,
	/** TCP selective acknowledgement is enabled */
	TCP_SACK_ENABLED = 0x0008,
};

/** TCP internal header
 *
 * This is the header that replaces the TCP header for packets
 * enqueued on the receive queue.
 */
struct tcp_rx_queued_header {
	/** SEQ value, in host-endian order
	 *
	 * This represents the SEQ value at the time the packet is
	 * enqueued, and so excludes the SYN, if present.
	 */
	uint32_t seq;
	/** Next SEQ value, in host-endian order */
	uint32_t nxt;
	/** Flags
	 *
	 * Only FIN is valid within this flags byte; all other flags
	 * have already been processed by the time the packet is
	 * enqueued.
	 */
	uint8_t flags;
	/** Reserved */
	uint8_t reserved[3];
};

/**
 * List of registered TCP connections
 */
static LIST_HEAD ( tcp_conns );

static LIST_HEAD ( tcp_listening_conns );

/** Transmit profiler */
static struct profiler tcp_tx_profiler __profiler = { .name = "tcp.tx" };

/** Receive profiler */
static struct profiler tcp_rx_profiler __profiler = { .name = "tcp.rx" };

/** Data transfer profiler */
static struct profiler tcp_xfer_profiler __profiler = { .name = "tcp.xfer" };

/* Forward declarations */
static struct process_descriptor tcp_process_desc;
static struct interface_descriptor tcp_xfer_desc;
static void tcp_keepalive_expired ( struct retry_timer *timer, int over );
static void tcp_wait_expired ( struct retry_timer *timer, int over );
static struct tcp_connection * tcp_demux ( struct sockaddr_tcpip * local,
                                           struct sockaddr_tcpip * peer );
static int tcp_rx_ack ( struct tcp_connection *tcp, uint32_t ack,
			uint32_t win );

/**
 * Name TCP state
 *
 * @v state		TCP state
 * @ret name		Name of TCP state
 */
static inline /* __attribute__ (( always_inline ))  */const char *
tcp_state ( int state ) {
	switch ( state ) {
	case TCP_CLOSED:		return "CLOSED";
	case TCP_SYN_SENT:		return "SYN_SENT";
	case TCP_SYN_RCVD:		return "SYN_RCVD";
	case TCP_ESTABLISHED:		return "ESTABLISHED";
	case TCP_FIN_WAIT_1:		return "FIN_WAIT_1";
	case TCP_FIN_WAIT_2:		return "FIN_WAIT_2";
	case TCP_CLOSING_OR_LAST_ACK:	return "CLOSING/LAST_ACK";
	case TCP_TIME_WAIT:		return "TIME_WAIT";
	case TCP_CLOSE_WAIT:		return "CLOSE_WAIT";
	default:			return "INVALID";
	}
}

/**
 * Dump TCP state transition
 *
 * @v tcp		TCP connection
 */
static inline /* __attribute__ (( always_inline ))  */void
tcp_dump_state ( struct tcp_connection *tcp ) {

	if ( tcp->tcp_state != tcp->prev_tcp_state ) {
		DBGC ( tcp, "TCP %p transitioned from %s to %s\n", tcp,
		       tcp_state ( tcp->prev_tcp_state ),
		       tcp_state ( tcp->tcp_state ) );
	}
	tcp->prev_tcp_state = tcp->tcp_state;
}

/**
 * Dump TCP flags
 *
 * @v flags		TCP flags
 */
static inline __attribute__ (( always_inline )) void
tcp_dump_flags ( struct tcp_connection *tcp, unsigned int flags ) {
	if ( flags & TCP_RST )
		DBGC2 ( tcp, " RST" );
	if ( flags & TCP_SYN )
		DBGC2 ( tcp, " SYN" );
	if ( flags & TCP_PSH )
		DBGC2 ( tcp, " PSH" );
	if ( flags & TCP_FIN )
		DBGC2 ( tcp, " FIN" );
	if ( flags & TCP_ACK )
		DBGC2 ( tcp, " ACK" );
}

/***************************************************************************
 *
 * Open and close
 *
 ***************************************************************************
 */

static struct tcp_listening_connection *
tcp_find_listening_connection ( int port ) {
	struct tcp_listening_connection * tcp_listening;
	list_for_each_entry ( tcp_listening, &tcp_listening_conns, list ) {
		if ( tcp_listening->local_port == ( unsigned int )port )
                    return tcp_listening;
	}

	return NULL;
}

/**
 * Check if local TCP port is available
 *
 * @v port		Local port number
 * @ret port		Local port number, or negative error
 */
static int tcp_port_available ( int port ) {
	struct tcp_connection * tcp;

	list_for_each_entry ( tcp, &tcp_conns, list ) {
		if ( tcp->local_port == ( unsigned int )port )
			return -EADDRINUSE;
	}

	return tcp_find_listening_connection( port ) ? -EADDRINUSE : port;
}

/**
 * Common connection initialization between open and accept
 *
 * @v tcp		Connection to initialize
 * @v xfer		Data transfer interface
 * @v st_peer		Peer socket address
 * @ret rc		Return status code
 */
static int tcp_finalize_open ( struct tcp_connection *tcp,
			       struct interface *xfer,
			       struct sockaddr_tcpip *st_peer ) {
	size_t mtu;
	int rc;

	ref_init ( &tcp->refcnt, NULL );
	intf_init ( &tcp->xfer, &tcp_xfer_desc, &tcp->refcnt );
	process_init_stopped ( &tcp->process, &tcp_process_desc, &tcp->refcnt );
	timer_init ( &tcp->keepalive, tcp_keepalive_expired, &tcp->refcnt );
	timer_init ( &tcp->wait, tcp_wait_expired, &tcp->refcnt );
	tcp->prev_tcp_state = TCP_CLOSED;
	tcp_dump_state ( tcp );
	INIT_LIST_HEAD ( &tcp->tx_segments );
	INIT_LIST_HEAD ( &tcp->tx_queue );
	INIT_LIST_HEAD ( &tcp->tx_data_queue );
	INIT_LIST_HEAD ( &tcp->tx_ack_pending );
	INIT_LIST_HEAD ( &tcp->rx_queue );
	memcpy ( &tcp->peer, st_peer, sizeof ( tcp->peer ) );
	tcp->tx_timeout = TCP_MSL; // TODO: RTFM

	/* Calculate MSS */
	mtu = tcpip_mtu ( &tcp->peer );
	if ( ! mtu ) {
		DBGC ( tcp, "TCP %p has no route to %s\n",
		       tcp, sock_ntoa ( ( struct sockaddr * ) st_peer ) );
		rc = -ENETUNREACH;
		goto err;
	}
	tcp->mss = ( mtu - sizeof ( struct tcp_header ) );

	/* Start sending process to initiate SYN */
        process_add ( &tcp->process );

	/* Add a pending operation for the SYN */
	pending_get ( &tcp->pending_flags );

	/* Attach parent interface, transfer reference to connection
	 * list and return
	 */
	intf_plug_plug ( &tcp->xfer, xfer );
	list_add ( &tcp->list, &tcp_conns );
	return 0;

 err:
	ref_put ( &tcp->refcnt );
	return rc;
}

/**
 * Open a TCP connection
 *
 * @v xfer		Data transfer interface
 * @v peer		Peer socket address
 * @v local		Local socket address, or NULL
 * @ret rc		Return status code
 */
static int tcp_open ( struct interface * xfer, struct sockaddr * peer,
		      struct sockaddr * local ) {
	int rc;
	int port;

	struct tcp_connection * tcp;
	struct sockaddr_tcpip * st_peer = ( struct sockaddr_tcpip * )peer;
	struct sockaddr_tcpip * st_local = ( struct sockaddr_tcpip * )local;

	tcp = zalloc ( sizeof ( *tcp ) );
	if ( ! tcp )
		return -ENOMEM;

	DBGC ( tcp, "TCP %p allocated\n", tcp );

	/* Bind to local port */
	port = tcpip_bind ( st_local, tcp_port_available );
	if ( port < 0 ) {
		rc = port;
		DBGC ( tcp, "TCP %p could not bind: %s\n",
		       tcp, strerror ( rc ) );
		goto err_bind;
	}
	tcp->local_port = port;
	DBGC ( tcp, "TCP %p bound to port %d\n", tcp, tcp->local_port );

	tcp->snd_nxt = random ();
	tcp->snd_una = tcp->snd_nxt;

	tcp->tcp_state = TCP_SYN_SENT;

	return tcp_finalize_open ( tcp, xfer, st_peer );

err_bind:
	free ( tcp );
	return rc;
}

/**
 * Accept a TCP connection
 *
 * @v xfer		Data transfer interface
 * @v st_peer		Peer socket address
 * @v st_local		Local socket address
 * @v tcphdr		Header of the incoming request
 * @ret rc		Return status code
 */
int tcp_accept ( struct interface * xfer,
		 struct sockaddr_tcpip * st_peer,
		 struct sockaddr_tcpip * st_local,
		 struct tcp_header * tcphdr ) {
	struct tcp_connection * tcp;

	tcp = zalloc ( sizeof ( *tcp ) );
	if ( ! tcp )
		return -ENOMEM;

	DBGC ( tcp, "TCP %p allocated\n", tcp );

	tcp->local_port = ntohs ( st_local->st_port );
	tcp->rcv_ack = ntohl ( tcphdr->seq );
	tcp->tcp_state = TCP_SYN_RCVD;

	return tcp_finalize_open ( tcp, xfer, st_peer );
}

/**
 * Close a listening connection
 *
 * @v tcp		Connection
 * @v rc		Close status code
 */
void tcp_listening_close ( struct tcp_listening_connection * tcp, int rc ) {
	/* Close notification interface */
	intf_close ( &tcp->xfer, rc );

	/* Stop listening */
	list_del ( &tcp->list );
}

static struct interface_operation tcp_listening_operations[] = {
	INTF_OP ( intf_close, struct tcp_listening_connection *,
		  tcp_listening_close ),
};

static struct interface_descriptor tcp_listening_desc =
	INTF_DESC ( struct tcp_listening_connection, xfer,
		    tcp_listening_operations );


/**
 * Listen for incoming TCP connections
 *
 * @v xfer		Attempt notification interface
 * @v local		Local socket address
 * @ret rc		Return status code
 */
int tcp_listen ( struct interface * xfer, struct sockaddr * local ) {
	struct tcp_listening_connection * tcp;
	int port;
	int rc;

	/* Allocate and initialise structure */
	tcp = zalloc ( sizeof ( *tcp ) );
	if ( ! tcp )
		return -ENOMEM;

	DBGC ( tcp, "listening TCP %p allocated\n", tcp );
	ref_init ( &tcp->refcnt, NULL );

	intf_init ( &tcp->xfer, &tcp_listening_desc, &tcp->refcnt );

	/* Bind to local port */
	port = tcpip_bind ( ( struct sockaddr_tcpip * )local, tcp_port_available );
	if ( port < 0 ) {
		rc = port;
		DBGC ( tcp, "TCP %p could not bind: %s\n",
		       tcp, strerror ( rc ) );
		goto err_bind;
	}
	tcp->local_port = port;
	DBGC ( tcp, "TCP %p bound to port %d\n", tcp, tcp->local_port );

	/* Attach parent interface, transfer reference to connection
	 * list and return
	 */
	intf_plug_plug ( &tcp->xfer, xfer );
	list_add ( &tcp->list, &tcp_listening_conns );
	return 0;

 err_bind:
	ref_put ( &tcp->refcnt );
	return rc;
}

/**
 * Close TCP connection
 *
 * @v tcp		TCP connection
 * @v rc		Reason for close
 *
 * Closes the data transfer interface.  If the TCP state machine is in
 * a suitable state, the connection will be deleted.
 */
static void tcp_close ( struct tcp_connection *tcp, int rc ) {
	struct io_buffer *iobuf;
	struct io_buffer *tmp_buf;

	struct tcp_tx_queued_segment *seg;
	struct tcp_tx_queued_segment *tmp_seg;

	/* Close data transfer interface */
	intf_shutdown ( &tcp->xfer, rc );
	tcp->flags |= TCP_XFER_CLOSED;

	/* If we are in CLOSED, or have otherwise not yet received a
	 * SYN (i.e. we are in LISTEN or SYN_SENT), just delete the
	 * connection.
	 */
	if ( ! ( tcp->tcp_state & TCP_STATE_RCVD ( TCP_SYN ) ) ) {

		/* Transition to CLOSED for the sake of debugging messages */
		tcp->tcp_state = TCP_CLOSED;
		tcp_dump_state ( tcp );

		/* Free any unprocessed I/O buffers */
		list_for_each_entry_safe ( iobuf, tmp_buf,
                                           &tcp->rx_queue, list ) {
			list_del ( &iobuf->list );
			free_iob ( iobuf );
		}

		/* Free any unsent I/O buffers */
		list_for_each_entry_safe ( iobuf, tmp_buf, &tcp->tx_data_queue, list ) {
			list_del ( &iobuf->list );
			/* free_iob ( iobuf ); */ // TODO: remove debug
			pending_put ( &tcp->pending_data );
		}
		assert ( ! is_pending ( &tcp->pending_data ) );

		/* Free all segments */
		list_for_each_entry_safe ( seg, tmp_seg, &tcp->tx_segments, list ) {
			/* No SYN, no ACKed segment */
			assert ( ! tcp_segment_is_acknowledged ( seg ) );
			list_del ( &seg->queue_list );
			list_del ( &seg->list );
			/* free ( seg ); */ // TODO: remove debug
		}

		/* Remove pending operations for SYN and FIN, if applicable */
		pending_put ( &tcp->pending_flags );
		pending_put ( &tcp->pending_flags );

		/* Remove from list and drop reference */
		process_del ( &tcp->process );
		stop_timer ( &tcp->keepalive );
		stop_timer ( &tcp->wait );
		list_del ( &tcp->list );
		ref_put ( &tcp->refcnt );
		DBGC ( tcp, "TCP %p connection deleted\n", tcp );
		return;
	}

	/* If we have not had our SYN acknowledged (i.e. we are in
	 * SYN_RCVD), pretend that it has been acknowledged so that we
	 * can send a FIN without breaking things.
	 */
	if ( ! ( tcp->tcp_state & TCP_STATE_ACKED ( TCP_SYN ) ) )
		tcp_rx_ack ( tcp, ( tcp->snd_una + 1 ), 0 );

	/* Stop keepalive timer */
	stop_timer ( &tcp->keepalive );

	/* If we have no data remaining to send, start sending FIN */
	if ( list_empty ( &tcp->tx_data_queue ) &&
	     ! ( tcp->tcp_state & TCP_STATE_SENT ( TCP_FIN ) ) ) {

		tcp->tcp_state |= TCP_STATE_SENT ( TCP_FIN );
		tcp_dump_state ( tcp );
		process_add ( &tcp->process );

		/* Add a pending operation for the FIN */
		pending_get ( &tcp->pending_flags );
	}
}

/***************************************************************************
 *
 * Transmit data path
 *
 ***************************************************************************
 */

/**
 * Calculate transmission window
 *
 * @v tcp		TCP connection
 * @ret len		Maximum length that can be sent in a single packet
 */
static size_t tcp_xmit_win ( struct tcp_connection *tcp ) {
	uint32_t win_seq_limit;

	/* Not ready if we're not in a suitable connection state */
	if ( ! TCP_CAN_SEND_DATA ( tcp->tcp_state ) )
		return 0;

	size_t max_win = tcp->snd_win;
	if ( max_win > 32000 )
		max_win = 32000;

	/* Compute the sequence number of the right edge of the window */
	win_seq_limit = tcp->snd_una + max_win;

	/* TODO: The window _shouldn't_ shrink. Either RST or implement proper trimming */
	assert ( tcp_cmp ( tcp->snd_nxt, win_seq_limit ) <= 0 );

	size_t res = win_seq_limit - tcp->snd_nxt;
        size_t inflight = tcp_inflight ( tcp );

        DBGC2(tcp, "TCP %p window announced %zd inflight %zd\n", tcp, res, inflight);
        return res;

}

/**
 * Check data-transfer flow control window
 *
 * @v tcp		TCP connection
 * @ret len		Length of window
 */
static size_t tcp_xfer_window ( struct tcp_connection *tcp ) {
	/* Not ready if data queue is non-empty.  This imposes a limit
	 * of only one unACKed packet in the TX queue at any time; we
	 * do this to conserve memory usage.
	 */
	/* if ( ! list_empty ( &tcp->tx_queue ) ) */
	/* 	return 0; */

	uint32_t win = tcp_xmit_win ( tcp );
	uint32_t queued = tcp->tx_unsegmented_len;
	if ( queued > win )
		return 0;

	return win - queued;
}

/**
 * Find selective acknowledgement block
 *
 * @v tcp		TCP connection
 * @v seq		SEQ value in SACK block (in host-endian order)
 * @v sack		SACK block to fill in (in host-endian order)
 * @ret len		Length of SACK block
 */
static uint32_t tcp_sack_block ( struct tcp_connection *tcp, uint32_t seq,
				 struct tcp_sack_block *sack ) {
	struct io_buffer *iobuf;
	struct tcp_rx_queued_header *tcpqhdr;
	uint32_t left = tcp->rcv_ack;
	uint32_t right = left;

	/* Find highest block which does not start after SEQ */
	list_for_each_entry ( iobuf, &tcp->rx_queue, list ) {
		tcpqhdr = iobuf->data;
		if ( tcp_cmp ( tcpqhdr->seq, right ) > 0 ) {
			if ( tcp_cmp ( tcpqhdr->seq, seq ) > 0 )
				break;
			left = tcpqhdr->seq;
		}
		if ( tcp_cmp ( tcpqhdr->nxt, right ) > 0 )
			right = tcpqhdr->nxt;
	}

	/* Fail if this block does not contain SEQ */
	if ( tcp_cmp ( right, seq ) < 0 )
		return 0;

	/* Populate SACK block */
	sack->left = left;
	sack->right = right;
	return ( right - left );
}

/**
 * Update TCP selective acknowledgement list
 *
 * @v tcp		TCP connection
 * @v seq		SEQ value in first SACK block (in host-endian order)
 * @ret count		Number of SACK blocks
 */
static unsigned int tcp_sack ( struct tcp_connection *tcp, uint32_t seq ) {
	struct tcp_sack_block sack[TCP_SACK_MAX];
	unsigned int old = 0;
	unsigned int new = 0;
	unsigned int i;
	uint32_t len;

	/* Populate first new SACK block */
	len = tcp_sack_block ( tcp, seq, &sack[0] );
	if ( len )
		new++;

	/* Populate remaining new SACK blocks based on old SACK blocks */
	for ( old = 0 ; old < TCP_SACK_MAX ; old++ ) {

		/* Stop if we run out of space in the new list */
		if ( new == TCP_SACK_MAX )
			break;

		/* Skip empty old SACK blocks */
		if ( tcp->sack[old].left == tcp->sack[old].right )
			continue;

		/* Populate new SACK block */
		len = tcp_sack_block ( tcp, tcp->sack[old].left, &sack[new] );
		if ( len == 0 )
			continue;

		/* Eliminate duplicates */
		for ( i = 0 ; i < new ; i++ ) {
			if ( sack[i].left == sack[new].left ) {
				new--;
				break;
			}
		}
		new++;
	}

	/* Update SACK list */
	memset ( tcp->sack, 0, sizeof ( tcp->sack ) );
	memcpy ( tcp->sack, sack, ( new * sizeof ( tcp->sack[0] ) ) );
	return new;
}

/**
 * Process TCP transmit buffer
 *
 * @v tcp		TCP connection
 * @v cursor		Buffer and offset to start processing from
 * @v max_len		Max amount of data to process
 * @v dest		I/O buffer to fill with data, or NULL
 * @v move_cursor	Whether to move the cursor to the end of processed data
 * @ret len		Length of data processed
 *
 * This copies data from the TCP connection's transmit buffer pointed to by
 * some @c segment.  Data will be copied into the @c dest I/O buffer.
 */
static size_t tcp_process_tx_queue ( struct tcp_connection *tcp,
				      struct iobuf_cursor *cursor,
				      size_t max_len, struct io_buffer *dest,
				      bool move_cursor ) {
	struct io_buffer *iobuf;
	size_t offset;
	size_t frag_len;
	size_t len = 0;

	offset = cursor->offset;
	iobuf = cursor->iobuf;

	list_for_each_entry_continue_at ( iobuf, &tcp->tx_data_queue, list ) {
		frag_len = iob_len ( iobuf );
		assert ( frag_len > offset );
		frag_len -= offset;

		if ( frag_len > max_len )
			frag_len = max_len;

		if ( dest ) {
			memcpy ( iob_put ( dest, frag_len ),
				 ( char * )iobuf->data + offset, frag_len );
		}

		/* Not moving the cursor for each buffer is more complicated,
		 * and requires some more variables. Let's keep it simple */
		if ( move_cursor ) {
			offset += frag_len;
			if ( offset == iob_len ( iobuf ) ) {
				cursor->iobuf = list_next_entry (
				    iobuf, &tcp->tx_data_queue, list );
				cursor->offset = 0;
			} else {
				cursor->iobuf = iobuf;
				cursor->offset = offset;
			}
		}

		/* There can only be an offset on the first block */
		offset = 0;
		len += frag_len;
		max_len -= frag_len;

		if ( max_len == 0 )
			break;
	}

	DBGC2 ( tcp, "TCP %p processed queue%s%s %zd bytes\n", tcp,
		dest ? " copied" : "",
		move_cursor ? " and moved cursor" : "", len );
	return len;
}

/* returns the number of created segments, or a negative error code */
static int tcp_prepare_tx_segment ( struct tcp_connection *tcp,
				    size_t max_len ) {
	struct tcp_tx_queued_segment *segment;
	struct iobuf_cursor previous_edge;
	size_t segment_len = 0;
	size_t seq_len;
	int flags;
	int rc;

	flags = ( TCP_FLAGS_SENDING ( tcp->tcp_state ) &
		  ~tcp->tx_queued_flags );

	/* SYN or FIN consume one byte, and we can never send both */
	assert ( !( ( flags & TCP_SYN ) && ( flags & TCP_FIN ) ) );

	/* The previous right edge of the window is the lower
	   limit of the new segment*/
	previous_edge = tcp->tx_unsegmented;

	if ( tcp->tx_unsegmented.iobuf != NULL
	     && TCP_CAN_SEND_DATA ( tcp->tcp_state ) )
		segment_len = tcp_process_tx_queue ( tcp, &tcp->tx_unsegmented,
						     max_len, NULL, true );

	seq_len = tcp_segment_seq_len ( segment_len, flags );
	/* No need to queue a retransmissible frame if no sequence space */
	if ( seq_len == 0 )
		return 0;

        DBGC ( tcp, "TCP %p allocated segment\n", tcp );
	segment = zalloc ( sizeof ( *segment ) );
	if ( segment == NULL ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	if ( segment_len ) {
		segment->buffer = previous_edge;
	}
	DBGC2 ( segment, "TCP_SEGMENT %p bound to TCP %p (%p + %zd) #%zd\n",
		segment, tcp, segment->buffer.iobuf, segment->buffer.offset,
		segment_len );
	segment->len = segment_len;
	segment->seq = tcp->snd_nxt;

	tcp->tx_unsegmented_len -= segment_len;

	/* Increase the sequence cursor */
	tcp->snd_nxt += seq_len;

	segment->flags = flags;
	list_add_tail ( &segment->list, &tcp->tx_segments );
	list_add_tail ( &segment->queue_list, &tcp->tx_queue );

	/* Avoid sending these flags again until the packet is ACKed */
	tcp->tx_queued_flags |= flags & ( TCP_SYN | TCP_FIN );

	return 1;

err_alloc:
	tcp->tx_unsegmented = previous_edge;
	return rc;
}

static void tcp_register_ack ( struct tcp_connection * tcp, uint32_t ack,
			       uint32_t sack_left, uint32_t sack_right ) {
	struct tcp_tx_queued_segment * segment;
	uint32_t seq;
	uint32_t seq_end;
	uint32_t seq_len;

	list_for_each_entry ( segment, &tcp->tx_segments, list ) {
		seq = segment->seq;
		seq_len = tcp_segment_seq_len ( segment->len, segment->flags );
		seq_end = seq + seq_len;

		if ( segment->transmission_count == 0 )
			continue;

		if ( tcp_cmp ( ack, seq_end ) >= 0 ||
		     /* TODO: ensure this is ok */
		     ( tcp_cmp ( sack_left, seq ) <= 0 &&
		       tcp_cmp ( sack_right, seq_end ) >= 0 ) ) {
			DBGC2 ( segment, "TCP_SEGMENT %p marked as "
				"acknowledged\n", segment );
			/* Remove the segment from the retransmission queue */
			list_del ( &segment->queue_list );

			/* Mark the segment as acknowledged */
			tcp_segment_mark_acknowledged ( segment );
		}
	}
}

/* TODO: remove this, for debug only */
static inline size_t list_len ( struct list_head *head ) {
	struct list_head *tmp;
	size_t size = 0;

	list_for_each ( tmp, head ) {
		size++;
	}
	return size;
}


static void print_queue_size(struct tcp_connection  * tcp ) {
	struct tcp_tx_queued_segment *seg;

	size_t segment_count = list_len ( &tcp->tx_segments );
	DBGC ( tcp, "TCP %p tx_segments_count %zd\n", tcp, segment_count );
	DBGC ( tcp, "TCP %p tx_data_queue %zd\n", tcp,
	       list_len ( &tcp->tx_data_queue ) );

	size_t queued_size = 0;
	size_t queue_seq_len = 0;
	list_for_each_entry ( seg, &tcp->tx_segments, list ) {
		queued_size += seg->len;
		queue_seq_len += tcp_segment_seq_len ( seg->len, seg->flags );
	}

	DBGC2 ( tcp, "TCP %p queue_size len %zd seq_len %zd expected %zd\n", tcp,
		queued_size, queue_seq_len, tcp_inflight ( tcp ) );
}



/* Free any acknowledged segment and associated buffers */
static void tcp_trim_tx_queue ( struct tcp_connection *tcp ) {
	struct tcp_tx_queued_segment *seg;
	struct tcp_tx_queued_segment *next_seg;

	struct io_buffer *bound_buf;
	struct io_buffer *next_bound_buf;
	struct io_buffer *tmp;

        //print_queue_size(tcp);
	list_for_each_entry_safe ( seg, next_seg, &tcp->tx_segments, list ) {
		if ( ! tcp_segment_is_acknowledged ( seg ) )
			break;

		bound_buf = seg->buffer.iobuf;

		/* next_bound_buf is the next useful buffer, or NULL */
		next_bound_buf =
		    list_is_last_entry ( seg, &tcp->tx_segments, list )
			? tcp->tx_unsegmented.iobuf
			: next_seg->buffer.iobuf;

		/* Free buffers until the next useful buffer is found */
		while ( bound_buf != NULL && bound_buf != next_bound_buf ) {

			tmp = list_next_entry ( bound_buf, &tcp->tx_data_queue,
						list );

			DBGC2 ( seg, "TCP_SEGMENT buffer %p freed\n", bound_buf );

			/* Free the current buffer */
			list_del ( &bound_buf->list );
			free_iob ( bound_buf );
			pending_put ( &tcp->pending_data );

			bound_buf = tmp;
		}

		DBGC2 ( seg, "TCP_SEGMENT %p freed\n", seg );

		/* The segment was acknowledged, so no need to remove it
		   from its tx_queue or tx_ack_pending */

                /* The flags the segment holds were acknowledged */
		tcp->tx_queued_flags &= ~seg->flags;

		/* Remove the segment from tx_segments */
		list_del ( &seg->list );
		/* Free the segment */
		free ( seg );
	}

	print_queue_size ( tcp );
}

static int tcp_xmit_segment ( struct tcp_connection *tcp, uint32_t sack_seq,
			      struct tcp_tx_queued_segment *segment ) {
	struct io_buffer *iobuf;
	struct tcp_header *tcphdr;
	struct tcp_mss_option *mssopt;
	struct tcp_window_scale_padded_option *wsopt;
	struct tcp_timestamp_padded_option *tsopt;
	struct tcp_sack_permitted_padded_option *spopt;
	struct tcp_sack_padded_option *sackopt;
	struct tcp_sack_block *sack;
	void *payload;
	unsigned int flags;
	unsigned int sack_count;
	unsigned int i;
	size_t len;
	size_t sack_len;
	uint32_t seq_len;
	uint32_t max_rcv_win;
	uint32_t max_representable_win;
	uint32_t ts;
	int rc;

	/* Start profiling */
	profile_start ( &tcp_tx_profiler );

	/* Calculate both the actual (payload) and sequence space
	 * lengths that we wish to transmit.
	 */
	len = segment->len;
	seq_len = tcp_segment_seq_len ( len, segment->flags );
	flags = segment->flags;

	/* If we are transmitting anything that requires
	 * acknowledgement (i.e. consumes sequence space), start the
	 * retransmission timer.  Do this before attempting to
	 * allocate the I/O buffer, in case allocation itself fails.
	 */
	/* if ( seq_len ) */
	/* 	start_timer ( &tcp->timer ); */

	/* Allocate I/O buffer */
	iobuf = alloc_iob ( len + TCP_MAX_HEADER_LEN );
	if ( ! iobuf ) {
		DBGC ( tcp, "TCP %p could not allocate iobuf for %08x..%08x "
		       "%08x\n", tcp, tcp->snd_una, ( tcp->snd_una + seq_len ),
		       tcp->rcv_ack );
		return -ENOMEM;
	}
	iob_reserve ( iobuf, TCP_MAX_HEADER_LEN );

	/* Fill data payload from transmit queue */
	if ( segment->len ) {
		tcp_process_tx_queue ( tcp, &segment->buffer, segment->len,
				       iobuf, false );
	}

	/* Expand receive window if possible */
	max_rcv_win = xfer_window ( &tcp->xfer );
	if ( max_rcv_win > TCP_MAX_WINDOW_SIZE )
		max_rcv_win = TCP_MAX_WINDOW_SIZE;
	max_representable_win = ( 0xffff << tcp->rcv_win_scale );
	if ( max_rcv_win > max_representable_win )
		max_rcv_win = max_representable_win;
	max_rcv_win &= ~0x03; /* Keep everything dword-aligned */
	if ( tcp->rcv_win < max_rcv_win )
		tcp->rcv_win = max_rcv_win;

	/* Save the startup time */
	ts = currticks ();

	/* Fill up the TCP header */
	payload = iobuf->data;
	if ( flags & TCP_SYN ) {
		mssopt = iob_push ( iobuf, sizeof ( *mssopt ) );
		mssopt->kind = TCP_OPTION_MSS;
		mssopt->length = sizeof ( *mssopt );
		mssopt->mss = htons ( tcp->mss );
		wsopt = iob_push ( iobuf, sizeof ( *wsopt ) );
		wsopt->nop = TCP_OPTION_NOP;
		wsopt->wsopt.kind = TCP_OPTION_WS;
		wsopt->wsopt.length = sizeof ( wsopt->wsopt );
		wsopt->wsopt.scale = TCP_RX_WINDOW_SCALE;
		spopt = iob_push ( iobuf, sizeof ( *spopt ) );
		memset ( spopt->nop, TCP_OPTION_NOP, sizeof ( spopt->nop ) );
		spopt->spopt.kind = TCP_OPTION_SACK_PERMITTED;
		spopt->spopt.length = sizeof ( spopt->spopt );
	}
	if ( ( flags & TCP_SYN ) || ( tcp->flags & TCP_TS_ENABLED ) ) {
		tsopt = iob_push ( iobuf, sizeof ( *tsopt ) );
		memset ( tsopt->nop, TCP_OPTION_NOP, sizeof ( tsopt->nop ) );
		tsopt->tsopt.kind = TCP_OPTION_TS;
		tsopt->tsopt.length = sizeof ( tsopt->tsopt );
		tsopt->tsopt.tsval = htonl ( ts );
		tsopt->tsopt.tsecr = htonl ( tcp->ts_recent );
	}
	if ( ( tcp->flags & TCP_SACK_ENABLED ) &&
	     ( ! list_empty ( &tcp->rx_queue ) ) &&
	     ( ( sack_count = tcp_sack ( tcp, sack_seq ) ) != 0 ) ) {
		sack_len = ( sack_count * sizeof ( *sack ) );
		sackopt = iob_push ( iobuf, ( sizeof ( *sackopt ) + sack_len ));
		memset ( sackopt->nop, TCP_OPTION_NOP, sizeof ( sackopt->nop ));
		sackopt->sackopt.kind = TCP_OPTION_SACK;
		sackopt->sackopt.length =
			( sizeof ( sackopt->sackopt ) + sack_len );
		sack = ( ( ( void * ) sackopt ) + sizeof ( *sackopt ) );
		for ( i = 0 ; i < sack_count ; i++, sack++ ) {
			sack->left = htonl ( tcp->sack[i].left );
			sack->right = htonl ( tcp->sack[i].right );
		}
	}
	if ( len != 0 )
		flags |= TCP_PSH;
	tcphdr = iob_push ( iobuf, sizeof ( *tcphdr ) );
	memset ( tcphdr, 0, sizeof ( *tcphdr ) );
	tcphdr->src = htons ( tcp->local_port );
	tcphdr->dest = tcp->peer.st_port;
	tcphdr->seq = htonl ( segment ? segment->seq : tcp->snd_nxt );

	tcphdr->ack = htonl ( tcp->rcv_ack );
	tcphdr->hlen = ( ( payload - iobuf->data ) << 2 );
	tcphdr->flags = flags;
	tcphdr->win = htons ( tcp->rcv_win >> tcp->rcv_win_scale );
	tcphdr->csum = tcpip_chksum ( iobuf->data, iob_len ( iobuf ) );

	/* Dump header */
	DBGC2 ( tcp, "TCP %p TX %d->%d %08x..%08x           %08x %4zd",
		tcp, ntohs ( tcphdr->src ), ntohs ( tcphdr->dest ),
		ntohl ( tcphdr->seq ), tcp->snd_nxt,
		ntohl ( tcphdr->ack ), len );
	tcp_dump_flags ( tcp, tcphdr->flags );
	DBGC2 ( tcp, "\n" );

	/* Transmit packet */
	if ( ( rc = tcpip_tx ( iobuf, &tcp_protocol, NULL, &tcp->peer, NULL,
			       &tcphdr->csum ) ) != 0 ) {
		DBGC ( tcp, "TCP %p could not transmit %08x..%08x %08x: %s\n",
		       tcp, ntohl ( tcphdr->seq ), tcp->snd_nxt,
		       tcp->rcv_ack, strerror ( rc ) );
		return rc;
	}

	DBGC2 ( segment, "TCP_SEGMENT %p transmitted\n", segment );

	/* Update segment metadata */
	segment->ts = ts;
	segment->transmission_count++;

	profile_stop ( &tcp_tx_profiler );
	return 0;
}

/* sort of duplicate of the retry timer logic, but enables having a single
 * timeout for all segments */
static void __attribute__((unused)) tcp_schedule_retransmissions ( struct tcp_connection * tcp ) {
	struct tcp_tx_queued_segment *segment;
	uint32_t now = currticks ();
	uint32_t runtime;

	/* The list of segments awaiting acknowledgement is sorted, oldest
	   segment first */
	while ( ( segment = list_first_entry ( &tcp->tx_ack_pending,
					       struct tcp_tx_queued_segment,
					       queue_list ) ) != NULL ) {
		runtime = now - segment->ts;
		if ( runtime < tcp->tx_timeout )
			break;

		/** TODO: backoff timeout */
		/* if ( ++segment->tx_fail_count == 4 ) { */
		/* 	rc = -ETIMEDOUT; */
		/* 	tcp->tcp_state = TCP_CLOSED; */
		/* 	tcp_dump_state ( tcp ); */
		/* 	tcp_close ( tcp, rc ); */
		/* 	return rc; */
		/* } */

		assert ( ( tcp->tcp_state == TCP_SYN_SENT ) ||
			 ( tcp->tcp_state == TCP_SYN_RCVD ) ||
			 ( tcp->tcp_state == TCP_ESTABLISHED ) ||
			 ( tcp->tcp_state == TCP_FIN_WAIT_1 ) ||
			 ( tcp->tcp_state == TCP_CLOSE_WAIT ) ||
			 ( tcp->tcp_state == TCP_CLOSING_OR_LAST_ACK ) );

		DBGC ( tcp, "TCP %p retransmission in %s for %08x..%08x %08x\n", tcp,
		       tcp_state ( tcp->tcp_state ), segment->seq,
		       tcp_segment_seq_len ( segment->seq, segment->flags ),
		       tcp->rcv_ack );

		DBGC ( tcp, "TCP %p former queue size\n", tcp );

		/* Move the segment to the tx queue */
		list_del ( &segment->queue_list );
		list_add ( &segment->queue_list, &tcp->tx_queue );
		DBGC ( tcp, "TCP %p new queue size\n", tcp );
	}
}

/**
 * Transmit any outstanding data (with selective acknowledgement)
 *
 * @v tcp		TCP connection
 * @v sack_seq		SEQ for first selective acknowledgement (if any)
 *
 * Transmits any outstanding data on the connection.
 *
 * Note that even if an error is returned, the retransmission timer
 * will have been started if necessary, and so the stack will
 * eventually attempt to retransmit the failed packet.
 */
static void tcp_xmit_sack ( struct tcp_connection *tcp, uint32_t sack_seq ) {
	struct tcp_tx_queued_segment *segment;
	struct tcp_tx_queued_segment ack_segment;
	size_t win;
	int rc;

	if ( !( tcp->tcp_state & TCP_STATE_RCVD ( TCP_SYN ) ) )
		tcp_schedule_retransmissions ( tcp );

	while ( true ) {
		win = tcp_xmit_win ( tcp );

		if ( win > TCP_PATH_MTU )
			win = TCP_PATH_MTU;

		/* Look for candidate retransmissions in the ack_pending queue
		 */
                // TODO: reenable this
		tcp_schedule_retransmissions ( tcp );

		/* If there's no segment ready to be transmitted, try to make
		 * one */
		if ( list_empty ( &tcp->tx_queue ) &&
		     ( rc = tcp_prepare_tx_segment ( tcp, win ) ) < 0 ) {
			/* Return if something went wrong */
			return;
		}
        
		/* Get the first segment of the tx queue */
		segment = list_first_entry (
		    &tcp->tx_queue, struct tcp_tx_queued_segment, queue_list );

		if ( segment != NULL )
			goto send_segment;

		/* Return if there's no ACK required */
		if ( !( tcp->flags & TCP_ACK_PENDING ) )
			return;

		/* Prepare an ACK segment */
		ack_segment = ( struct tcp_tx_queued_segment ){
		    .flags = TCP_FLAGS_SENDING ( tcp->tcp_state ),
		    .seq = tcp->snd_nxt,
		};
		segment = &ack_segment;

		/* Transmit the segment. */
	send_segment:
		if ( ( rc = tcp_xmit_segment ( tcp, sack_seq, segment ) ) != 0 )
			return;

		/* Clear ACK-pending flag */
		tcp->flags &= ~TCP_ACK_PENDING;

		/* Move the segment to the ACK Pending queue */
		if ( segment != &ack_segment ) {
			list_del ( &segment->queue_list );
			list_add_tail ( &segment->queue_list,
					&tcp->tx_ack_pending );
		}
	}
}

/**
 * Transmit any outstanding data
 *
 * @v tcp		TCP connection
 */
static void tcp_xmit ( struct tcp_connection *tcp ) {
    DBGC ( tcp, "TCP %p window_size %zd\n", tcp, tcp_xmit_win ( tcp ) );
	/* Transmit without an explicit first SACK */
	tcp_xmit_sack ( tcp, tcp->rcv_ack );
}

/** TCP process descriptor */
static struct process_descriptor tcp_process_desc =
	PROC_DESC_ONCE ( struct tcp_connection, process, tcp_xmit );

/**
 * Keepalive timer expired
 *
 * @v timer		Keepalive timer
 * @v over		Failure indicator
 */
static void tcp_keepalive_expired ( struct retry_timer *timer,
				    int over __unused ) {
	struct tcp_connection *tcp =
		container_of ( timer, struct tcp_connection, keepalive );

	DBGC ( tcp, "TCP %p sending keepalive\n", tcp );

	/* Reset keepalive timer */
	start_timer_fixed ( &tcp->keepalive, TCP_KEEPALIVE_DELAY );

	/* Send keepalive.  We do this only to preserve or restore
	 * state in intermediate devices (e.g. firewall NAT tables);
	 * we don't actually care about eliciting a response to verify
	 * that the peer is still alive.  We therefore send just a
	 * pure ACK, to keep our transmit path simple.
	 */
	tcp->flags |= TCP_ACK_PENDING;
	tcp_xmit ( tcp );
}

/**
 * Shutdown timer expired
 *
 * @v timer		Shutdown timer
 * @v over		Failure indicator
 */
static void tcp_wait_expired ( struct retry_timer *timer, int over __unused ) {
	struct tcp_connection *tcp =
		container_of ( timer, struct tcp_connection, wait );

	assert ( tcp->tcp_state == TCP_TIME_WAIT );

	DBGC ( tcp, "TCP %p wait complete in %s for %08x..%08x %08x\n", tcp,
	       tcp_state ( tcp->tcp_state ), tcp->snd_una,
	       tcp->snd_nxt, tcp->rcv_ack );

	tcp->tcp_state = TCP_CLOSED;
	tcp_dump_state ( tcp );
	tcp_close ( tcp, 0 );
}

/**
 * Send RST response to incoming packet
 *
 * @v in_tcphdr		TCP header of incoming packet
 * @ret rc		Return status code
 */
static int tcp_xmit_reset ( struct tcp_connection *tcp,
			    struct sockaddr_tcpip *st_dest,
			    struct tcp_header *in_tcphdr ) {
	struct io_buffer *iobuf;
	struct tcp_header *tcphdr;
	int rc;

	/* Allocate space for dataless TX buffer */
	iobuf = alloc_iob ( TCP_MAX_HEADER_LEN );
	if ( ! iobuf ) {
		DBGC ( tcp, "TCP %p could not allocate iobuf for RST "
		       "%08x..%08x %08x\n", tcp, ntohl ( in_tcphdr->ack ),
		       ntohl ( in_tcphdr->ack ), ntohl ( in_tcphdr->seq ) );
		return -ENOMEM;
	}
	iob_reserve ( iobuf, TCP_MAX_HEADER_LEN );

	/* Construct RST response */
	tcphdr = iob_push ( iobuf, sizeof ( *tcphdr ) );
	memset ( tcphdr, 0, sizeof ( *tcphdr ) );
	tcphdr->src = in_tcphdr->dest;
	tcphdr->dest = in_tcphdr->src;
	tcphdr->seq = in_tcphdr->ack;
	tcphdr->ack = in_tcphdr->seq;
	tcphdr->hlen = ( ( sizeof ( *tcphdr ) / 4 ) << 4 );
	tcphdr->flags = ( TCP_RST | TCP_ACK );
	tcphdr->win = htons ( 0 );
	tcphdr->csum = tcpip_chksum ( iobuf->data, iob_len ( iobuf ) );

	/* Dump header */
	DBGC2 ( tcp, "TCP %p TX %d->%d %08x..%08x           %08x %4d",
		tcp, ntohs ( tcphdr->src ), ntohs ( tcphdr->dest ),
		ntohl ( tcphdr->seq ), ( ntohl ( tcphdr->seq ) ),
		ntohl ( tcphdr->ack ), 0 );
	tcp_dump_flags ( tcp, tcphdr->flags );
	DBGC2 ( tcp, "\n" );

	/* Transmit packet */
	if ( ( rc = tcpip_tx ( iobuf, &tcp_protocol, NULL, st_dest,
			       NULL, &tcphdr->csum ) ) != 0 ) {
		DBGC ( tcp, "TCP %p could not transmit RST %08x..%08x %08x: "
		       "%s\n", tcp, ntohl ( in_tcphdr->ack ),
		       ntohl ( in_tcphdr->ack ), ntohl ( in_tcphdr->seq ),
		       strerror ( rc ) );
		return rc;
	}

	return 0;
}

/***************************************************************************
 *
 * Receive data path
 *
 ***************************************************************************
 */

/**
 * Identify TCP connection by local port number
 *
 * @v local_port	Local port
 * @ret tcp		TCP connection, or NULL
 */
static struct tcp_connection * tcp_demux ( struct sockaddr_tcpip * local,
					   struct sockaddr_tcpip * peer ) {
	struct tcp_connection * tcp;

        uint16_t local_port = ntohs ( local->st_port );

	list_for_each_entry ( tcp, &tcp_conns, list ) {
		if ( tcp->local_port == local_port &&
		     tcpip_sock_compare ( &tcp->peer, peer ) == 0 )
			return tcp;
	}
	return NULL;
}

/**
 * Parse TCP received options
 *
 * @v tcp		TCP connection (may be NULL)
 * @v tcphdr		TCP header
 * @v hlen		TCP header length
 * @v options		Options structure to fill in
 * @ret rc		Return status code
 */
static int tcp_rx_opts ( struct tcp_connection *tcp,
			 const struct tcp_header *tcphdr, size_t hlen,
			 struct tcp_options *options ) {
	const void *data = ( ( ( void * ) tcphdr ) + sizeof ( *tcphdr ) );
	const void *end = ( ( ( void * ) tcphdr ) + hlen );
	const struct tcp_option *option;
	unsigned int kind;
	size_t remaining;
	size_t min;

	/* Sanity check */
	assert ( hlen >= sizeof ( *tcphdr ) );

	/* Parse options */
	memset ( options, 0, sizeof ( *options ) );
	while ( ( remaining = ( end - data ) ) ) {

		/* Extract option code */
		option = data;
		kind = option->kind;

		/* Handle single-byte options */
		if ( kind == TCP_OPTION_END )
			break;
		if ( kind == TCP_OPTION_NOP ) {
			data++;
			continue;
		}

		/* Handle multi-byte options */
		min = sizeof ( *option );
		switch ( kind ) {
		case TCP_OPTION_MSS:
			/* Ignore received MSS */
			break;
		case TCP_OPTION_WS:
			options->wsopt = data;
			min = sizeof ( *options->wsopt );
			break;
		case TCP_OPTION_SACK_PERMITTED:
			options->spopt = data;
			min = sizeof ( *options->spopt );
			break;
		case TCP_OPTION_SACK:
			/* Ignore received SACKs */
			break;
		case TCP_OPTION_TS:
			options->tsopt = data;
			min = sizeof ( *options->tsopt );
			break;
		default:
			DBGC ( tcp, "TCP %p received unknown option %d\n",
			       tcp, kind );
			break;
		}
		if ( remaining < min ) {
			DBGC ( tcp, "TCP %p received truncated option %d\n",
			       tcp, kind );
			return -EINVAL;
		}
		if ( option->length < min ) {
			DBGC ( tcp, "TCP %p received underlength option %d\n",
			       tcp, kind );
			return -EINVAL;
		}
		if ( option->length > remaining ) {
			DBGC ( tcp, "TCP %p received overlength option %d\n",
			       tcp, kind );
			return -EINVAL;
		}
		data += option->length;
	}

	return 0;
}

/**
 * Consume received sequence space
 *
 * @v tcp		TCP connection
 * @v seq_len		Sequence space length to consume
 */
static void tcp_rx_seq ( struct tcp_connection *tcp, uint32_t seq_len ) {
	unsigned int sack;

	/* Sanity check */
	assert ( seq_len > 0 );

	/* Update acknowledgement number */
	tcp->rcv_ack += seq_len;

	/* Update window */
	if ( tcp->rcv_win > seq_len ) {
		tcp->rcv_win -= seq_len;
	} else {
		tcp->rcv_win = 0;
	}

	/* Update timestamp */
	tcp->ts_recent = tcp->ts_val;

	/* Update SACK list */
	for ( sack = 0 ; sack < TCP_SACK_MAX ; sack++ ) {
		if ( tcp->sack[sack].left == tcp->sack[sack].right )
			continue;
		if ( tcp_cmp ( tcp->sack[sack].left, tcp->rcv_ack ) < 0 )
			tcp->sack[sack].left = tcp->rcv_ack;
		if ( tcp_cmp ( tcp->sack[sack].right, tcp->rcv_ack ) < 0 )
			tcp->sack[sack].right = tcp->rcv_ack;
	}

	/* Mark ACK as pending */
	tcp->flags |= TCP_ACK_PENDING;
}

/**
 * Handle TCP received SYN
 *
 * @v tcp		TCP connection
 * @v seq		SEQ value (in host-endian order)
 * @v options		TCP options
 * @ret rc		Return status code
 */
static int tcp_rx_syn ( struct tcp_connection *tcp, uint32_t seq,
			struct tcp_options *options ) {

	/* Synchronise sequence numbers on first SYN */
	if ( ! ( tcp->tcp_state & TCP_STATE_RCVD ( TCP_SYN ) ) ) {
		tcp->rcv_ack = seq;
		if ( options->tsopt )
			tcp->flags |= TCP_TS_ENABLED;
		if ( options->spopt )
			tcp->flags |= TCP_SACK_ENABLED;
		if ( options->wsopt ) {
			tcp->snd_win_scale = options->wsopt->scale;
			tcp->rcv_win_scale = TCP_RX_WINDOW_SCALE;
		}
		DBGC ( tcp, "TCP %p using %stimestamps, %sSACK, TX window "
		       "x%d, RX window x%d\n", tcp,
		       ( ( tcp->flags & TCP_TS_ENABLED ) ? "" : "no " ),
		       ( ( tcp->flags & TCP_SACK_ENABLED ) ? "" : "no " ),
		       ( 1 << tcp->snd_win_scale ),
		       ( 1 << tcp->rcv_win_scale ) );
	}

	/* Ignore duplicate SYN */
	if ( seq != tcp->rcv_ack )
		return 0;

	/* Acknowledge SYN */
	tcp_rx_seq ( tcp, 1 );

	/* Mark SYN as received and start sending ACKs with each packet */
	tcp->tcp_state |= ( TCP_STATE_SENT ( TCP_ACK ) |
			    TCP_STATE_RCVD ( TCP_SYN ) );

	return 0;
}

/**
 * Handle TCP received ACK
 *
 * @v tcp		TCP connection
 * @v ack		ACK value (in host-endian order)
 * @v win		WIN value (in host-endian order)
 * @ret rc		Return status code
 */
static int tcp_rx_ack ( struct tcp_connection *tcp, uint32_t ack,
			uint32_t win ) {
	uint32_t ack_len = ( ack - tcp->snd_una );
	size_t len;
	unsigned int acked_flags;

	/* Check for out-of-range or old duplicate ACKs */
	if ( ack_len > tcp_inflight ( tcp ) ) {
		DBGC ( tcp, "TCP %p received ACK for %08x..%08x, "
		       "sent only %08x..%08x\n", tcp, tcp->snd_una,
		       ( tcp->snd_una + ack_len ), tcp->snd_una,
		       tcp->snd_nxt );

		if ( TCP_HAS_BEEN_ESTABLISHED ( tcp->tcp_state ) ) {
			/* Just ignore what might be old duplicate ACKs */
			return 0;
		} else {
			/* Send RST if an out-of-range ACK is received
			 * on a not-yet-established connection, as per
			 * RFC 793.
			 */
			return -EINVAL;
		}
	}

	/* Update window size */
	tcp->snd_win = win;

	/* Hold off (or start) the keepalive timer, if applicable */
	if ( ! ( tcp->tcp_state & TCP_STATE_SENT ( TCP_FIN ) ) )
		start_timer_fixed ( &tcp->keepalive, TCP_KEEPALIVE_DELAY );

	/* Ignore ACKs that don't actually acknowledge any new data.
	 * (In particular, do not stop the retransmission timer; this
	 * avoids creating a sorceror's apprentice syndrome when a
	 * duplicate ACK is received and we still have data in our
	 * transmit queue.)
	 */
	if ( ack_len == 0 )
		return 0;

	/* TODO: it might be ok to stop the transmission process */

	/* Determine acknowledged flags and data length */
	len = ack_len;
	acked_flags = ( TCP_FLAGS_SENDING ( tcp->tcp_state ) &
			( TCP_SYN | TCP_FIN ) );
	if ( acked_flags ) {
		len--;
		pending_put ( &tcp->pending_flags );
	}

	/* Move the window forward */
	tcp->snd_una = ack;

	/* Remove any acknowledged data from transmit queue */
	tcp_register_ack ( tcp, ack, 0, 0 );
	tcp_trim_tx_queue ( tcp );

	/* Mark SYN/FIN as acknowledged if applicable. */
	if ( acked_flags )
		tcp->tcp_state |= TCP_STATE_ACKED ( acked_flags );

	/* Start sending FIN if we've had all possible data ACKed */
	if ( list_empty ( &tcp->tx_data_queue ) &&
	     ( tcp->flags & TCP_XFER_CLOSED ) &&
	     ! ( tcp->tcp_state & TCP_STATE_SENT ( TCP_FIN ) ) ) {
		tcp->tcp_state |= TCP_STATE_SENT ( TCP_FIN );
		pending_get ( &tcp->pending_flags );
	}

	return 0;
}

/**
 * Handle TCP received data
 *
 * @v tcp		TCP connection
 * @v seq		SEQ value (in host-endian order)
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 *
 * This function takes ownership of the I/O buffer.
 */
static int tcp_rx_data ( struct tcp_connection *tcp, uint32_t seq,
			 struct io_buffer *iobuf ) {
	uint32_t already_rcvd;
	uint32_t len;
	int rc;

	/* Ignore duplicate or out-of-order data */
	already_rcvd = ( tcp->rcv_ack - seq );
	len = iob_len ( iobuf );
	if ( already_rcvd >= len ) {
		free_iob ( iobuf );
		return 0;
	}
	iob_pull ( iobuf, already_rcvd );
	len -= already_rcvd;

	/* Acknowledge new data */
	tcp_rx_seq ( tcp, len );

	/* Deliver data to application */
	profile_start ( &tcp_xfer_profiler );
	if ( ( rc = xfer_deliver_iob ( &tcp->xfer, iobuf ) ) != 0 ) {
		DBGC ( tcp, "TCP %p could not deliver %08x..%08x: %s\n",
		       tcp, seq, ( seq + len ), strerror ( rc ) );
		return rc;
	}
	profile_stop ( &tcp_xfer_profiler );

	return 0;
}

/**
 * Handle TCP received FIN
 *
 * @v tcp		TCP connection
 * @v seq		SEQ value (in host-endian order)
 * @ret rc		Return status code
 */
static int tcp_rx_fin ( struct tcp_connection *tcp, uint32_t seq ) {

	/* Ignore duplicate or out-of-order FIN */
	if ( seq != tcp->rcv_ack )
		return 0;

	/* Acknowledge FIN */
	tcp_rx_seq ( tcp, 1 );

	/* Mark FIN as received */
	tcp->tcp_state |= TCP_STATE_RCVD ( TCP_FIN );

	/* Close connection */
	tcp_close ( tcp, 0 );

	return 0;
}

/**
 * Handle TCP received RST
 *
 * @v tcp		TCP connection
 * @v seq		SEQ value (in host-endian order)
 * @ret rc		Return status code
 */
static int tcp_rx_rst ( struct tcp_connection *tcp, uint32_t seq ) {

	/* Accept RST only if it falls within the window.  If we have
	 * not yet received a SYN, then we have no window to test
	 * against, so fall back to checking that our SYN has been
	 * ACKed.
	 */
	if ( tcp->tcp_state & TCP_STATE_RCVD ( TCP_SYN ) ) {
		if ( ! tcp_in_window ( seq, tcp->rcv_ack, tcp->rcv_win ) )
			return 0;
	} else {
		if ( ! ( tcp->tcp_state & TCP_STATE_ACKED ( TCP_SYN ) ) )
			return 0;
	}

	/* Abort connection */
	tcp->tcp_state = TCP_CLOSED;
	tcp_dump_state ( tcp );
	tcp_close ( tcp, -ECONNRESET );

	DBGC ( tcp, "TCP %p connection reset by peer\n", tcp );
	return -ECONNRESET;
}

/**
 * Enqueue received TCP packet
 *
 * @v tcp		TCP connection
 * @v seq		SEQ value (in host-endian order)
 * @v flags		TCP flags
 * @v iobuf		I/O buffer
 */
static void tcp_rx_enqueue ( struct tcp_connection *tcp, uint32_t seq,
			     uint8_t flags, struct io_buffer *iobuf ) {
	struct tcp_rx_queued_header *tcpqhdr;
	struct io_buffer *queued;
	size_t len;
	uint32_t seq_len;
	uint32_t nxt;

	/* Calculate remaining flags and sequence length.  Note that
	 * SYN, if present, has already been processed by this point.
	 */
	flags &= TCP_FIN;
	len = iob_len ( iobuf );
	seq_len = ( len + ( flags ? 1 : 0 ) );
	nxt = ( seq + seq_len );

	/* Discard immediately (to save memory) if:
	 *
	 * a) we have not yet received a SYN (and so have no defined
	 *    receive window), or
	 * b) the packet lies entirely outside the receive window, or
	 * c) there is no further content to process.
	 */
	if ( ( ! ( tcp->tcp_state & TCP_STATE_RCVD ( TCP_SYN ) ) ) ||
	     ( tcp_cmp ( seq, tcp->rcv_ack + tcp->rcv_win ) >= 0 ) ||
	     ( tcp_cmp ( nxt, tcp->rcv_ack ) < 0 ) ||
	     ( seq_len == 0 ) ) {
		free_iob ( iobuf );
		return;
	}

	/* Add internal header */
	tcpqhdr = iob_push ( iobuf, sizeof ( *tcpqhdr ) );
	tcpqhdr->seq = seq;
	tcpqhdr->nxt = nxt;
	tcpqhdr->flags = flags;

	/* Add to RX queue */
	list_for_each_entry ( queued, &tcp->rx_queue, list ) {
		tcpqhdr = queued->data;
		if ( tcp_cmp ( seq, tcpqhdr->seq ) < 0 )
			break;
	}
	list_add_tail ( &iobuf->list, &queued->list );
}

/**
 * Process receive queue
 *
 * @v tcp		TCP connection
 */
static void tcp_process_rx_queue ( struct tcp_connection *tcp ) {
	struct io_buffer *iobuf;
	struct tcp_rx_queued_header *tcpqhdr;
	uint32_t seq;
	unsigned int flags;
	size_t len;

	/* Process all applicable received buffers.  Note that we
	 * cannot use list_for_each_entry() to iterate over the RX
	 * queue, since tcp_discard() may remove packets from the RX
	 * queue while we are processing.
	 */
	while ( ( iobuf = list_first_entry ( &tcp->rx_queue, struct io_buffer,
					     list ) ) ) {

		/* Stop processing when we hit the first gap */
		tcpqhdr = iobuf->data;
		if ( tcp_cmp ( tcpqhdr->seq, tcp->rcv_ack ) > 0 )
			break;

		/* Strip internal header and remove from RX queue */
		list_del ( &iobuf->list );
		seq = tcpqhdr->seq;
		flags = tcpqhdr->flags;
		iob_pull ( iobuf, sizeof ( *tcpqhdr ) );
		len = iob_len ( iobuf );

		/* Handle new data, if any */
		tcp_rx_data ( tcp, seq, iob_disown ( iobuf ) );
		seq += len;

		/* Handle FIN, if present */
		if ( flags & TCP_FIN ) {
			tcp_rx_fin ( tcp, seq );
			seq++;
		}
	}
}

int tcp_notify_connect ( struct interface *intf, struct sockaddr_tcpip *st_peer,
			 struct sockaddr_tcpip *st_local,
			 struct tcp_header *tcphdr ) {
	int rc;

	struct interface *dest;
	tcp_notify_connect_TYPE ( void * ) *op =
	    intf_get_dest_op ( intf, tcp_notify_connect, &dest );
	void *object = intf_object ( dest );
	size_t len;

	if ( op ) {
		len = op ( object, st_peer, st_local, tcphdr );
	} else {
		rc = -EPIPE;
		goto err;
	}

	intf_put ( dest );
	return len;

err:
	return rc;
}

/**
 * Process received packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v st_src		Partially-filled source address
 * @v st_dest		Partially-filled destination address
 * @v pshdr_csum	Pseudo-header checksum
 * @ret rc		Return status code
  */
static int tcp_rx ( struct io_buffer *iobuf,
		    struct net_device *netdev __unused,
		    struct sockaddr_tcpip *st_src,
		    struct sockaddr_tcpip *st_dest,
		    uint16_t pshdr_csum ) {
	struct tcp_header *tcphdr = iobuf->data;
	struct tcp_connection *tcp;
	struct tcp_options options;
	size_t hlen;
	uint16_t csum;
	uint32_t seq;
	uint32_t ack;
	uint16_t raw_win;
	uint32_t win;
	unsigned int flags;
	size_t len;
	uint32_t seq_len;
	size_t old_xfer_window;
	int rc;

	/* Start profiling */
	profile_start ( &tcp_rx_profiler );

	/* Sanity check packet */
	if ( iob_len ( iobuf ) < sizeof ( *tcphdr ) ) {
		DBG ( "TCP packet too short at %zd bytes (min %zd bytes)\n",
		      iob_len ( iobuf ), sizeof ( *tcphdr ) );
		rc = -EINVAL;
		goto discard;
	}
	hlen = ( ( tcphdr->hlen & TCP_MASK_HLEN ) / 16 ) * 4;
	if ( hlen < sizeof ( *tcphdr ) ) {
		DBG ( "TCP header too short at %zd bytes (min %zd bytes)\n",
		      hlen, sizeof ( *tcphdr ) );
		rc = -EINVAL;
		goto discard;
	}
	if ( hlen > iob_len ( iobuf ) ) {
		DBG ( "TCP header too long at %zd bytes (max %zd bytes)\n",
		      hlen, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto discard;
	}
	csum = tcpip_continue_chksum ( pshdr_csum, iobuf->data,
				       iob_len ( iobuf ) );
	if ( csum != 0 ) {
		DBG ( "TCP checksum incorrect (is %04x including checksum "
		      "field, should be 0000)\n", csum );
		rc = -EINVAL;
		goto discard;
	}

        /* augment the sockaddrs with tcp port numbers */
	st_src->st_port = tcphdr->src;
	st_dest->st_port = tcphdr->dest;

	/* Parse parameters from header and strip header */
	tcp = tcp_demux ( st_dest, st_src );
	seq = ntohl ( tcphdr->seq );
	ack = ntohl ( tcphdr->ack );
	raw_win = ntohs ( tcphdr->win );
	flags = tcphdr->flags;
	if ( ( rc = tcp_rx_opts ( tcp, tcphdr, hlen, &options ) ) != 0 )
		goto discard;
	if ( tcp && options.tsopt )
		tcp->ts_val = ntohl ( options.tsopt->tsval );
	iob_pull ( iobuf, hlen );
	len = iob_len ( iobuf );
	seq_len = ( len + ( ( flags & TCP_SYN ) ? 1 : 0 ) +
		    ( ( flags & TCP_FIN ) ? 1 : 0 ) );

	/* Dump header */
	DBGC2 ( tcp, "TCP %p RX %d<-%d           %08x %08x..%08x %4zd",
		tcp, ntohs ( tcphdr->dest ), ntohs ( tcphdr->src ),
		ntohl ( tcphdr->ack ), ntohl ( tcphdr->seq ),
		( ntohl ( tcphdr->seq ) + seq_len ), len );
	tcp_dump_flags ( tcp, tcphdr->flags );
	DBGC2 ( tcp, "\n" );

	/* If no connection was found, check for listening sockets */
	if ( !tcp ) {

		/* Listening connections start with a syn*/
		if ( !( flags & TCP_SYN ) || ( flags & TCP_ACK ) ) {
			rc = -ENOTCONN;
			goto discard;
		}

		tcphdr->seq = htonl ( seq + seq_len );

		struct tcp_listening_connection *listening_conn;
		listening_conn =
		    tcp_find_listening_connection ( ntohs ( tcphdr->dest ) );

		if ( !listening_conn ) {
			rc = -ENOTCONN;
			tcp_xmit_reset ( tcp, st_src, tcphdr );
		} else if ( ( rc = tcp_notify_connect ( &listening_conn->xfer,
							st_src, st_dest,
							tcphdr ) ) != 0 )
			tcp_xmit_reset ( tcp, st_src, tcphdr );

		/* discard the message anyway */
                goto discard;
	}

	/* Record old data-transfer window */
	old_xfer_window = tcp_xfer_window ( tcp );

	/* Handle ACK, if present */
	if ( flags & TCP_ACK ) {
		win = ( raw_win << tcp->snd_win_scale );
		if ( ( rc = tcp_rx_ack ( tcp, ack, win ) ) != 0 ) {
			tcp_xmit_reset ( tcp, st_src, tcphdr );
			goto discard;
		}
	}

	/* Force an ACK if this packet is out of order */
	if ( ( tcp->tcp_state & TCP_STATE_RCVD ( TCP_SYN ) ) &&
	     ( seq != tcp->rcv_ack ) ) {
		tcp->flags |= TCP_ACK_PENDING;
	}

	/* Handle SYN, if present */
	if ( flags & TCP_SYN ) {
		tcp_rx_syn ( tcp, seq, &options );
		seq++;
	}

	/* Handle RST, if present */
	if ( flags & TCP_RST ) {
		if ( ( rc = tcp_rx_rst ( tcp, seq ) ) != 0 )
			goto discard;
	}

	/* Enqueue received data */
	tcp_rx_enqueue ( tcp, seq, flags, iob_disown ( iobuf ) );

	/* Process receive queue */
	tcp_process_rx_queue ( tcp );

	/* Dump out any state change as a result of the received packet */
	tcp_dump_state ( tcp );

	/* Schedule transmission of ACK (and any pending data).  If we
	 * have received any out-of-order packets (i.e. if the receive
	 * queue remains non-empty after processing) then send the ACK
	 * immediately in order to trigger Fast Retransmission.
	 */
	if ( list_empty ( &tcp->rx_queue ) ) {
		process_add ( &tcp->process );
	} else {
		tcp_xmit_sack ( tcp, seq );
	}

	/* If this packet was the last we expect to receive, set up
	 * timer to expire and cause the connection to be freed.
	 */
	if ( TCP_CLOSED_GRACEFULLY ( tcp->tcp_state ) ) {
		stop_timer ( &tcp->wait );
		start_timer_fixed ( &tcp->wait, ( 2 * TCP_MSL ) );
	}

	/* Notify application if window has changed */
	if ( tcp_xfer_window ( tcp ) != old_xfer_window )
		xfer_window_changed ( &tcp->xfer );

	profile_stop ( &tcp_rx_profiler );
	return 0;

 discard:
	/* Free received packet */
	free_iob ( iobuf );
	return rc;
}

/** TCP protocol */
struct tcpip_protocol tcp_protocol __tcpip_protocol = {
	.name = "TCP",
	.rx = tcp_rx,
	.tcpip_proto = IP_TCP,
};

/**
 * Discard some cached TCP data
 *
 * @ret discarded	Number of cached items discarded
 */
static unsigned int tcp_discard ( void ) {
	struct tcp_connection *tcp;
	struct io_buffer *iobuf;
	unsigned int discarded = 0;

	/* Try to drop one queued RX packet from each connection */
	list_for_each_entry ( tcp, &tcp_conns, list ) {
		list_for_each_entry_reverse ( iobuf, &tcp->rx_queue, list ) {

			/* Remove packet from queue */
			list_del ( &iobuf->list );
			free_iob ( iobuf );

			/* Report discard */
			discarded++;
			break;
		}
	}

	return discarded;
}

/** TCP cache discarder */
struct cache_discarder tcp_discarder __cache_discarder ( CACHE_NORMAL ) = {
	.discard = tcp_discard,
};

/**
 * Find first TCP connection that has not yet been closed
 *
 * @ret tcp		First unclosed connection, or NULL
 */
static struct tcp_connection * tcp_first_unclosed ( void ) {
	struct tcp_connection *tcp;

	/* Find first connection which has not yet been closed */
	list_for_each_entry ( tcp, &tcp_conns, list ) {
		if ( ! ( tcp->flags & TCP_XFER_CLOSED ) )
			return tcp;
	}
	return NULL;
}

/**
 * Find first TCP connection that has not yet finished all operations
 *
 * @ret tcp		First unfinished connection, or NULL
 */
static struct tcp_connection * tcp_first_unfinished ( void ) {
	struct tcp_connection *tcp;

	/* Find first connection which has not yet closed gracefully,
	 * or which still has a pending transmission (e.g. to ACK the
	 * received FIN).
	 */
	list_for_each_entry ( tcp, &tcp_conns, list ) {
		if ( ( ! TCP_CLOSED_GRACEFULLY ( tcp->tcp_state ) ) ||
		     process_running ( &tcp->process ) ) {
			return tcp;
		}
	}
	return NULL;
}

/**
 * Shut down all TCP connections
 *
 */
static void tcp_shutdown ( int booting __unused ) {
	struct tcp_connection *tcp;
	unsigned long start;

	/* Initiate a graceful close of all connections, allowing for
	 * the fact that the connection list may change as we do so.
	 */
	while ( ( tcp = tcp_first_unclosed() ) ) {
		DBGC ( tcp, "TCP %p closing for shutdown\n", tcp );
		tcp_close ( tcp, -ECANCELED );
	}

	/* Wait for all connections to finish closing gracefully */
	start = currticks();
	while ( ( tcp = tcp_first_unfinished() ) != NULL ) {
		if ( ( currticks () - start ) >= TCP_FINISH_TIMEOUT ) {
			DBG ( "Timed out while waiting for TCP %p to "
			      "terminate\n",
			      tcp );
			break;
		}
		step();
	}

	/* Forcibly close any remaining connections */
	while ( ( tcp = list_first_entry ( &tcp_conns, struct tcp_connection,
					   list ) ) != NULL ) {
		tcp->tcp_state = TCP_CLOSED;
		tcp_dump_state ( tcp );
		tcp_close ( tcp, -ECANCELED );
	}
}

/** TCP shutdown function */
struct startup_fn tcp_startup_fn __startup_fn ( STARTUP_LATE ) = {
	.shutdown = tcp_shutdown,
};

/***************************************************************************
 *
 * Data transfer interface
 *
 ***************************************************************************
 */

/**
 * Close interface
 *
 * @v tcp		TCP connection
 * @v rc		Reason for close
 */
static void tcp_xfer_close ( struct tcp_connection *tcp, int rc ) {

	/* Close data transfer interface */
	tcp_close ( tcp, rc );

	/* Transmit FIN, if possible */
	tcp_xmit ( tcp );
}

/**
 * Deliver datagram as I/O buffer
 *
 * @v tcp		TCP connection
 * @v iobuf		Datagram I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int tcp_xfer_deliver ( struct tcp_connection *tcp,
			      struct io_buffer *iobuf,
			      struct xfer_metadata *meta __unused ) {
	/* Delivering zero-sized buffers adds a whole bunch of
	   corner cases for no obvious benefit */
	assert ( iob_len ( iobuf ) != 0 );

	/* Don't let the implementation break if it happens */
	if ( iob_len ( iobuf ) == 0 ) {
		free_iob ( iobuf );
		return 0;
	}

	DBGC2 ( tcp, "TCP %p queueing %p (#%zd)\n", tcp, iobuf,
		iob_len ( iobuf ) );

	/* Enqueue buffer */
	list_add_tail ( &iobuf->list, &tcp->tx_data_queue );

	/* When the tx buffer is empty, it has no edge. Initialize
	   it when it occurs */
	if ( tcp->tx_unsegmented.iobuf == NULL ) {
		tcp->tx_unsegmented.iobuf = iobuf;
		tcp->tx_unsegmented.offset = 0;
	}

	/* Update the count of unsegmented bytes */
	tcp->tx_unsegmented_len += iob_len ( iobuf );

	/* Each enqueued buffer is a pending operation */
	pending_get ( &tcp->pending_data );

	/* Transmit data, if possible */
	tcp_xmit ( tcp );

	return 0;
}

/** TCP data transfer interface operations */
static struct interface_operation tcp_xfer_operations[] = {
	INTF_OP ( xfer_deliver, struct tcp_connection *, tcp_xfer_deliver ),
	INTF_OP ( xfer_window, struct tcp_connection *, tcp_xfer_window ),
	INTF_OP ( intf_close, struct tcp_connection *, tcp_xfer_close ),
};

/** TCP data transfer interface descriptor */
static struct interface_descriptor tcp_xfer_desc =
	INTF_DESC ( struct tcp_connection, xfer, tcp_xfer_operations );

/***************************************************************************
 *
 * Openers
 *
 ***************************************************************************
 */

/** TCP IPv4 socket opener */
struct socket_opener tcp_ipv4_socket_opener __socket_opener = {
	.semantics	= TCP_SOCK_STREAM,
	.family		= AF_INET,
	.open		= tcp_open,
};

/** TCP IPv6 socket opener */
struct socket_opener tcp_ipv6_socket_opener __socket_opener = {
	.semantics	= TCP_SOCK_STREAM,
	.family		= AF_INET6,
	.open		= tcp_open,
};

/** Linkage hack */
int tcp_sock_stream = TCP_SOCK_STREAM;

/**
 * Open TCP URI
 *
 * @v xfer		Data transfer interface
 * @v uri		URI
 * @ret rc		Return status code
 */
static int tcp_open_uri ( struct interface *xfer, struct uri *uri ) {
	struct sockaddr_tcpip peer;

	/* Sanity check */
	if ( ! uri->host )
		return -EINVAL;

	memset ( &peer, 0, sizeof ( peer ) );
	peer.st_port = htons ( uri_port ( uri, 0 ) );
	return xfer_open_named_socket ( xfer, SOCK_STREAM,
					( struct sockaddr * ) &peer,
					uri->host, NULL );
}

/** TCP URI opener */
struct uri_opener tcp_uri_opener __uri_opener = {
	.scheme		= "tcp",
	.open		= tcp_open_uri,
};
