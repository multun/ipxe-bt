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
#include <ipxe/fault.h>

#include "tcp_internals.h"

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


/**
 * List of registered TCP connections
 */
static LIST_HEAD ( tcp_conns );

/**
 * List of listening TCP connections
 */
static LIST_HEAD ( tcp_listening_conns );

/* Forward declarations */
static struct process_descriptor tcp_process_desc;
static struct interface_descriptor tcp_xfer_desc;

/** TCP process descriptor */
static struct process_descriptor tcp_process_desc =
	PROC_DESC ( struct tcp_connection, process, tcp_xmit );


/**
 * Identify TCP connection by local port number
 *
 * @v local_port	Local port
 * @ret tcp		TCP connection, or NULL
 */
struct tcp_connection * tcp_demux ( struct sockaddr_tcpip * local,
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
 * Name TCP state
 *
 * @v state		TCP state
 * @ret name		Name of TCP state
 */
const char * tcp_state ( int state ) {
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
 * Shutdown timer expired
 *
 * @v timer		Shutdown timer
 * @v over		Failure indicator
 */
void tcp_wait_expired ( struct retry_timer *timer, int over __unused ) {
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
 * Keepalive timer expired
 *
 * @v timer		Keepalive timer
 * @v over		Failure indicator
 */
void tcp_keepalive_expired ( struct retry_timer *timer, int over __unused ) {
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

/***************************************************************************
 *
 * Open and close
 *
 ***************************************************************************
 */

struct tcp_listening_connection *
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

	if ( tcp_find_listening_connection( port ) )
            return -EADDRINUSE;

        return port;
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
	tcp->tx_timeout = 4 * TICKS_PER_SEC; // TODO: RTFM

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
static void tcp_listening_close ( struct tcp_listening_connection * tcp, int rc ) {
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
void tcp_close ( struct tcp_connection *tcp, int rc ) {
	struct io_buffer *iobuf;

	struct io_buffer *tmp_buf;

	struct tcp_tx_segment *seg;
	struct tcp_tx_segment *tmp_seg;

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
			free_iob ( iobuf );
			pending_put ( &tcp->pending_data );
		}
		assert ( ! is_pending ( &tcp->pending_data ) );

		/* Free all segments */
		list_for_each_entry_safe ( seg, tmp_seg, &tcp->tx_segments, list ) {
			/* No SYN, no ACKed segment */
			assert ( ! tcp_segment_is_acknowledged ( seg ) );
			list_del ( &seg->queue_list );
			list_del ( &seg->list );
			free ( seg );
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
