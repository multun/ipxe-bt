#ifndef _TCP_INTERNALS_H
#define _TCP_INTERNALS_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/interface.h>
#include <ipxe/timer.h>
#include <ipxe/iobuf.h>
#include <ipxe/refcnt.h>
#include <ipxe/pending.h>
#include <ipxe/profile.h>
#include <ipxe/process.h>
#include <ipxe/tcpip.h>
#include <ipxe/retry.h>
#include <ipxe/tcp.h>
#include <ipxe/netdevice.h>


/** A pointer to some byte of an io_buffer */
struct iobuf_cursor {
	struct io_buffer *iobuf;
	size_t offset;
};

/** A segment awaiting acknowledgement */
struct tcp_tx_segment {
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
tcp_segment_mark_acknowledged ( struct tcp_tx_segment *segment ) {
        segment->queue_list = ( struct list_head ) { 0 };
}

static inline bool
tcp_segment_is_acknowledged ( struct tcp_tx_segment *segment ) {
	struct list_head *list = &segment->queue_list;

	/* One of the pointers being NULL would denote corruption */
	assert ( ( list->prev == NULL ) == ( list->next == NULL ) );
	return list->prev == NULL && list->next == NULL;
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

	/** The number of duplicate received ACK */
	uint32_t dup_ack_count;

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


static inline size_t tcp_inflight ( struct tcp_connection * conn ) {
	return conn->snd_nxt - conn->snd_una;
}


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

void tcp_xmit_sack ( struct tcp_connection *tcp, uint32_t sack_seq );
int tcp_xmit_reset ( struct tcp_connection *tcp, struct sockaddr_tcpip *st_dest,
		     struct tcp_header *in_tcphdr );
void tcp_xmit ( struct tcp_connection *tcp );
size_t tcp_xfer_window ( struct tcp_connection *tcp );
int tcp_rx_ack ( struct tcp_connection *tcp, uint32_t ack, uint32_t win );
void tcp_keepalive_expired ( struct retry_timer *timer, int over __unused );
struct tcp_connection *tcp_demux ( struct sockaddr_tcpip *local,
				   struct sockaddr_tcpip *peer );
size_t tcp_xmit_win ( struct tcp_connection *tcp );
void tcp_retransmit_segment ( struct tcp_connection *tcp,
			      struct tcp_tx_segment *segment );
void tcp_register_ack ( struct tcp_connection *tcp, uint32_t ack,
			uint32_t sack_left, uint32_t sack_right );
void tcp_trim_tx_queue ( struct tcp_connection *tcp );
const char * tcp_state ( int state );
void tcp_close ( struct tcp_connection *tcp, int rc );
struct tcp_listening_connection * tcp_find_listening_connection ( int port );

#define TCP_FAST_RETRANSMIT_COUNT 3
#define TCP_MAX_TX_WINDOW 32000


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

/**
 * Dump TCP state transition
 *
 * @v tcp		TCP connection
 */
static inline __attribute__ (( always_inline )) void
tcp_dump_state ( struct tcp_connection *tcp ) {

	if ( tcp->tcp_state != tcp->prev_tcp_state ) {
		DBGC ( tcp, "TCP %p transitioned from %s to %s\n", tcp,
		       tcp_state ( tcp->prev_tcp_state ),
		       tcp_state ( tcp->tcp_state ) );
	}
	tcp->prev_tcp_state = tcp->tcp_state;
}

#define TCP_TX_FAULT 2
#define TCP_RX_FAULT 0

#endif /* _TCP_INTERNALS_H */
