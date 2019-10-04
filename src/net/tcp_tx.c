#include "tcp_internals.h"

#include <ipxe/xfer.h>
#include <ipxe/fault.h>

/** Transmit profiler */
static struct profiler tcp_tx_profiler __profiler = { .name = "tcp.tx" };


/***************************************************************************
 *
 * Transmit data path
 *
 ***************************************************************************
 */

static uint32_t tcp_segment_seq_len ( uint32_t len, int flags ) {
	if ( flags & ( TCP_SYN | TCP_FIN ) ) {
	        len++;
	}

	return len;
}

/**
 * Calculate transmission window
 *
 * @v tcp		TCP connection
 * @ret len		Maximum length that can be sent in a single packet
 */
size_t tcp_xmit_win ( struct tcp_connection *tcp ) {
	uint32_t win_seq_limit;

	/* Not ready if we're not in a suitable connection state */
	if ( ! TCP_CAN_SEND_DATA ( tcp->tcp_state ) )
		return 0;

	size_t max_win = tcp->snd_win;

        /* Clamp the transmission window to a reasonable size to avoid
         * allocating too much memory.
         */
	if ( max_win > TCP_MAX_TX_WINDOW )
		max_win = TCP_MAX_TX_WINDOW;

	/* Compute the sequence number of the right edge of the window */
	win_seq_limit = tcp->snd_una + max_win;

	/* TODO: The window _shouldn't_ shrink. Either RST or implement proper trimming */
	assert ( tcp_cmp ( tcp->snd_nxt, win_seq_limit ) <= 0 );

	size_t res = win_seq_limit - tcp->snd_nxt;
        /* size_t inflight = tcp_inflight ( tcp ); */

        /* DBGC2(tcp, "TCP %p window announced %zd inflight %zd\n", tcp, res, inflight); */
        return res;
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

void tcp_register_ack ( struct tcp_connection *tcp, uint32_t ack,
			uint32_t sack_left, uint32_t sack_right ) {
	struct tcp_tx_segment * segment;
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
		     tcp_range_in_window ( sack_left, sack_right, seq,
					   seq_end ) ) {
			DBGC2 ( segment, "TCP_SEGMENT %p marked as "
				"acknowledged\n", segment );
			/* Remove the segment from the retransmission queue */
			list_del ( &segment->queue_list );

			/* Mark the segment as acknowledged */
			tcp_segment_mark_acknowledged ( segment );
		}
	}
}

/* sort of duplicate of the retry timer logic, but enables having a single
 * timeout for all segments */
static void tcp_schedule_retransmissions ( struct tcp_connection * tcp ) {
	struct tcp_tx_segment *segment;
	uint32_t now = currticks ();
	uint32_t runtime;

	/* The list of segments awaiting acknowledgement is sorted, oldest
	   segment first */
	while ( ( segment = list_first_entry ( &tcp->tx_ack_pending,
					       struct tcp_tx_segment,
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

                tcp_retransmit_segment ( tcp, segment );
	}
}

/**
 * Transmit any outstanding data
 *
 * @v tcp		TCP connection
 */
void tcp_xmit ( struct tcp_connection *tcp ) {
	/* Transmit without an explicit first SACK */
	tcp_xmit_sack ( tcp, tcp->rcv_ack );
}

/**
 * Send RST response to incoming packet
 *
 * @v in_tcphdr		TCP header of incoming packet
 * @ret rc		Return status code
 */
int tcp_xmit_reset ( struct tcp_connection *tcp,
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
 * Queue processing
 *
 ***************************************************************************
 */

/* TODO: remove this, for debug only */
static inline size_t list_len ( struct list_head *head ) {
	struct list_head *tmp;
	size_t size = 0;

	list_for_each ( tmp, head ) {
		size++;
	}
	return size;
}

void tcp_retransmit_segment ( struct tcp_connection *tcp,
			      struct tcp_tx_segment *segment ) {
	/* Move the segment to the tx queue */
	list_del ( &segment->queue_list );
	list_add ( &segment->queue_list, &tcp->tx_queue );
	DBGC ( tcp, "TCP %p new tx queue size %zd\n", tcp,
	       list_len ( &tcp->tx_queue ) );
}



static void print_queue_size(struct tcp_connection  * tcp ) {
	struct tcp_tx_segment *seg;

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
	struct tcp_tx_segment *segment;
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


/* Free any acknowledged segment and associated buffers */
void tcp_trim_tx_queue ( struct tcp_connection *tcp ) {
	struct tcp_tx_segment *seg;
	struct tcp_tx_segment *next_seg;

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
			      struct tcp_tx_segment *segment ) {
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

	if ( inject_fault ( TCP_TX_FAULT ) ) {
		DBGC ( tcp, "TCP %p >>> Injected transmission fault <<<\n", tcp );
	        free_iob ( iobuf );
		goto segment_transmitted;
	}

	/* Transmit packet */
	if ( ( rc = tcpip_tx ( iobuf, &tcp_protocol, NULL, &tcp->peer, NULL,
			       &tcphdr->csum ) ) != 0 ) {
		DBGC ( tcp, "TCP %p could not transmit %08x..%08x %08x: %s\n",
		       tcp, ntohl ( tcphdr->seq ), tcp->snd_nxt,
		       tcp->rcv_ack, strerror ( rc ) );
		return rc;
	}

	DBGC2 ( segment, "TCP_SEGMENT %p transmitted\n", segment );

segment_transmitted:
	/* Update segment metadata */
	segment->ts = ts;
	segment->transmission_count++;

	profile_stop ( &tcp_tx_profiler );
	return 0;
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
void tcp_xmit_sack ( struct tcp_connection *tcp, uint32_t sack_seq ) {
	struct tcp_tx_segment *segment;
	struct tcp_tx_segment ack_segment;
	size_t win;
	int rc;

        /* Look for candidate retransmissions in the ack_pending queue */
        tcp_schedule_retransmissions ( tcp );

	while ( true ) {
		win = tcp_xmit_win ( tcp );

		if ( win > TCP_PATH_MTU )
			win = TCP_PATH_MTU;

		/* If there's no segment ready to be transmitted, try to make
		 * one */
		if ( TCP_CAN_SEND_DATA ( tcp->tcp_state ) &&
                     list_empty ( &tcp->tx_queue ) ) {
                    if ( ( rc = tcp_prepare_tx_segment ( tcp, win ) ) < 0 )
			/* TODO: do something when preparing the segment fails */
			return;
		}
        
		/* Get the first segment of the tx queue */
		segment = list_first_entry (
		    &tcp->tx_queue, struct tcp_tx_segment, queue_list );

                /* Make a segment out of thin air if needed */
		if ( segment == NULL ) {
			/* Return if there's no ACK required */
			if ( !( tcp->flags & TCP_ACK_PENDING ) )
				return;

			/* Prepare an ACK segment */
			ack_segment = ( struct tcp_tx_segment ){
			    .flags = TCP_FLAGS_SENDING ( tcp->tcp_state ),
			    .seq = tcp->snd_nxt,
			};
			segment = &ack_segment;
		}

		/* Transmit the segment. */
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
