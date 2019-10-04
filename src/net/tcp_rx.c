#include "tcp_internals.h"

#include <ipxe/xfer.h>
#include <ipxe/fault.h>

/** Receive profiler */
static struct profiler tcp_rx_profiler __profiler = { .name = "tcp.rx" };

/** Data transfer profiler */
static struct profiler tcp_xfer_profiler __profiler = { .name = "tcp.xfer" };



/**
 * Check data-transfer flow control window
 *
 * @v tcp		TCP connection
 * @ret len		Length of window
 */
size_t tcp_xfer_window ( struct tcp_connection *tcp ) {
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

static int tcp_fast_retransmit ( struct tcp_connection *tcp ) {
	struct tcp_tx_segment *head_segment = list_first_entry (
	    &tcp->tx_ack_pending, struct tcp_tx_segment, queue_list );

	if ( head_segment == NULL ) {
		DBGC ( tcp, "TCP %p no pending data, ignoring fast "
                       "retransmit\n", tcp );
		return 0;
	}

        if (head_segment->seq != tcp->snd_una) {
		DBGC ( tcp, "TCP %p fast retransmit ignored as the edge "
                       "segment is alread queued\n", tcp );
                return 0;
        }

	DBGC ( tcp, "TCP %p fast retransmit %x\n", tcp, tcp->snd_una );
	tcp_retransmit_segment ( tcp, head_segment );
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
int tcp_rx_ack ( struct tcp_connection *tcp, uint32_t ack, uint32_t win ) {
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

        /** Ignore ACKs that don't actually acknowledge any new data.
         * (In particular, do not stop the retransmission timer; this
         * avoids creating a sorceror's apprentice syndrome when a
         * duplicate ACK is received and we still have data in our
         * transmit queue.)
         */

        if (ack_len == 0) {
            /* Increase the duplicate ACK count */
            tcp->dup_ack_count++;
            DBGC ( tcp, "TCP %p received duplicate ACK #%d\n", tcp, tcp->dup_ack_count );
	    if ( tcp->dup_ack_count < TCP_FAST_RETRANSMIT_COUNT )
                return 0;

            tcp->dup_ack_count = 0;
            return tcp_fast_retransmit ( tcp );
	} else {
            /* Move the window forward */
            tcp->snd_una = ack;

            /* Reset the duplicate ACK count */
            tcp->dup_ack_count = 0;
        }

	/* TODO: it might be ok to stop the transmission process */

	/* Determine acknowledged flags and data length */
	len = ack_len;
	acked_flags = ( TCP_FLAGS_SENDING ( tcp->tcp_state ) &
			( TCP_SYN | TCP_FIN ) );
	if ( acked_flags ) {
		len--;
		pending_put ( &tcp->pending_flags );
	}

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

	if ( inject_fault ( TCP_RX_FAULT ) ) {
		DBG ( "TCP >>> Injected RX fault <<<.\n" );
		rc = 0;
		goto discard;
	}

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
	if ( tcp == NULL ) {
		/* Listening connections start with a syn*/
		if ( !( flags & TCP_SYN ) || ( flags & TCP_ACK ) ) {
			rc = -ENOTCONN;
			goto discard;
		}

                /* Update the sequence number for future messages */
		tcphdr->seq = htonl ( seq + seq_len );

                /* Find a listening connection */
		struct tcp_listening_connection *listening_conn =
                    tcp_find_listening_connection ( ntohs ( tcphdr->dest ) );
		if ( listening_conn == NULL ) {
			rc = -ENOTCONN;
			tcp_xmit_reset ( tcp, st_src, tcphdr );
                        goto discard;
                }

                /* Notify the listener about the connection attempt */
		if ( ( rc = tcp_notify_connect ( &listening_conn->xfer,
                                                 st_src, st_dest,
                                                 tcphdr ) ) != 0 )
			tcp_xmit_reset ( tcp, st_src, tcphdr );

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
