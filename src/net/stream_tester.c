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
#include <ipxe/xfer.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ipxe/in.h>
#include <ipxe/open.h>
#include <ipxe/socket.h>
#include <ipxe/tcp.h>
#include <ipxe/tcpip.h>
#include <ipxe/uri.h>
#include <ipxe/xfer.h>


struct stream_tester {
	/** Reference count */
	struct refcnt refcnt;

	unsigned char rx_cycle;
	unsigned char tx_cycle;
	struct interface xfer;
	struct interface remote;

	size_t tx_remaining;
};

static void stream_tester_close ( struct stream_tester *stream_tester, int rc ) {
	DBGC ( stream_tester, "STREAM_TESTER %p completed (%s)\n", stream_tester,
	       strerror ( rc ) );

	intf_shutdown ( &stream_tester->remote, rc );
	intf_shutdown ( &stream_tester->xfer, rc );
}

static int stream_tester_deliver ( struct stream_tester *stream_tester,
                                   struct io_buffer *iobuf,
                                   struct xfer_metadata *meta __unused ) {
	int rc;

	unsigned char *buf_beg = iobuf->data;
	unsigned char *buf_end = iobuf->tail;

	for ( ; buf_beg < buf_end; buf_beg++ )
		if ( *buf_beg != stream_tester->rx_cycle++ ) {
			rc = -EINVAL;
			stream_tester_close ( stream_tester, rc );
			return rc;
		}

	free_iob ( iobuf );
	return 0;
}

static void stream_tester_finished ( struct stream_tester *stream_tester, int rc ) {
	DBG ( "STREAM_TESTER %p finished with %d (%s)\n", stream_tester, rc,
	      strerror ( rc ) );
	stream_tester_close ( stream_tester, rc );
}


static void stream_tester_tx ( struct stream_tester * tester ) {
	int rc;

	size_t window_size = xfer_window ( &tester->remote );

	DBG ( "STREAM_TESTER %p window changed: %zd\n", tester, window_size );

	if ( ! window_size )
		return;

	const size_t max_size = tester->tx_remaining;
	size_t alloc_size = window_size;
	if ( alloc_size > max_size )
		alloc_size = max_size;

	struct io_buffer * io_buf = alloc_iob ( alloc_size );
	if ( !io_buf ) {
		DBGC ( tester, "STREAM_TESTER %p couldn't allocate %zd bytes"
		       " buffer\n", tester, alloc_size );

		rc = -ENOBUFS;
		goto err_alloc;
	}

	unsigned char *buf_beg = iob_put ( io_buf, alloc_size );
	unsigned char *buf_end = io_buf->tail;

	for ( ; buf_beg < buf_end; buf_beg++ )
		*buf_beg = tester->tx_cycle++;

	if ( ( rc = xfer_deliver_iob ( &tester->remote,
				       iob_disown ( io_buf ) ) ) != 0 )
		goto err_deliver;

	tester->tx_remaining -= alloc_size;

	if ( tester->tx_remaining == 0 ) {
		DBGC ( tester, "STREAM_TESTER %p done transmitting, closing\n",
		       tester );
		stream_tester_close ( tester, 0 );
	}

	return;

err_deliver:
	free_iob ( io_buf );
err_alloc:
	stream_tester_close ( tester, rc );
	return;
}



static struct interface_operation tester_operations[] = {
	INTF_OP ( xfer_window_changed, struct stream_tester *, stream_tester_tx ),
	INTF_OP ( xfer_deliver, struct stream_tester *, stream_tester_deliver ),
	INTF_OP ( intf_close, struct stream_tester *, stream_tester_finished ),
};

static struct interface_descriptor tester_desc =
	INTF_DESC ( struct stream_tester, remote, tester_operations );

/** Job control interface operations */
static struct interface_operation tester_xfer_operations[] = {
	INTF_OP ( intf_close, struct stream_tester *, stream_tester_close ),
};

/** Job control interface operations */
static struct interface_descriptor tester_xfer_desc =
	INTF_DESC ( struct stream_tester, xfer, tester_xfer_operations );

static int stream_tester_open ( struct interface *xfer, struct uri *uri ) {
	struct stream_tester *tester;
	int rc;

	DBG ( "STREAM_TESTER opening a new tester\n" );

	tester = zalloc ( sizeof ( *tester ) );
	if ( !tester ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	ref_init ( &tester->refcnt, NULL );

	tester->tx_remaining = 1000000;

	intf_init ( &tester->xfer, &tester_xfer_desc, &tester->refcnt );
	intf_init ( &tester->remote, &tester_desc, &tester->refcnt );

	struct uri tmp_uri = *uri;
	tmp_uri.scheme = tmp_uri.fragment;
	tmp_uri.fragment = NULL;

	struct uri * new_uri = uri_dup ( &tmp_uri );

	rc = xfer_open_uri ( &tester->remote, new_uri );

        uri_put ( new_uri );

        if ( rc < 0 )
            goto err_open;

	intf_plug_plug ( xfer, &tester->xfer );
        intf_put ( &tester->xfer );
	return 0;

err_open:
	free ( tester );
err_alloc:
	return rc;
}

/** BitStream_Tester URI opener */
struct uri_opener bitstream_tester_uri_opener __uri_opener = {
    .scheme = "stream_tester",
    .open = stream_tester_open,
};
