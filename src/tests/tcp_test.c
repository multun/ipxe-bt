#include <errno.h>
#include <ipxe/device.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/linux.h>
#include <ipxe/list.h>
#include <ipxe/malloc.h>
#include <ipxe/netdevice.h>
#include <ipxe/settings.h>
#include <ipxe/socket.h>
#include <ipxe/test.h>
#include <ipxe/in.h>
#include <ipxe/neighbour.h>
#include <ipxe/ip.h>
#include <ipxe/list.h>
#include <ipxe/tcpip.h>
#include <ipxe/tcp.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/if_ether.h>
#include <ipxe/if_arp.h>
#include <ipxe/process.h>
#include <ipxe/time.h>
#include <linux_api.h>
#include <stdio.h>
#include <string.h>


/** Remove all the linux devices registered in probe() */
static void test_rootdev_remove ( struct root_device *rootdev ) {
	struct device *device;
	struct device *tmp;

	list_for_each_entry_safe ( device, tmp, &rootdev->dev.children,
				   siblings ) {
		list_del ( &device->siblings );
		free ( device );
	}
}

static int test_rootdev_probe ( struct root_device *rootdev __unused ) {
	// test devices are dynamically added
	return 0;
}

static struct root_driver test_root_driver = {
    .probe = test_rootdev_probe,
    .remove = test_rootdev_remove,
};

struct root_device test_root_device __root_device = {
    .dev = {.name = "test"},
    .driver = &test_root_driver,
};

static void test_rootdev_register ( struct device *device ) {
	list_add ( &device->siblings, &test_root_device.dev.children );
	device->parent = &test_root_device.dev;
	INIT_LIST_HEAD ( &device->children );
}

static void test_rootdev_unregister ( struct device *device ) {
	list_del ( &device->siblings );
}

struct mock_nic {
	struct list_head rx_queue;
	int pcap_fd;
};

static int mock_netdev_open ( struct net_device *netdev __unused ) {
	struct mock_nic * nic = netdev->priv;
        nic->pcap_fd = linux_open ( "test.pcap", O_RDWR | O_TRUNC);
        
        struct pcap_hdr_s {
		uint32 magic_number;   /* magic number */
		uint16 version_major;  /* major version number */
		uint16 version_minor;  /* minor version number */
		int32  thiszone;       /* GMT to local correction */
		uint32 sigfigs;        /* accuracy of timestamps */
		uint32 snaplen;        /* max length of captured packets, in octets */
		uint32 network;        /* data link type */
        } global_pcap_header = {
		.magic_number = 0xa1b2c3d4,
		.version_major = 2,
		.version_minor = 4,
		.thiszone = 0,
		.sigfigs = 0,
		.snaplen = 65535,
		.network = 1 /* LINKTYPE_ETHERNET */,
        };

	linux_write ( nic->pcap_fd, &global_pcap_header,
		      sizeof ( global_pcap_header ) );
	return 0;
}

static void mock_netdev_close ( struct net_device *netdev __unused ) {
	struct mock_nic * nic = netdev->priv;
	if ( nic->pcap_fd == -1 )
		linux_close ( nic->pcap_fd );

	// free the metadata block
	test_rootdev_unregister ( netdev->dev );
	free ( netdev->dev );
	netdev_put ( netdev );
}

/**
 * Transmit an ethernet packet.
 *
 * The packet can be written to the TAP device and marked as complete
 * immediately.
 */
static int mock_netdev_transmit ( struct net_device *netdev,
				  struct io_buffer *iobuf ) {
	struct mock_nic *nic = netdev->priv;

	/* Pad and align packet */
	iob_pad ( iobuf, ETH_ZLEN );

	DBGC2 ( nic, "MOCK_DEVICE %p wrote %zd bytes\n", nic,
		iob_len ( iobuf ) );

        struct {
		uint32 ts_sec;         /* timestamp seconds */
		uint32 ts_usec;        /* timestamp microseconds */
		uint32 incl_len;       /* number of octets of packet saved in file */
		uint32 orig_len;       /* actual length of packet */
	} packet_pcap_header = {
		.ts_sec = time_now (),
		.ts_usec = 0,
		.incl_len = iob_len ( iobuf ),
		.orig_len = iob_len ( iobuf ),
	};

	linux_write ( nic->pcap_fd, &packet_pcap_header,
		      sizeof ( packet_pcap_header ) );

	linux_write ( nic->pcap_fd, iobuf->data, iob_len ( iobuf ) );
	// the iobuf now is in netdev->tx_queue, call
        // netdev_tx_complete ( netdev, iobuf );
        // to release it

	return 0;
}

/** Poll for new packets */
static void mock_netdev_poll ( struct net_device *netdev ) {
	struct mock_nic * nic = netdev->priv;
	struct io_buffer *iobuf;

        iobuf = list_first_entry ( &nic->rx_queue, struct io_buffer, list );
	if ( iobuf )
            netdev_rx ( netdev, iobuf );
}

static void mock_netdev_irq ( struct net_device *netdev, int enable ) {
	struct mock_nic *nic = netdev->priv;

	DBGC ( nic, "mock netdev %p irq enable = %d\n", nic, enable );
}

static struct net_device_operations mock_netdev_operations = {
    .open = mock_netdev_open,
    .close = mock_netdev_close,
    .transmit = mock_netdev_transmit,
    .poll = mock_netdev_poll,
    .irq = mock_netdev_irq,
};


static int store_ipv4_setting ( const struct setting *setting,
				struct settings *target,
				struct in_addr *address ) {
	return store_setting ( target, setting, address, sizeof ( *address ) );
}


struct device *create_test_device(const char *device_name) {    
	struct device *device = zalloc ( sizeof ( *device ) );
	if ( !device )
		return NULL;

	snprintf ( device->name, sizeof ( device->name ), "%s", device_name );
	device->desc.bus_type = BUS_TYPE_TEST;
	test_rootdev_register ( device );
        return device;
}

struct net_device *mock_netdev_probe ( const char *device_name,
                                       struct in_addr *netmask,
                                       struct in_addr *address,
                                       struct in_addr *gateway,
                                       uint8_t *ll_addr) {
	struct net_device *netdev;
	struct mock_nic *nic;
        struct device *device;
        struct settings *settings;

	int rc;

	netdev = alloc_etherdev ( sizeof ( *nic ) );
	if ( !netdev )
		return NULL;

	netdev_init ( netdev, &mock_netdev_operations );
	nic = netdev->priv;

	memset ( nic, 0, sizeof ( *nic ) );
	INIT_LIST_HEAD ( &nic->rx_queue );

        if ( ( device = create_test_device(device_name) ) == NULL )
            goto err_device;

	netdev->dev = device;

	memcpy ( &netdev->hw_addr, ll_addr, MAX_LL_ADDR_LEN );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	if ( ( rc = netdev_open ( netdev ) ) )
		goto err_open;

	/* Get network device settings */
	settings = netdev_settings ( netdev );

	if ( ( rc = store_ipv4_setting ( &ip_setting, settings, address ))
             || (rc = store_ipv4_setting ( &netmask_setting, settings, netmask ))
             || ( rc = store_ipv4_setting ( &gateway_setting, settings, gateway )))
            goto err_settings;

	netdev_link_up ( netdev );

	return netdev;
err_open:
err_settings:
	unregister_netdev(netdev);
err_register:
err_device:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	return NULL;
}


struct tcp_tester {
	struct interface remote;
        struct list_head received;
        size_t window_size;
        unsigned closed;
};


static int tcp_tester_deliver ( struct tcp_tester *tester,
                                struct io_buffer *iobuf,
                                struct xfer_metadata *meta __unused ) {
	DBGC ( tester, "TCP_TESTER %p got message\n", tester );
	list_add_tail ( &iobuf->list, &tester->received );
        return 0;
}


static void tcp_tester_finished ( struct tcp_tester *tcp_tester, int rc ) {
	DBG ( "TCP_TESTER %p finished with %d (%s)\n", tcp_tester, rc,
	      strerror ( rc ) );
        tcp_tester->closed = 1;
	intf_shutdown ( &tcp_tester->remote, rc );
}


static void tcp_tester_update_window ( struct tcp_tester * tester ) {
	tester->window_size = xfer_window ( &tester->remote );
}

static struct interface_operation tester_operations[] = {
	INTF_OP ( xfer_window_changed, struct tcp_tester *, tcp_tester_update_window ),
	INTF_OP ( xfer_deliver, struct tcp_tester *, tcp_tester_deliver ),
	INTF_OP ( intf_close, struct tcp_tester *, tcp_tester_finished ),
};

static struct interface_descriptor tester_desc =
	INTF_DESC ( struct tcp_tester, remote, tester_operations );

static void tcp_tester_init ( struct tcp_tester * tester ) {
	memset ( tester, 0, sizeof ( *tester ) );
	intf_init ( &tester->remote, &tester_desc, NULL );
}

static size_t netdev_flush_tx_queue ( struct net_device *ndev ) {
	struct io_buffer *iob;
	struct io_buffer *tmp;
        size_t released = 0;
	list_for_each_entry_safe ( iob, tmp, &ndev->tx_queue, list ) {
		netdev_tx_complete ( ndev, iob );
		released++;
	}

	return released;
}

static struct io_buffer *netdev_pop ( struct net_device *ndev ) {
	struct io_buffer *iobuf;
	struct ethhdr *ethhdr;
	struct arphdr *arphdr;
	uint16_t eth_proto;
	const uint8_t eth_broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

pop_next:
	// step a few times to ensure a SYN gets sent
	for ( size_t i = 0; i < 3; i++ ) {
		step ();
		iobuf = list_first_entry ( &ndev->tx_queue, struct io_buffer,
					   list );
		if ( iobuf )
			break;
	}

	if ( !iobuf )
		return NULL;

	ethhdr = iobuf->data;
	iob_pull ( iobuf, sizeof ( *ethhdr ) );
	list_del ( &iobuf->list );

	eth_proto = htons ( ethhdr->h_protocol );

	if ( eth_proto == ETH_P_IP ) {
		iob_pull ( iobuf, sizeof ( struct iphdr ) );
		struct tcp_header *tcphdr = iobuf->data;
		printf ( "tcp dst: %d\n", ntohs ( tcphdr->dest ) );
		return iobuf;
	}

	if ( eth_proto != ETH_P_ARP ) {
		DBGC ( ndev, "MOCK_NETDEV %p unknown ether type\n", ndev );
		return NULL;
	}

	arphdr = iobuf->data;
	// ignore gratuitous ARP
	if ( memcmp ( arp_sender_pa ( arphdr ), arp_target_pa ( arphdr ),
		      arphdr->ar_pln ) == 0 &&
	     memcmp ( ethhdr->h_dest, eth_broadcast, ETH_ALEN ) == 0 ) {
		DBGC ( ndev, "MOCK_NETDEV %p ignoring gratuitous ARP\n", ndev );
		free_iob ( iobuf );
		goto pop_next;
	}

	DBGC ( ndev, "MOCK_NETDEV %p received an unknown arp packet\n", ndev );
	return NULL;
}


static struct tcp_tester tester;

struct tcp_header *prepare_reponse(struct io_buffer *iobuf) {
    struct tcp_header *tcphdr = iobuf->data;
    struct iphdr *iphdr = iob_push ( iobuf, sizeof ( *iphdr ) );
    struct in_addr ip_tmp;
    ip_tmp = iphdr->src;
    iphdr->src = iphdr->dest;
    iphdr->dest = ip_tmp;

    struct ethhdr *ethhdr = iob_push ( iobuf, sizeof ( *ethhdr ) );
    uint8_t ether_tmp[ETH_ALEN];
    memcpy(ether_tmp, ethhdr->h_source, ETH_ALEN);
    memcpy(ethhdr->h_source, ethhdr->h_dest, ETH_ALEN);
    memcpy(ethhdr->h_dest, ether_tmp, ETH_ALEN);
    return tcphdr;            
}

/**
 * Perform TCP self-tests
 *
 */
static void tcp_test_exec ( void ) {
	struct in_addr netmask;
	struct in_addr address;
	struct in_addr gateway;

        uint8_t ll_addr[MAX_LL_ADDR_LEN];
	memset ( ll_addr, 42, MAX_LL_ADDR_LEN );

	memset ( &address, 1, sizeof ( address ) );
	memset ( &gateway, 2, sizeof ( gateway ) );
	memset ( &netmask, 255, sizeof ( netmask ) );

        // create a virtual network device
	struct net_device *ndev =
	    mock_netdev_probe ( "test", &netmask, &address, &gateway, ll_addr );

        // preseed the ARP table (we don't want to answer ARP by hand)
	neighbour_define ( ndev, &ipv4_protocol, &gateway, ll_addr );

        // initialize a mock endpoint to interact with the TCP
	tcp_tester_init ( &tester );

        struct sockaddr_in peer;
        struct sockaddr_in local;
	memset ( &peer, 0, sizeof ( peer ) );
	memset ( &local, 0, sizeof ( local ) );
	peer.sin_family = AF_INET;
	peer.sin_port = htons ( 42 );
	peer.sin_addr = gateway;

	local.sin_family = AF_INET;
	peer.sin_addr = gateway;

        int rc = xfer_open_socket ( &tester.remote, SOCK_STREAM,
				    ( struct sockaddr * )&peer,
				    ( struct sockaddr * )&local );
        // initialize the tcp connection
	assert ( rc == 0 );

	struct io_buffer *iobuf = netdev_pop ( ndev );
        struct tcp_header *tcphdr __unused = prepare_reponse(iobuf);
        netdev_rx ( ndev, iobuf );

	assert ( netdev_flush_tx_queue ( ndev ) == 0 );

	unregister_netdev ( ndev );
	ok ( 1 );
}

/** TCP self-test */
struct self_test _test __self_test = {
    .name = "tcp",
    .exec = tcp_test_exec,
};
