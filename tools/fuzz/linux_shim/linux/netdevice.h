/* SPDX-License-Identifier: ISC */
/* Declarations only: the harness never touches netdev functions. */
#include "linux_shim.h"
struct net_device;
struct sk_buff;
enum netdev_tx_t { NETDEV_TX_OK = 0x00, NETDEV_TX_BUSY = 0x10 };
typedef enum netdev_tx_t netdev_tx_t;
