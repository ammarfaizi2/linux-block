/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_NETDEVICE_API_LOCK_H
#define _LINUX_NETDEVICE_API_LOCK_H

#include <linux/smp_api.h>
#include <linux/netdevice_api.h>

#include <linux/jiffies.h>
#include <linux/spinlock_api.h>

static inline void __netif_tx_lock(struct netdev_queue *txq, int cpu)
{
	spin_lock(&txq->_xmit_lock);
	/* Pairs with READ_ONCE() in __dev_queue_xmit() */
	WRITE_ONCE(txq->xmit_lock_owner, cpu);
}

static inline bool __netif_tx_acquire(struct netdev_queue *txq)
{
	__acquire(&txq->_xmit_lock);
	return true;
}

static inline void __netif_tx_release(struct netdev_queue *txq)
{
	__release(&txq->_xmit_lock);
}

static inline void __netif_tx_lock_bh(struct netdev_queue *txq)
{
	spin_lock_bh(&txq->_xmit_lock);
	/* Pairs with READ_ONCE() in __dev_queue_xmit() */
	WRITE_ONCE(txq->xmit_lock_owner, smp_processor_id());
}

static inline bool __netif_tx_trylock(struct netdev_queue *txq)
{
	bool ok = spin_trylock(&txq->_xmit_lock);

	if (likely(ok)) {
		/* Pairs with READ_ONCE() in __dev_queue_xmit() */
		WRITE_ONCE(txq->xmit_lock_owner, smp_processor_id());
	}
	return ok;
}

static inline void __netif_tx_unlock(struct netdev_queue *txq)
{
	/* Pairs with READ_ONCE() in __dev_queue_xmit() */
	WRITE_ONCE(txq->xmit_lock_owner, -1);
	spin_unlock(&txq->_xmit_lock);
}

static inline void __netif_tx_unlock_bh(struct netdev_queue *txq)
{
	/* Pairs with READ_ONCE() in __dev_queue_xmit() */
	WRITE_ONCE(txq->xmit_lock_owner, -1);
	spin_unlock_bh(&txq->_xmit_lock);
}

/*
 * txq->trans_start can be read locklessly from dev_watchdog()
 */
static inline void txq_trans_update(struct netdev_queue *txq)
{
	if (txq->xmit_lock_owner != -1)
		WRITE_ONCE(txq->trans_start, jiffies);
}

static inline void txq_trans_cond_update(struct netdev_queue *txq)
{
	unsigned long now = jiffies;

	if (READ_ONCE(txq->trans_start) != now)
		WRITE_ONCE(txq->trans_start, now);
}

/* legacy drivers only, netdev_start_xmit() sets txq->trans_start */
static inline void netif_trans_update(struct net_device *dev)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);

	txq_trans_cond_update(txq);
}

/**
 *	netif_tx_lock - grab network device transmit lock
 *	@dev: network device
 *
 * Get network device transmit lock
 */
void netif_tx_lock(struct net_device *dev);

static inline void netif_tx_lock_bh(struct net_device *dev)
{
	local_bh_disable();
	netif_tx_lock(dev);
}

void netif_tx_unlock(struct net_device *dev);

static inline void netif_tx_unlock_bh(struct net_device *dev)
{
	netif_tx_unlock(dev);
	local_bh_enable();
}

#define HARD_TX_LOCK(dev, txq, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_lock(txq, cpu);		\
	} else {					\
		__netif_tx_acquire(txq);		\
	}						\
}

#define HARD_TX_TRYLOCK(dev, txq)			\
	(((dev->features & NETIF_F_LLTX) == 0) ?	\
		__netif_tx_trylock(txq) :		\
		__netif_tx_acquire(txq))

#define HARD_TX_UNLOCK(dev, txq) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_unlock(txq);			\
	} else {					\
		__netif_tx_release(txq);		\
	}						\
}

static inline void netif_tx_disable(struct net_device *dev)
{
	unsigned int i;
	int cpu;

	local_bh_disable();
	cpu = smp_processor_id();
	spin_lock(&dev->tx_global_lock);
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		__netif_tx_lock(txq, cpu);
		netif_tx_stop_queue(txq);
		__netif_tx_unlock(txq);
	}
	spin_unlock(&dev->tx_global_lock);
	local_bh_enable();
}

static inline void netif_addr_lock(struct net_device *dev)
{
	unsigned char nest_level = 0;

#ifdef CONFIG_LOCKDEP
	nest_level = dev->nested_level;
#endif
	spin_lock_nested(&dev->addr_list_lock, nest_level);
}

static inline void netif_addr_lock_bh(struct net_device *dev)
{
	unsigned char nest_level = 0;

#ifdef CONFIG_LOCKDEP
	nest_level = dev->nested_level;
#endif
	local_bh_disable();
	spin_lock_nested(&dev->addr_list_lock, nest_level);
}

static inline void netif_addr_unlock(struct net_device *dev)
{
	spin_unlock(&dev->addr_list_lock);
}

static inline void netif_addr_unlock_bh(struct net_device *dev)
{
	spin_unlock_bh(&dev->addr_list_lock);
}

static inline netdev_tx_t __netdev_start_xmit(const struct net_device_ops *ops,
					      struct sk_buff *skb, struct net_device *dev,
					      bool more)
{
	__this_cpu_write(softnet_data.xmit.more, more);
	return ops->ndo_start_xmit(skb, dev);
}

static inline netdev_tx_t netdev_start_xmit(struct sk_buff *skb, struct net_device *dev,
					    struct netdev_queue *txq, bool more)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	netdev_tx_t rc;

	rc = __netdev_start_xmit(ops, skb, dev, more);
	if (rc == NETDEV_TX_OK)
		txq_trans_update(txq);

	return rc;
}

#endif	/* _LINUX_NETDEVICE_API_LOCK_H */
