#include <linux/bits.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/of_dma.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/pm_runtime.h>

#include "dmaengine.h"

#define NCHANNELS_MAX	32

#define RING_WRITE_SLOT	GENMASK(1, 0)
#define RING_READ_SLOT	GENMASK(5, 4)

#define RING_FULL  BIT(9)
#define RING_EMPTY BIT(8)
#define RING_ERR   BIT(10)

#define STATUS_DESC_DONE	BIT(0)
#define STATUS_ERR		BIT(6)

#define FLAG_DESC_NOTIFY	BIT(16)

#define REG_TX_EN		0x0000
#define REG_TX_EN_CLR		0x0004
#define REG_CTRL		0x0010
#define REG_TX_INTSTATE1	0x0034

#define REG_TX_CTL(ch)		(0x8000 + (ch)*0x400)
#define REG_TX_CTL_RESET_RINGS	BIT(0)

#define REG_TX_DESC_RING(ch)	(0x8070 + (ch)*0x400)
#define REG_TX_REPORT_RING(ch)	(0x8074 + (ch)*0x400)

#define REG_TX_RESIDUE(ch)	(0x8064 + (ch)*0x400)

#define REG_TX_STATUS1(ch)	(0x8014 + (ch)*0x400)
#define REG_TX_INTMASK1(ch)	(0x8024 + (ch)*0x400)

#define REG_TX_BUS_WIDTH(ch)	(0x8040 + (ch)*0x400)

#define BUS_WIDTH_8BIT		0x00
#define BUS_WIDTH_16BIT		0x01
#define BUS_WIDTH_32BIT		0x02
#define BUS_WIDTH_FRAME_2_WORDS	0x10
#define BUS_WIDTH_FRAME_4_WORDS	0x20

#define REG_TX_DESC_WRITE(ch)	(0x10000 + (ch)*0x4)
#define REG_TX_REPORT_READ(ch)	(0x10100 + (ch)*0x4)


struct admac_data;
struct admac_tx;

struct admac_chan {
	int no;
	struct admac_data *host;
	struct dma_chan chan;
	struct tasklet_struct tasklet;

	spinlock_t lock;
	struct admac_tx *current_tx;
	int nperiod_acks;

	struct list_head submitted;
	struct list_head issued;
};

struct admac_data {
	struct dma_device dma;
	struct device *dev;
	__iomem void *regs;

	int nchannels;
	struct admac_chan channels[];
};

struct admac_tx {
	struct dma_async_tx_descriptor tx;

	bool cyclic;
	dma_addr_t buf_addr;
	dma_addr_t buf_end;
	size_t buf_len;
	size_t period_len;
	size_t submitted_pos;
	size_t reclaimed_pos;

	struct list_head node;
};

static void admac_cyclic_write_desc(struct admac_data *ad, int channo, struct admac_tx *tx);
static void admac_cyclic_write_one_desc(struct admac_data *ad, int channo, struct admac_tx *tx);
static int admac_desc_free(struct dma_async_tx_descriptor *tx);

inline static struct admac_chan *to_admac_chan(struct dma_chan *chan)
{
	return container_of(chan, struct admac_chan, chan);
}

inline static struct admac_tx *to_admac_tx(struct dma_async_tx_descriptor *tx)
{
	return container_of(tx, struct admac_tx, tx);
}

inline static void admac_poke(struct admac_data *data, int regoffset, u32 val)
{
	writel_relaxed(val, data->regs + regoffset);
}

inline static u32 admac_peek(struct admac_data *data, int regoffset)
{
	return readl_relaxed(data->regs + regoffset);
}

inline static void admac_modify(struct admac_data *data, int regoffset, u32 mask, u32 val)
{
	u32 oldval = readl_relaxed(data->regs + regoffset);
	writel_relaxed((oldval & ~mask) | (val & mask), data->regs + regoffset);
}

int admac_alloc_chan_resources(struct dma_chan *chan)
{
	return 0;
}

void admac_free_chan_resources(struct dma_chan *chan)
{
	// TODO
}

int admac_ring_noccupied_slots(int ringval)
{
	int wrslot = FIELD_GET(RING_WRITE_SLOT, ringval);
	int rdslot = FIELD_GET(RING_READ_SLOT, ringval);

	if (wrslot != rdslot) {
		return (wrslot + 4 - rdslot) % 4;
	} else {
		WARN_ON((ringval & (RING_FULL | RING_EMPTY)) == 0);

		if (ringval & RING_FULL)
			return 4;
		else
			return 0;
	}
}

/*
 * Read from hardware the residue of a cyclic dmaengine transaction.
 */
u32 admac_cyclic_read_residue(struct admac_data *ad, int channo, struct admac_tx *adtx)
{
	u32 ring1, ring2;
	u32 residue1, residue2;
	int nreports;
	size_t pos;

	ring1 =    admac_peek(ad, REG_TX_REPORT_RING(channo));
	residue1 = admac_peek(ad, REG_TX_RESIDUE(channo));
	ring2 =    admac_peek(ad, REG_TX_REPORT_RING(channo));
	residue2 = admac_peek(ad, REG_TX_RESIDUE(channo));

	if (residue2 > residue1) {
		// engine must have loaded next descriptor between the two residue reads
		nreports = admac_ring_noccupied_slots(ring1) + 1;
	} else {
		// no descriptor load between the two reads, ring2 is safe to use
		nreports = admac_ring_noccupied_slots(ring2);
	}

	pos = adtx->reclaimed_pos + adtx->period_len * (nreports + 1) \
						 - residue2;

	return adtx->buf_len - pos % adtx->buf_len;
}

enum dma_status admac_tx_status(struct dma_chan *chan, dma_cookie_t cookie,
				struct dma_tx_state *txstate)
{
	struct admac_chan *adchan = to_admac_chan(chan);
	struct admac_data *ad = adchan->host;
	struct admac_tx *adtx;

	enum dma_status ret;
	size_t residue;
	unsigned long flags;

	ret = dma_cookie_status(chan, cookie, txstate);
	if (ret == DMA_COMPLETE || !txstate)
		return ret;

	/*
	 * Presumably ALSA code will query residue to know if an overrun occured,
	 * this seems a proper place to insert a write barrier.
	 */
	wmb();

	spin_lock_irqsave(&adchan->lock, flags);
	adtx = adchan->current_tx;

	if (adtx && adtx->tx.cookie == cookie) {
		ret = DMA_IN_PROGRESS;
		residue = admac_cyclic_read_residue(ad, adchan->no, adtx);
	} else {
		ret = DMA_IN_PROGRESS;
		residue = 0;
		list_for_each_entry(adtx, &adchan->issued, node) {
			if (adtx->tx.cookie == cookie) {
				residue = adtx->buf_len;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&adchan->lock, flags);

	if (adtx)
		dev_dbg(ad->dev, "ch%d residue: %lx, (%ld%%)\n", adchan->no,
			residue, residue*100/adtx->buf_len);

	dma_set_residue(txstate, residue);
	return ret;
}

void admac_start(struct admac_chan *adchan)
{
	struct admac_data *ad = adchan->host;
	int ch = adchan->no;

	admac_poke(ad, REG_TX_STATUS1(ch), STATUS_DESC_DONE | STATUS_ERR);
	admac_poke(ad, REG_TX_CTL(ch), REG_TX_CTL_RESET_RINGS);
	admac_poke(ad, REG_TX_CTL(ch), 0);
	admac_cyclic_write_one_desc(ad, ch, adchan->current_tx);
	admac_poke(ad, REG_TX_EN, 1 << ch);

	admac_cyclic_write_desc(ad, ch, adchan->current_tx);

	dev_dbg(ad->dev, "ch%d start\n", ch);
}

void admac_issue_pending(struct dma_chan *chan)
{
	struct admac_chan *adchan = to_admac_chan(chan);
	struct admac_tx *tx;
	unsigned long flags;

	spin_lock_irqsave(&adchan->lock, flags);
	list_splice_tail_init(&adchan->submitted, &adchan->issued);
	if (!list_empty(&adchan->issued) && !adchan->current_tx) {
		tx = list_first_entry(&adchan->issued, struct admac_tx, node);
		list_del(&tx->node);

		adchan->current_tx = tx;
		adchan->nperiod_acks = 0;
		admac_start(adchan);
	}
	spin_unlock_irqrestore(&adchan->lock, flags);
}

int admac_pause(struct dma_chan *chan)
{
	struct admac_chan *adchan = to_admac_chan(chan);

	admac_poke(adchan->host, REG_TX_EN_CLR, 1 << adchan->no);

	return 0;
}

int admac_resume(struct dma_chan *chan)
{
	struct admac_chan *adchan = to_admac_chan(chan);
	
	admac_poke(adchan->host, REG_TX_EN, 1 << adchan->no);

	return 0;
}

int admac_terminate_all(struct dma_chan *chan)
{
	struct admac_chan *adchan = to_admac_chan(chan);
	struct admac_tx *adtx, *_adtx;
	unsigned long flags;
	LIST_HEAD(head);

	spin_lock_irqsave(&adchan->lock, flags);
	admac_poke(adchan->host, REG_TX_EN_CLR, 1 << adchan->no);
	adchan->current_tx = NULL;
	list_splice_tail_init(&adchan->submitted, &head);
	list_splice_tail_init(&adchan->issued, &head);
	spin_unlock_irqrestore(&adchan->lock, flags);

	list_for_each_entry_safe(adtx, _adtx, &head, node) {
		list_del(&adtx->node);
		admac_desc_free(&adtx->tx);
	}

	return 0;
}

dma_cookie_t admac_tx_submit(struct dma_async_tx_descriptor *tx)
{
	struct admac_tx *adtx = to_admac_tx(tx);
	struct admac_chan *adchan = to_admac_chan(tx->chan);
	unsigned long flags;
	dma_cookie_t cookie;

	spin_lock_irqsave(&adchan->lock, flags);
	cookie = dma_cookie_assign(tx);
	list_add_tail(&adtx->node, &adchan->submitted);
	spin_unlock_irqrestore(&adchan->lock, flags);

	return cookie;
}

static int admac_desc_free(struct dma_async_tx_descriptor *tx)
{
	struct admac_tx *adtx = to_admac_tx(tx);
	devm_kfree(to_admac_chan(tx->chan)->host->dev, adtx);
	return 0;
}

struct dma_async_tx_descriptor *admac_prep_dma_cyclic(
		struct dma_chan *chan, dma_addr_t buf_addr, size_t buf_len,
		size_t period_len, enum dma_transfer_direction direction,
		unsigned long flags)
{
	struct admac_chan *adchan = container_of(chan, struct admac_chan, chan);
	struct admac_tx *adtx;

	adtx = devm_kzalloc(adchan->host->dev, sizeof(*adtx), GFP_NOWAIT);
	if (!adtx)
		return NULL;

	adtx->cyclic = true;

	adtx->buf_addr = buf_addr;
	adtx->buf_len = buf_len;
	adtx->buf_end = buf_addr + buf_len;
	adtx->period_len = period_len;

	adtx->submitted_pos = 0;
	adtx->reclaimed_pos = 0;

	dma_async_tx_descriptor_init(&adtx->tx, chan);
	adtx->tx.tx_submit = admac_tx_submit;
	adtx->tx.desc_free = admac_desc_free;

	return &adtx->tx;
}

static struct dma_chan *admac_dma_of_xlate(struct of_phandle_args *dma_spec,
						struct of_dma *ofdma)
{
	struct admac_data *ad = (struct admac_data*) ofdma->of_dma_data;
	unsigned int index;

	if (dma_spec->args_count != 1)
		return NULL;

	index = dma_spec->args[0];

	if (index >= ad->nchannels) {
		dev_err(ad->dev, "channel index %u out of bounds\n", index);
		return NULL;
	}

	return &ad->channels[index].chan;
}

/*
 * Write one hardware descriptor for a dmaegine cyclic transaction.
 */
static void admac_cyclic_write_one_desc(struct admac_data *ad, int channo,
					struct admac_tx *tx)
{
	dma_addr_t addr;

	if (WARN_ON(!tx->cyclic))
		return;

	addr = tx->buf_addr + (tx->submitted_pos % tx->buf_len);
	WARN_ON(addr + tx->period_len > tx->buf_end);

	dev_dbg(ad->dev, "ch%d descriptor: addr=0x%llx len=0x%x flags=0x%lx\n",
		channo, addr, (u32) tx->period_len, FLAG_DESC_NOTIFY);

	admac_poke(ad, REG_TX_DESC_WRITE(channo), addr);
	admac_poke(ad, REG_TX_DESC_WRITE(channo), addr >> 32);
	admac_poke(ad, REG_TX_DESC_WRITE(channo), tx->period_len);
	admac_poke(ad, REG_TX_DESC_WRITE(channo), FLAG_DESC_NOTIFY);

	tx->submitted_pos += tx->period_len;
	tx->submitted_pos %= 2 * tx->buf_len;
}

/*
 * Write all the hardware descriptors for a cyclic transaction
 * there is space for.
 */
static void admac_cyclic_write_desc(struct admac_data *ad, int channo,
					struct admac_tx *tx)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (admac_peek(ad, REG_TX_DESC_RING(channo)) & RING_FULL)
			break;
		admac_cyclic_write_one_desc(ad, channo, tx);
	}
}

static int admac_drain_reports(struct admac_data *ad, int channo)
{
	int count;

	for (count = 0; count < 4; count++) {
		u32 countval_hi, countval_lo, unk1, flags;

		if (admac_peek(ad, REG_TX_REPORT_RING(channo)) & RING_EMPTY)
			break;

		countval_lo = admac_peek(ad, REG_TX_REPORT_READ(channo));
		countval_hi = admac_peek(ad, REG_TX_REPORT_READ(channo));
		unk1 =        admac_peek(ad, REG_TX_REPORT_READ(channo));
		flags =       admac_peek(ad, REG_TX_REPORT_READ(channo));

		dev_dbg(ad->dev, "ch%d report: countval=0x%llx unk1=0x%x flags=0x%x\n",
			channo, ((u64) countval_hi) << 32 | countval_lo, unk1, flags);
	}

	return count;
}

static void admac_handle_status_err(struct admac_data *ad, int channo)
{
	bool handled = false;

	if (admac_peek(ad, REG_TX_DESC_RING(channo) & RING_ERR)) {
		admac_poke(ad, REG_TX_DESC_RING(channo), RING_ERR);
		dev_err(ad->dev, "ch%d descriptor ring error\n", channo);
		handled = true;
	}

	if (admac_peek(ad, REG_TX_REPORT_RING(channo)) & RING_ERR) {
		admac_poke(ad, REG_TX_REPORT_RING(channo), RING_ERR);
		dev_err(ad->dev, "ch%d report ring error\n", channo);
		handled = true;
	}

	if (unlikely(!handled)) {
		dev_err(ad->dev, "ch%d unknown error, masking future error interrupts\n", channo);
		admac_modify(ad, REG_TX_INTMASK1(channo), STATUS_ERR, 0);
	}
}

static void admac_handle_status_desc_done(struct admac_data *ad, int channo)
{
	struct admac_chan *adchan = &ad->channels[channo];
	unsigned long flags;
	int nreports;

	admac_poke(ad, REG_TX_STATUS1(channo), STATUS_DESC_DONE);

	spin_lock_irqsave(&adchan->lock, flags);
	nreports = admac_drain_reports(ad, channo);

	if (adchan->current_tx) {
		struct admac_tx *tx = adchan->current_tx;

		adchan->nperiod_acks += nreports;
		tx->reclaimed_pos += nreports * tx->period_len;
		tx->reclaimed_pos %= 2 * tx->buf_len;

		admac_cyclic_write_desc(ad, channo, tx);
		tasklet_schedule(&adchan->tasklet);
	}
	spin_unlock_irqrestore(&adchan->lock, flags);
}

static irqreturn_t admac_interrupt(int irq, void *devid)
{
	struct admac_data *ad = devid;
	u32 chan_bitfield;
	int i;

	chan_bitfield = admac_peek(ad, REG_TX_INTSTATE1);

	for (i = 0; i < ad->nchannels; i++) {
		u32 cause;

		if (!(chan_bitfield & (1 << i)))
			continue;

		cause = admac_peek(ad, REG_TX_STATUS1(i));

		if (cause & STATUS_ERR)
			admac_handle_status_err(ad, i);

		if (cause & STATUS_DESC_DONE)
			admac_handle_status_desc_done(ad, i);
	}

	return (chan_bitfield != 0) ? IRQ_HANDLED : IRQ_NONE;
}

static void admac_chan_tasklet(struct tasklet_struct *t)
{
	struct admac_chan *adchan = from_tasklet(adchan, t, tasklet);
	struct admac_tx *adtx;
	struct dmaengine_desc_callback cb;
	struct dmaengine_result tx_result;
	int nacks;

	spin_lock_irq(&adchan->lock);
	adtx = adchan->current_tx;
	nacks = adchan->nperiod_acks;
	adchan->nperiod_acks = 0;
	spin_unlock_irq(&adchan->lock);

	if (!adtx || !nacks)
		return;

	tx_result.result = DMA_TRANS_NOERROR;
	tx_result.residue = 0;

	dmaengine_desc_get_callback(&adtx->tx, &cb);
	while (nacks--)
		dmaengine_desc_callback_invoke(&cb, &tx_result);
}

static int admac_device_config(struct dma_chan *chan,
				 struct dma_slave_config *config)
{
	struct admac_chan *adchan = to_admac_chan(chan);
	u32 bus_width = 0;

	switch (config->dst_addr_width) {
	case DMA_SLAVE_BUSWIDTH_1_BYTE:
		bus_width |= BUS_WIDTH_8BIT;
		break;
	case DMA_SLAVE_BUSWIDTH_2_BYTES:
		bus_width |= BUS_WIDTH_16BIT;
		break;
	case DMA_SLAVE_BUSWIDTH_4_BYTES:
		bus_width |= BUS_WIDTH_32BIT;
		break;
	default:
		return -EINVAL;
	}

	switch (config->dst_port_window_size) {
	case 0 ... 1:
		break;
	case 2:
		bus_width |= BUS_WIDTH_FRAME_2_WORDS;
		break;
	case 4:
		bus_width |= BUS_WIDTH_FRAME_4_WORDS;
		break;
	default:
		return -EINVAL;
	}

	admac_poke(adchan->host, REG_TX_BUS_WIDTH(adchan->no), bus_width);

	/* burst size */
	admac_poke(adchan->host, 0x8054 + (0x400 * adchan->no), 0x800000);

	admac_poke(adchan->host, REG_TX_STATUS1(adchan->no), STATUS_DESC_DONE | STATUS_ERR);
	admac_poke(adchan->host, REG_TX_INTMASK1(adchan->no), STATUS_DESC_DONE | STATUS_ERR);
	return 0;
}

static int admac_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct admac_data *ad;
	struct dma_device *dma;
	int nchannels;
	int err, irq, i;

	err = of_property_read_u32(np, "dma-channels", &nchannels);
	if (err || (nchannels > NCHANNELS_MAX)) {
		dev_err(&pdev->dev, "missing or invalid dma-channels property\n");
		return -EINVAL;
	}

	ad = devm_kzalloc(&pdev->dev, struct_size(ad, channels, nchannels), GFP_KERNEL);
	if (!ad)
		return -ENOMEM;

	platform_set_drvdata(pdev, ad);
	ad->dev = &pdev->dev;
	ad->nchannels = nchannels;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "unable to obtain interrupt resource\n");
		return irq;
	}

	err = devm_request_irq(&pdev->dev, irq, admac_interrupt,
					0, dev_name(&pdev->dev), ad);
	if (err) {
		dev_err(&pdev->dev, "unable to register interrupt: %d\n", err);
		return err;
	}

	ad->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(ad->regs)) {
		dev_err(&pdev->dev, "unable to obtain MMIO resource\n");
		return PTR_ERR(ad->regs);
	}

	dma = &ad->dma;

	dma_cap_set(DMA_PRIVATE, dma->cap_mask);
	dma_cap_set(DMA_CYCLIC, dma->cap_mask);

	dma->dev = &pdev->dev;
	dma->device_alloc_chan_resources = admac_alloc_chan_resources;
	dma->device_free_chan_resources = admac_free_chan_resources;
	dma->device_tx_status = admac_tx_status;
	dma->device_issue_pending = admac_issue_pending;
	dma->device_terminate_all = admac_terminate_all;
	dma->device_prep_dma_cyclic = admac_prep_dma_cyclic;
	dma->device_config = admac_device_config;

	dma->directions = BIT(DMA_MEM_TO_DEV);
	dma->residue_granularity = DMA_RESIDUE_GRANULARITY_BURST;
	dma->dst_addr_widths = BIT(DMA_SLAVE_BUSWIDTH_1_BYTE) |
			BIT(DMA_SLAVE_BUSWIDTH_2_BYTES) |
			BIT(DMA_SLAVE_BUSWIDTH_4_BYTES);

	INIT_LIST_HEAD(&dma->channels);
	for (i = 0; i < nchannels; i++) {
		struct admac_chan *adchan = &ad->channels[i];
		adchan->host = ad;
		adchan->no = i;
		adchan->chan.device = &ad->dma;
		dma_cookie_init(&adchan->chan);
		spin_lock_init(&adchan->lock);
		INIT_LIST_HEAD(&adchan->submitted);
		INIT_LIST_HEAD(&adchan->issued);
		list_add_tail(&adchan->chan.device_node, &dma->channels);
		tasklet_setup(&adchan->tasklet, admac_chan_tasklet);
	}

	err = dma_async_device_register(&ad->dma);
	if (err) {
		dev_err(&pdev->dev, "failed to register DMA device: %d\n", err);
		return err;
	}

	err = of_dma_controller_register(pdev->dev.of_node, admac_dma_of_xlate, ad);
	if (err) {
		dev_err(&pdev->dev, "failed to register with OF: %d\n", err);
		dma_async_device_unregister(&ad->dma);
		return err;
	}

	dev_dbg(&pdev->dev, "all good, ready to go!\n");

	return 0;
}

static int admac_remove(struct platform_device *pdev)
{
	of_dma_controller_free(pdev->dev.of_node);
	//dma_async_device_unregister(->dmadev);
	return 0;
}

static const struct of_device_id admac_of_match[] = {
	{ .compatible = "apple,admac", },
	{ },
};

static struct platform_driver apple_admac_driver = {
	.driver = {
		.name = "apple-admac",
		.of_match_table = admac_of_match,
	},
	.probe = admac_probe,
	.remove = admac_remove,
};
module_platform_driver(apple_admac_driver);

MODULE_AUTHOR("Martin Povišer <povik@protonmail.com>");
MODULE_DESCRIPTION("Driver for Audio DMA Controller (ADMAC) in Apple SoCs");
MODULE_LICENSE("GPL v2");
