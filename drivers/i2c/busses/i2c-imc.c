/*
 * Copyright (c) 2013 Andrew Lutomirski <luto@amacapital.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/i2c/dimm-bus.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pm_qos.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/i2c.h>

/*
 * The datasheet can be found here, for example:
 * http://www.intel.com/content/dam/www/public/us/en/documents/datasheets/xeon-e5-1600-2600-vol-2-datasheet.pdf
 *
 * There seem to be quite a few bugs or spec errors, though:
 *
 *  - A successful transaction sets WOD and RDO.
 *
 *  - The docs for TSOD_POLL_EN make no sense (see imc_channel_claim)
 *
 *  - Erratum BT109, which says:
 *
 *      The processor may not complete SMBus (System Management Bus)
 *      transactions targeting the TSOD (Temperature Sensor On DIMM)
 *      when Package C-States are enabled. Due to this erratum, if the
 *      processor transitions into a Package C-State while an SMBus
 *      transaction with the TSOD is in process, the processor will
 *      suspend receipt of the transaction. The transaction completes
 *      while the processor is in a Package C-State.  Upon exiting
 *      Package C-State, the processor will attempt to resume the
 *      SMBus transaction, detect a protocol violation, and log an
 *      error.
 *
 *   That description seems to be wrong.  If the package enters a
 *   C-State while a software-initiated SMBUS transaction is running,
 *   then the result of the transaction seems to be wrong, but no
 *   error is signaled.  It does not seem to matter whether the
 *   transaction is targeting a TSOD.
 *
 *   For added fun, the relevant bits in MSR_PKG_CST_CONFIG_CONTROL
 *   are lockable, so we can't just disable package C-States.
 *
 *   The upshot is that we need to use a hack to keep a package awake
 *   while we're using its SMBUS master.  pm_qos is the easiest, so we
 *   use it for now.  It has the unfortunate side-effect that each
 *   claim and each release will result in an IPI to all CPUs and
 *   that, while any SMBUS transaction is running, the whole system
 *   will be forced to a high-power state.
 */

/* Register offsets (in PCI configuration space) */
#define SMBSTAT(i)			(0x180 + 0x10*i)
#define SMBCMD(i)			(0x184 + 0x10*i)
#define SMBCNTL(i)			(0x188 + 0x10*i)
#define SMB_TSOD_POLL_RATE_CNTR(i)	(0x18C + 0x10*i)
#define SMB_TSOD_POLL_RATE		(0x1A8)

/* SMBSTAT fields */
#define SMBSTAT_RDO		(1U << 31)	/* Read Data Valid */
#define SMBSTAT_WOD		(1U << 30)	/* Write Operation Done */
#define SMBSTAT_SBE		(1U << 29)	/* SMBus Error */
#define SMBSTAT_SMB_BUSY	(1U << 28)	/* SMBus Busy State */
/* 26:24 is the last automatically polled TSOD address */
#define SMBSTAT_RDATA_MASK	0xffff		/* result of a read */

/* SMBCMD fields */
#define SMBCMD_TRIGGER		(1U << 31)	/* CMD Trigger */
#define SMBCMD_PNTR_SEL		(1U << 30)	/* HW polls TSOD with pointer */
#define SMBCMD_WORD_ACCESS	(1U << 29)	/* word (vs byte) access */
#define SMBCMD_TYPE_MASK	(3U << 27)	/* Mask for access type */
#define  SMBCMD_TYPE_READ	(0U << 27)	/* Read */
#define  SMBCMD_TYPE_WRITE	(1U << 27)	/* Write */
#define  SMBCMD_TYPE_PNTR_WRITE	(3U << 27)	/* Write to pointer */
#define SMBCMD_SA_MASK		(7U << 24)	/* Slave Address high bits */
#define SMBCMD_SA_SHIFT		24
#define SMBCMD_BA_MASK		0xff0000	/* Bus Txn address */
#define SMBCMD_BA_SHIFT		16
#define SMBCMD_WDATA_MASK	0xffff		/* data to write */

/* SMBCNTL fields */
#define SMBCNTL_DTI_MASK	0xf0000000	/* Slave Address low bits */
#define SMBCNTL_DTI_SHIFT	28		/* Slave Address low bits */
#define SMBCNTL_CKOVRD		(1U << 27)	/* # Clock Override */
#define SMBCNTL_DIS_WRT		(1U << 26)	/* Disable Write (sadly) */
#define SMBCNTL_SOFT_RST	(1U << 10)	/* Soft Reset */
#define SMBCNTL_TSOD_POLL_EN	(1U << 8)	/* TSOD Polling Enable */
/* Bits 0-3 and 4-6 indicate TSOD presence in various slots */

/* System Address Controller, PCI dev 13 fn 6, 8086.3cf5 */
#define SAD_CONTROL 0xf4

/*
 * The clock is around 100kHz, and transactions are nine cycles per byte
 * plus a few start/stop cycles, plus whatever clock streching is involved.
 * This is a guess at the polling interval.
 */

#define TXN_LEN_US (20 * 10)

#define PCI_DEVICE_ID_INTEL_SBRIDGE_BR          0x3cf5  /* 13.6 */
#define PCI_DEVICE_ID_INTEL_SBRIDGE_IMC_TA      0x3ca8  /* 15.0 */

struct imc_channel {
	struct i2c_adapter adapter;
	struct mutex mutex;
	bool can_write, suspended;
};

struct imc_priv {
	struct pci_dev *pci_dev;
	struct imc_channel channels[2];
};

/*
 * There's some cost to just having a pm_qos request installed, so we
 * just use one globally instead of one per device.
 */
static struct pm_qos_request imc_pm_qos;
static int imc_pm_qos_count;
static DEFINE_MUTEX(imc_pm_qos_mutex);

static void imc_pmqos_get(void)
{
	mutex_lock(&imc_pm_qos_mutex);
	if (++imc_pm_qos_count == 1)
		pm_qos_update_request(&imc_pm_qos, 5);
	mutex_unlock(&imc_pm_qos_mutex);
}

static void imc_pmqos_put(void)
{
	mutex_lock(&imc_pm_qos_mutex);
	if (--imc_pm_qos_count == 0)
		pm_qos_update_request(&imc_pm_qos, PM_QOS_DEFAULT_VALUE);
	mutex_unlock(&imc_pm_qos_mutex);
}

static void imc_channel_release(struct imc_priv *priv, int chan)
{
	/* Return to HW control. */
	u32 cntl;
	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &cntl);
	cntl |= SMBCNTL_TSOD_POLL_EN;
	pci_write_config_dword(priv->pci_dev, SMBCNTL(chan), cntl);
	imc_pmqos_put();
}

static int imc_channel_claim(struct imc_priv *priv, int chan)
{
	/*
	 * The docs are a bit confused here.  We're supposed to disable TSOD
	 * polling, then wait for busy to be cleared, then set
	 * SMBCNTL_TSOD_POLL_EN to zero to switch to software control.  But
	 * SMBCNTL_TSOD_POLL_EN is the only documented way to turn off polling.
	 */

	u32 cntl, stat;
	int i;

	if (priv->channels[chan].suspended)
		return -EIO;

	imc_pmqos_get();

	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &cntl);
	cntl &= ~SMBCNTL_TSOD_POLL_EN;
	pci_write_config_dword(priv->pci_dev, SMBCNTL(chan), cntl);

	for (i = 0; i < 20; i++) {
		pci_read_config_dword(priv->pci_dev, SMBSTAT(chan), &stat);
		if (!(stat & SMBSTAT_SMB_BUSY))
			return 0;  /* The channel is ours. */
		usleep_range(TXN_LEN_US, 3*TXN_LEN_US);
	}

	/* We failed to take control of the channel.  Return to HW control. */
	imc_channel_release(priv, chan);
	imc_pmqos_put();
	return -EBUSY;
}

/*
 * The iMC supports five access types.  The terminology is rather
 * inconsistent.  These are the types:
 *
 * "Write to pointer register SMBus": I2C_SMBUS_WRITE, I2C_SMBUS_BYTE
 *
 * Read byte/word: I2C_SMBUS_READ, I2C_SMBUS_{BYTE|WORD}_DATA
 *
 * Write byte/word: I2C_SMBUS_WRITE, I2C_SMBUS_{BYTE|WORD}_DATA
 *
 * The pointer write operations is AFAICT completely useless for
 * software control, for two reasons.  First, HW periodically polls any
 * TSODs on the bus, so it will corrupt the pointer in between SW
 * transactions.  More importantly, the matching "read byte"/"receive
 * byte" (the address-less single-byte read) is not available for SW
 * control.  Therefore, this driver doesn't implement pointer writes
 *
 * There is no PEC support.
 */

static u32 imc_func(struct i2c_adapter *adapter)
{
	int chan;
	struct imc_channel *ch;
	struct imc_priv *priv = i2c_get_adapdata(adapter);

	chan = (adapter == &priv->channels[0].adapter ? 0 : 1);
	ch = &priv->channels[chan];

	if (ch->can_write)
		return I2C_FUNC_SMBUS_BYTE_DATA | I2C_FUNC_SMBUS_WORD_DATA;
	else
		return I2C_FUNC_SMBUS_READ_BYTE_DATA |
			I2C_FUNC_SMBUS_READ_WORD_DATA;
}

static s32 imc_smbus_xfer(struct i2c_adapter *adap, u16 addr,
			  unsigned short flags, char read_write, u8 command,
			  int size, union i2c_smbus_data *data)
{
	int i, ret, chan;
	u32 tmp, cmdbits = 0, cntlbits = 0, stat;
	struct imc_channel *ch;
	struct imc_priv *priv = i2c_get_adapdata(adap);

	chan = (adap == &priv->channels[0].adapter ? 0 : 1);
	ch = &priv->channels[chan];

	if (addr > 0x7f)
		return -EOPNOTSUPP;  /* No large address support */
	if (flags)
		return -EOPNOTSUPP;  /* No PEC */

	cmdbits  |= ((u32)addr & 0x7) << SMBCMD_SA_SHIFT;
	cntlbits |= ((u32)addr >> 3) << SMBCNTL_DTI_SHIFT;

	switch (size) {
	case I2C_SMBUS_BYTE_DATA:
		cmdbits |= ((u32)command) << SMBCMD_BA_SHIFT;
		if (read_write == I2C_SMBUS_READ)
			cmdbits |= SMBCMD_TYPE_READ;
		else
			cmdbits |= SMBCMD_TYPE_WRITE | data->byte;
		break;
	case I2C_SMBUS_WORD_DATA:
		cmdbits |= ((u32)command) << SMBCMD_BA_SHIFT;
		cmdbits |= SMBCMD_WORD_ACCESS;
		if (read_write == I2C_SMBUS_READ)
			cmdbits |= SMBCMD_TYPE_READ;
		else
			cmdbits |= SMBCMD_TYPE_WRITE | swab16(data->word);
		break;
	default:
		return -EOPNOTSUPP;
	}

	mutex_lock(&ch->mutex);

	ret = imc_channel_claim(priv, chan);
	if (ret)
		goto out_unlock;

	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &tmp);
	tmp &= ~SMBCNTL_DTI_MASK;
	tmp |= cntlbits;
	pci_write_config_dword(priv->pci_dev, SMBCNTL(chan), tmp);

	/*
	 * This clears SMBCMD_PNTR_SEL.  We leave it cleared so that we don't
	 * need to think about keeping the TSOD pointer state consistent with
	 * the hardware's expectation.  This probably has some miniscule
	 * power cost, as TSOD polls will take 9 extra cycles.
	 */
	cmdbits |= SMBCMD_TRIGGER;
	pci_write_config_dword(priv->pci_dev, SMBCMD(chan), cmdbits);

	for (i = 0; ; i++) {
		pci_read_config_dword(priv->pci_dev, SMBSTAT(chan), &stat);
		if (!(stat & SMBSTAT_SMB_BUSY))
			break;
		if (i < 50) {
			usleep_range(TXN_LEN_US, 3*TXN_LEN_US);
			continue;
		}

		/* Timeout.  TODO: Reset the controller? */
		ret = -EIO;
		dev_err(&priv->pci_dev->dev, "controller is wedged\n");
		goto out_release;
	}

	if (stat & SMBSTAT_SBE) {
		/*
		 * Clear the error to re-enable TSOD polling.  The docs say
		 * that, as long as SBE is set, TSOD polling won't happen.
		 * The docs also say that writing zero to this bit (which is
		 * the only writable bit in the whole register) will clear
		 * the error.  Empirically, writing 0 does not clear SBE, but
		 * it's probably still good to do the write in compliance with
		 * the spec.  (TSOD polling still happens and seems to
		 * clear SBE on its own.)
		 */
		pci_write_config_dword(priv->pci_dev, SMBSTAT(chan), 0);
		ret = -ENXIO;
		goto out_release;
	}

	if (read_write == I2C_SMBUS_READ) {
		if (stat & SMBSTAT_RDO) {
			/*
			 * The iMC SMBUS controller thinks of SMBUS
			 * words as being big-endian (MSB first).
			 * Linux treats them as little-endian, we need
			 * to swap them.
			 *
			 * Note: the controller will often (always?) set
			 * WOD here.  This is probably a bug.
			 */
			if (size == I2C_SMBUS_WORD_DATA)
				data->word = swab16(stat & SMBSTAT_RDATA_MASK);
			else
				data->byte = stat & 0xFF;
			ret = 0;
		} else {
			dev_err(&priv->pci_dev->dev,
				"Unexpected read status 0x%08X\n", stat);
			ret = -EIO;
		}
	} else {
		if (stat & SMBSTAT_WOD) {
			/* Same bug (?) as in the read case. */
			ret = 0;
		} else {
			dev_err(&priv->pci_dev->dev,
				"Unexpected write status 0x%08X\n", stat);
			ret = -EIO;
		}
	}

out_release:
	imc_channel_release(priv, chan);

out_unlock:
	mutex_unlock(&ch->mutex);

	return ret;
}

static const struct i2c_algorithm imc_smbus_algorithm = {
	.smbus_xfer	= imc_smbus_xfer,
	.functionality	= imc_func,
};

static int imc_init_channel(struct imc_priv *priv, int i, int socket)
{
	int err;
	u32 val;
	struct imc_channel *ch = &priv->channels[i];

	i2c_set_adapdata(&ch->adapter, priv);
	ch->adapter.owner = THIS_MODULE;
	ch->adapter.algo = &imc_smbus_algorithm;
	ch->adapter.dev.parent = &priv->pci_dev->dev;

	pci_read_config_dword(priv->pci_dev, SMBCNTL(i), &val);
	ch->can_write = !(val & SMBCNTL_DIS_WRT);

	/*
	 * i2c_add_addapter can call imc_smbus_xfer, so we need to be
	 * ready immediately.
	 */
	mutex_init(&ch->mutex);

	snprintf(ch->adapter.name, sizeof(ch->adapter.name),
		 "iMC socket %d channel %d", socket, i);
	err = i2c_add_adapter(&ch->adapter);
	if (err) {
		mutex_destroy(&ch->mutex);
		return err;
	}

	i2c_scan_dimm_bus(&ch->adapter);

	return 0;
}

static void imc_free_channel(struct imc_priv *priv, int i)
{
	struct imc_channel *ch = &priv->channels[i];

	mutex_lock(&ch->mutex);
	i2c_del_adapter(&ch->adapter);
	mutex_unlock(&ch->mutex);
	mutex_destroy(&ch->mutex);
}

static int imc_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int i, err;
	struct imc_priv *priv;
	struct pci_dev *sad;  /* System Address Decoder */
	u32 sad_control;

	/* Paranoia: the datasheet says this is always at 15.0 */
	if (dev->devfn != PCI_DEVFN(15, 0))
		return -ENODEV;

	/*
	 * The socket number is hidden away on a different PCI device.
	 * There's another copy at devfn 11.0 offset 0x40, and an even
	 * less convincing copy at 5.0 0x140.  The actual APICID register
	 * is "not used ... and is still implemented in hardware because
	 * of FUD".
	 *
	 * In principle we could double-check that the socket matches
	 * the numa_node from SRAT, but this is probably not worth it.
	 */
	sad = pci_get_slot(dev->bus, PCI_DEVFN(13, 6));
	if (!sad)
		return -ENODEV;
	if (sad->vendor != PCI_VENDOR_ID_INTEL ||
	    sad->device != PCI_DEVICE_ID_INTEL_SBRIDGE_BR) {
		pci_dev_put(sad);
		return -ENODEV;
	}
	pci_read_config_dword(sad, SAD_CONTROL, &sad_control);
	pci_dev_put(sad);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->pci_dev = dev;

	pci_set_drvdata(dev, priv);

	for (i = 0; i < 2; i++) {
		int j;
		err = imc_init_channel(priv, i, sad_control & 0x7);
		if (err) {
			for (j = 0; j < i; j++)
				imc_free_channel(priv, j);
			goto exit_free;
		}
	}

	return 0;

exit_free:
	kfree(priv);
	return err;
}

static void imc_remove(struct pci_dev *dev)
{
	int i;
	struct imc_priv *priv = pci_get_drvdata(dev);

	for (i = 0; i < 2; i++)
		imc_free_channel(priv, i);

	kfree(priv);
}

static int imc_suspend(struct pci_dev *dev, pm_message_t mesg)
{
	int i;
	struct imc_priv *priv = pci_get_drvdata(dev);

	/* BIOS is in charge.  We should finish any pending transaction */
	for (i = 0; i < 2; i++) {
		mutex_lock(&priv->channels[i].mutex);
		priv->channels[i].suspended = true;
		mutex_unlock(&priv->channels[i].mutex);
	}

	return 0;
}

static int imc_resume(struct pci_dev *dev)
{
	int i;
	struct imc_priv *priv = pci_get_drvdata(dev);

	for (i = 0; i < 2; i++) {
		mutex_lock(&priv->channels[i].mutex);
		priv->channels[i].suspended = false;
		mutex_unlock(&priv->channels[i].mutex);
	}

	return 0;
}

static DEFINE_PCI_DEVICE_TABLE(imc_ids) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_SBRIDGE_IMC_TA) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, imc_ids);

static struct pci_driver imc_pci_driver = {
	.name		= "imc_smbus",
	.id_table	= imc_ids,
	.probe		= imc_probe,
	.remove		= imc_remove,
	.suspend	= imc_suspend,
	.resume		= imc_resume,
};

static int __init imc_init(void)
{
	int err;

	pm_qos_add_request(&imc_pm_qos,
			   PM_QOS_CPU_DMA_LATENCY, PM_QOS_DEFAULT_VALUE);
	err = pci_register_driver(&imc_pci_driver);
	if (err)
		pm_qos_remove_request(&imc_pm_qos);
	return err;
}

static void __exit imc_exit(void)
{
	pci_unregister_driver(&imc_pci_driver);
	pm_qos_remove_request(&imc_pm_qos);
}

module_init(imc_init);
module_exit(imc_exit);

MODULE_AUTHOR("Andrew Lutomirski <luto@amacapital.net>");
MODULE_DESCRIPTION("iMC SMBus driver");
MODULE_LICENSE("GPL");
