/*
 * Copyright (c) 2013-2016 Andrew Lutomirski <luto@amacapital.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/ratelimit.h>
#include <linux/i2c.h>

/*
 * The datasheet can be found here, for example:
 * http://www.intel.com/content/dam/www/public/us/en/documents/datasheets/xeon-e5-1600-2600-vol-2-datasheet.pdf
 *
 * There seem to be quite a few bugs or spec errors, though:
 *
 *  - A successful transaction sets WOD and RDO.
 *
 *  - The docs for TSOD_POLL_EN make no sense (see imc_channel_claim).
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
 *   The description notwithstanding, I've seen difficult-to-reproduce
 *   issues when the system goes completely idle (so package C-states can
 *   be entered) while software-initiated SMBUS transactions are in
 *   progress.
 */

/* Register offsets (in PCI configuration space) */
#define SMBSTAT(i)			(0x180 + 0x10*(i))
#define SMBCMD(i)			(0x184 + 0x10*(i))
#define SMBCNTL(i)			(0x188 + 0x10*(i))
#define SMB_TSOD_POLL_RATE_CNTR(i)	(0x18C + 0x10*(i))
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

/* Bits that might randomly change if we race with something. */
#define SMBCMD_OUR_BITS		(~(u32)SMBCMD_TRIGGER)
#define SMBCNTL_OUR_BITS	(SMBCNTL_DTI_MASK | SMBCNTL_TSOD_POLL_EN)

/* System Address Controller, PCI dev 13 fn 6, 8086.3cf5 */
#define SAD_CONTROL 0xf4

#define PCI_DEVICE_ID_INTEL_SBRIDGE_BR          0x3cf5  /* 13.6 */
#define PCI_DEVICE_ID_INTEL_SBRIDGE_IMC_TA      0x3ca8  /* 15.0 */

static atomic_t imc_raced;  /* Set permanently to 1 if we screw up. */

static bool allow_unsafe_access;

struct imc_channel {
	struct i2c_adapter adapter;
	struct mutex mutex;  /* protects access to regs and prev_tsod_poll */
	bool can_write, suspended;
	bool prev_tsod_poll;
};

struct imc_priv {
	struct pci_dev *pci_dev;
	struct imc_channel channels[2];
};

static bool imc_wait_not_busy(struct imc_priv *priv, int chan, u32 *stat)
{
	/*
	 * The clock is around 100kHz, and transactions are nine cycles
	 * per byte plus a few start/stop cycles, plus whatever clock
	 * streching is involved.  This means that polling every 70us
	 * or so will give decent performance.
	 *
	 * Ideally we would calculate a good estimate for the
	 * transaction time and sleep, but busy-waiting is an effective
	 * workaround for an apparent Sandy Bridge bug that causes bogus
	 * output if the system enters a package C-state.  (NB: these
	 * states are systemwide -- we don't need be running on the
	 * right package for this to work.)
	 *
	 * When Ivy Bridge and Haswell support are added, we could
	 * consider making the busy-wait depend on the platform.
	 */

	int i;

	for (i = 0; i < 50; i++) {
		pci_read_config_dword(priv->pci_dev, SMBSTAT(chan), stat);
		if (!(*stat & SMBSTAT_SMB_BUSY))
			return true;
		udelay(70);  /* see comment above -- we need to busy-wait */
	}

	return false;
}

static void imc_channel_release(struct imc_priv *priv, int chan)
{
	/* Return to HW control. */
	if (priv->channels[chan].prev_tsod_poll) {
		u32 cntl;

		pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &cntl);
		cntl |= SMBCNTL_TSOD_POLL_EN;
		pci_write_config_dword(priv->pci_dev, SMBCNTL(chan), cntl);
	}
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

	if (priv->channels[chan].suspended)
		return -EIO;

	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &cntl);
	priv->channels[chan].prev_tsod_poll = !!(cntl & SMBCNTL_TSOD_POLL_EN);
	cntl &= ~SMBCNTL_TSOD_POLL_EN;
	pci_write_config_dword(priv->pci_dev, SMBCNTL(chan), cntl);

	/* Sometimes the hardware won't let go. */
	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &cntl);
	if (cntl & SMBCNTL_TSOD_POLL_EN)
		return -EBUSY;

	if (!imc_wait_not_busy(priv, chan, &stat)) {
		imc_channel_release(priv, chan);
		return -EBUSY;  /* Someone else is controlling the bus. */
	}

	return 0;  /* The channel is ours. */
}

static bool imc_channel_can_claim(struct imc_priv *priv, int chan)
{
	u32 orig_cntl, cntl;

	/* See if we can turn off TSOD_POLL_EN. */

	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &orig_cntl);
	pci_write_config_dword(priv->pci_dev, SMBCNTL(chan),
			       orig_cntl & ~SMBCNTL_TSOD_POLL_EN);

	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &cntl);
	if (cntl & SMBCNTL_TSOD_POLL_EN)
		return false;  /* Failed. */

	pci_write_config_dword(priv->pci_dev, SMBCNTL(chan), orig_cntl);
	return true;
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
	int ret, chan;
	u32 cmd = 0, cntl, final_cmd, final_cntl, stat;
	struct imc_channel *ch;
	struct imc_priv *priv = i2c_get_adapdata(adap);

	if (atomic_read(&imc_raced))
		return -EIO;  /* Minimize damage. */

	chan = (adap == &priv->channels[0].adapter ? 0 : 1);
	ch = &priv->channels[chan];

	/* Encode CMD part of addresses and access size */
	cmd |= ((u32)addr & 0x7) << SMBCMD_SA_SHIFT;
	cmd |= ((u32)command) << SMBCMD_BA_SHIFT;
	if (size == I2C_SMBUS_WORD_DATA)
		cmd |= SMBCMD_WORD_ACCESS;

	/* Encode read/write and data to write */
	if (read_write == I2C_SMBUS_READ) {
		cmd |= SMBCMD_TYPE_READ;
	} else {
		cmd |= SMBCMD_TYPE_WRITE;
		cmd |= (size == I2C_SMBUS_WORD_DATA
			    ? swab16(data->word)
			    : data->byte);
	}

	mutex_lock(&ch->mutex);

	ret = imc_channel_claim(priv, chan);
	if (ret)
		goto out_unlock;

	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &cntl);
	cntl &= ~SMBCNTL_DTI_MASK;
	cntl |= ((u32)addr >> 3) << SMBCNTL_DTI_SHIFT;
	pci_write_config_dword(priv->pci_dev, SMBCNTL(chan), cntl);

	/*
	 * This clears SMBCMD_PNTR_SEL.  We leave it cleared so that we don't
	 * need to think about keeping the TSOD pointer state consistent with
	 * the hardware's expectation.  This probably has some miniscule
	 * power cost, as TSOD polls will take 9 extra cycles.
	 */
	cmd |= SMBCMD_TRIGGER;
	pci_write_config_dword(priv->pci_dev, SMBCMD(chan), cmd);

	if (!imc_wait_not_busy(priv, chan, &stat)) {
		/* Timeout.  TODO: Reset the controller? */
		ret = -ETIMEDOUT;
		dev_dbg(&priv->pci_dev->dev, "controller is wedged\n");
		goto out_release;
	}

	/*
	 * Be paranoid: try to detect races.  This will only detect races
	 * against BIOS, not against hardware.  (I've never seen this happen.)
	 */
	pci_read_config_dword(priv->pci_dev, SMBCMD(chan), &final_cmd);
	pci_read_config_dword(priv->pci_dev, SMBCNTL(chan), &final_cntl);
	if (((cmd ^ final_cmd) & SMBCMD_OUR_BITS) ||
	    ((cntl ^ final_cntl) & SMBCNTL_OUR_BITS)) {
		WARN(1, "iMC SMBUS raced against firmware");
		dev_err(&priv->pci_dev->dev,
			"Access to channel %d raced: cmd 0x%08X->0x%08X, cntl 0x%08X->0x%08X\n",
			chan, cmd, final_cmd, cntl, final_cntl);
		atomic_set(&imc_raced, 1);
		ret = -EIO;
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
		if (!(stat & SMBSTAT_RDO)) {
			dev_dbg(&priv->pci_dev->dev,
				"Unexpected read status 0x%08X\n", stat);
			ret = -EIO;
			goto out_release;
		}

		/*
		 * The iMC SMBUS controller thinks of SMBUS words as
		 * being big-endian (MSB first).  Linux treats them as
		 * little-endian, so we need to swap them.
		 *
		 * Note: the controller will often (always?) set WOD
		 * here.  This is probably a hardware bug.
		 */
		if (size == I2C_SMBUS_WORD_DATA)
			data->word = swab16(stat & SMBSTAT_RDATA_MASK);
		else
			data->byte = stat & 0xFF;
	} else {
		/*
		 * Note: the controller will often (always?) set RDO here.
		 * This is probably a hardware bug.
		 */
		if (!(stat & SMBSTAT_WOD)) {
			dev_dbg(&priv->pci_dev->dev,
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

	/*
	 * With CLTT enabled, the hardware won't let us turn
	 * off TSOD polling.  The device is completely useless
	 * when this happens (at least without help from Intel),
	 * but we can at least minimize confusion.
	 */
	if (!imc_channel_can_claim(priv, i)) {
		dev_warn(&priv->pci_dev->dev,
			 "iMC channel %d: we cannot control the HW.  Is CLTT on?\n",
			 i);
		return -EBUSY;
	}

	i2c_set_adapdata(&ch->adapter, priv);
	ch->adapter.owner = THIS_MODULE;
	ch->adapter.algo = &imc_smbus_algorithm;
	ch->adapter.dev.parent = &priv->pci_dev->dev;

	pci_read_config_dword(priv->pci_dev, SMBCNTL(i), &val);
	ch->can_write = !(val & SMBCNTL_DIS_WRT);

	mutex_init(&ch->mutex);

	snprintf(ch->adapter.name, sizeof(ch->adapter.name),
		 "iMC socket %d channel %d", socket, i);
	err = i2c_add_adapter(&ch->adapter);
	if (err) {
		mutex_destroy(&ch->mutex);
		return err;
	}

	return 0;
}

static void imc_free_channel(struct imc_priv *priv, int i)
{
	struct imc_channel *ch = &priv->channels[i];

	i2c_del_adapter(&ch->adapter);
	mutex_destroy(&ch->mutex);
}

static struct pci_dev *imc_get_related_device(struct pci_bus *bus,
					      unsigned int devfn, u16 devid)
{
	struct pci_dev *dev = pci_get_slot(bus, devfn);

	if (!dev)
		return NULL;
	if (dev->vendor != PCI_VENDOR_ID_INTEL || dev->device != devid) {
		pci_dev_put(dev);
		return NULL;
	}
	return dev;
}

static int imc_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int i, j, err;
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
	sad = imc_get_related_device(dev->bus, PCI_DEVFN(13, 6),
				     PCI_DEVICE_ID_INTEL_SBRIDGE_BR);
	if (!sad)
		return -ENODEV;
	pci_read_config_dword(sad, SAD_CONTROL, &sad_control);
	pci_dev_put(sad);

	priv = devm_kzalloc(&dev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->pci_dev = dev;

	pci_set_drvdata(dev, priv);

	for (i = 0; i < 2; i++) {
		err = imc_init_channel(priv, i, sad_control & 0x7);
		if (err)
			goto exit_free_channels;
	}

	return 0;

exit_free_channels:
	for (j = 0; j < i; j++)
		imc_free_channel(priv, j);
	return err;
}

static void imc_remove(struct pci_dev *dev)
{
	int i;
	struct imc_priv *priv = pci_get_drvdata(dev);

	for (i = 0; i < 2; i++)
		imc_free_channel(priv, i);
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

static const struct pci_device_id imc_ids[] = {
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

static int __init i2c_imc_init(void)
{
	if (!allow_unsafe_access)
		return -ENODEV;

	pr_warn("using this driver is dangerous unless your firmware is specifically designed for it; use at your own risk\n");
	return pci_register_driver(&imc_pci_driver);
}
module_init(i2c_imc_init);

static void __exit i2c_imc_exit(void)
{
	pci_unregister_driver(&imc_pci_driver);
}
module_exit(i2c_imc_exit);

module_param(allow_unsafe_access, bool, 0400);
MODULE_PARM_DESC(allow_unsafe_access, "enable i2c_imc despite potential races against BIOS/hardware bus access");

MODULE_AUTHOR("Andrew Lutomirski <luto@amacapital.net>");
MODULE_DESCRIPTION("iMC SMBus driver");
MODULE_LICENSE("GPL v2");
