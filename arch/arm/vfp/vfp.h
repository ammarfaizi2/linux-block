/*
 *  linux/arch/arm/vfp/vfp.h
 *
 *  Copyright (C) 2004 ARM Limited.
 *  Written by Deep Blue Solutions Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * Operations on unpacked elements
 */
#define vfp_sign_negate(sign)	(sign ^ 0x8000)

/*
 * Single-precision
 */
struct vfp_single {
	s16	exponent;
	u16	sign;
	u32	significand;
};

extern s32 vfp_get_float(unsigned int reg);
extern void vfp_put_float(s32 val, unsigned int reg);

/*
 * VFP_SINGLE_MANTISSA_BITS - number of bits in the mantissa
 * VFP_SINGLE_EXPONENT_BITS - number of bits in the exponent
 * VFP_SINGLE_LOW_BITS - number of low bits in the unpacked significand
 *  which are not propagated to the float upon packing.
 */
#define VFP_SINGLE_MANTISSA_BITS	(23)
#define VFP_SINGLE_EXPONENT_BITS	(8)
#define VFP_SINGLE_LOW_BITS		(32 - VFP_SINGLE_MANTISSA_BITS - 2)
#define VFP_SINGLE_LOW_BITS_MASK	((1 << VFP_SINGLE_LOW_BITS) - 1)

/*
 * The bit in an unpacked float which indicates that it is a quiet NaN
 */
#define VFP_SINGLE_SIGNIFICAND_QNAN	(1 << (VFP_SINGLE_MANTISSA_BITS - 1 + VFP_SINGLE_LOW_BITS))

/*
 * Operations on packed single-precision numbers
 */
#define vfp_single_packed_sign(v)	((v) & 0x80000000)
#define vfp_single_packed_negate(v)	((v) ^ 0x80000000)
#define vfp_single_packed_abs(v)	((v) & ~0x80000000)
#define vfp_single_packed_exponent(v)	(((v) >> VFP_SINGLE_MANTISSA_BITS) & ((1 << VFP_SINGLE_EXPONENT_BITS) - 1))
#define vfp_single_packed_mantissa(v)	((v) & ((1 << VFP_SINGLE_MANTISSA_BITS) - 1))

/*
 * Unpack a single-precision float.  Note that this returns the magnitude
 * of the single-precision float mantissa with the 1. if necessary,
 * aligned to bit 30.
 */
static inline void vfp_single_unpack(struct vfp_single *s, s32 val)
{
	u32 significand;

	s->sign = vfp_single_packed_sign(val) >> 16,
	s->exponent = vfp_single_packed_exponent(val);

	significand = (u32) val;
	significand = (significand << (32 - VFP_SINGLE_MANTISSA_BITS)) >> 2;
	if (s->exponent && s->exponent != 255)
		significand |= 0x40000000;
	s->significand = significand;
}

/*
 * Re-pack a single-precision float.  This assumes that the float is
 * already normalised such that the MSB is bit 30, _not_ bit 31.
 */
static inline s32 vfp_single_pack(struct vfp_single *s)
{
	u32 val;
	val = (s->sign << 16) +
	      (s->exponent << VFP_SINGLE_MANTISSA_BITS) +
	      (s->significand >> VFP_SINGLE_LOW_BITS);
	return (s32)val;
}

#define VFP_NUMBER		(1<<0)
#define VFP_ZERO		(1<<1)
#define VFP_DENORMAL		(1<<2)
#define VFP_INFINITY		(1<<3)
#define VFP_NAN			(1<<4)
#define VFP_NAN_SIGNAL		(1<<5)

#define VFP_QNAN		(VFP_NAN)
#define VFP_SNAN		(VFP_NAN|VFP_NAN_SIGNAL)

static inline int vfp_single_type(struct vfp_single *s)
{
	int type = VFP_NUMBER;
	if (s->exponent == 255) {
		if (s->significand == 0)
			type = VFP_INFINITY;
		else if (s->significand & VFP_SINGLE_SIGNIFICAND_QNAN)
			type = VFP_QNAN;
		else
			type = VFP_SNAN;
	} else if (s->exponent == 0) {
		if (s->significand == 0)
			type |= VFP_ZERO;
		else
			type |= VFP_DENORMAL;
	}
	return type;
}

#ifndef DEBUG
#define vfp_single_normaliseround(sd,vsd,fpscr,except,func) __vfp_single_normaliseround(sd,vsd,fpscr,except)
u32 __vfp_single_normaliseround(int sd, struct vfp_single *vs, u32 fpscr, u32 exceptions);
#else
u32 vfp_single_normaliseround(int sd, struct vfp_single *vs, u32 fpscr, u32 exceptions, const char *func);
#endif

/*
 * Double-precision
 */
struct vfp_double {
	s16	exponent;
	u16	sign;
	u64	significand;
};

/*
 * VFP_REG_ZERO is a special register number for vfp_get_double
 * which returns (double)0.0.  This is useful for the compare with
 * zero instructions.
 */
#ifdef CONFIG_VFPv3
#define VFP_REG_ZERO	32
#else
#define VFP_REG_ZERO	16
#endif
extern u64 vfp_get_double(unsigned int reg);
extern void vfp_put_double(u64 val, unsigned int reg);

#define VFP_DOUBLE_MANTISSA_BITS	(52)
#define VFP_DOUBLE_EXPONENT_BITS	(11)
#define VFP_DOUBLE_LOW_BITS		(64 - VFP_DOUBLE_MANTISSA_BITS - 2)
#define VFP_DOUBLE_LOW_BITS_MASK	((1 << VFP_DOUBLE_LOW_BITS) - 1)

/*
 * The bit in an unpacked double which indicates that it is a quiet NaN
 */
#define VFP_DOUBLE_SIGNIFICAND_QNAN	(1ULL << (VFP_DOUBLE_MANTISSA_BITS - 1 + VFP_DOUBLE_LOW_BITS))

/*
 * Operations on packed single-precision numbers
 */
#define vfp_double_packed_sign(v)	((v) & (1ULL << 63))
#define vfp_double_packed_negate(v)	((v) ^ (1ULL << 63))
#define vfp_double_packed_abs(v)	((v) & ~(1ULL << 63))
#define vfp_double_packed_exponent(v)	(((v) >> VFP_DOUBLE_MANTISSA_BITS) & ((1 << VFP_DOUBLE_EXPONENT_BITS) - 1))
#define vfp_double_packed_mantissa(v)	((v) & ((1ULL << VFP_DOUBLE_MANTISSA_BITS) - 1))

/*
 * Unpack a double-precision float.  Note that this returns the magnitude
 * of the double-precision float mantissa with the 1. if necessary,
 * aligned to bit 62.
 */
static inline void vfp_double_unpack(struct vfp_double *s, s64 val)
{
	u64 significand;

	s->sign = vfp_double_packed_sign(val) >> 48;
	s->exponent = vfp_double_packed_exponent(val);

	significand = (u64) val;
	significand = (significand << (64 - VFP_DOUBLE_MANTISSA_BITS)) >> 2;
	if (s->exponent && s->exponent != 2047)
		significand |= (1ULL << 62);
	s->significand = significand;
}

/*
 * Re-pack a double-precision float.  This assumes that the float is
 * already normalised such that the MSB is bit 30, _not_ bit 31.
 */
static inline s64 vfp_double_pack(struct vfp_double *s)
{
	u64 val;
	val = ((u64)s->sign << 48) +
	      ((u64)s->exponent << VFP_DOUBLE_MANTISSA_BITS) +
	      (s->significand >> VFP_DOUBLE_LOW_BITS);
	return (s64)val;
}

static inline int vfp_double_type(struct vfp_double *s)
{
	int type = VFP_NUMBER;
	if (s->exponent == 2047) {
		if (s->significand == 0)
			type = VFP_INFINITY;
		else if (s->significand & VFP_DOUBLE_SIGNIFICAND_QNAN)
			type = VFP_QNAN;
		else
			type = VFP_SNAN;
	} else if (s->exponent == 0) {
		if (s->significand == 0)
			type |= VFP_ZERO;
		else
			type |= VFP_DENORMAL;
	}
	return type;
}

u32 vfp_double_normaliseround(int dd, struct vfp_double *vd, u32 fpscr, u32 exceptions, const char *func);

u32 vfp_estimate_sqrt_significand(u32 exponent, u32 significand);

/*
 * A special flag to tell the normalisation code not to normalise.
 */
#define VFP_NAN_FLAG	0x100

/*
 * A bit pattern used to indicate the initial (unset) value of the
 * exception mask, in case nothing handles an instruction.  This
 * doesn't include the NAN flag, which get masked out before
 * we check for an error.
 */
#define VFP_EXCEPTION_ERROR	((u32)-1 & ~VFP_NAN_FLAG)

/*
 * A flag to tell vfp instruction type.
 *  OP_SCALAR - this operation always operates in scalar mode
 *  OP_SD - the instruction exceptionally writes to a single precision result.
 *  OP_DD - the instruction exceptionally writes to a double precision result.
 *  OP_SM - the instruction exceptionally reads from a single precision operand.
 */
#define OP_SCALAR	(1 << 0)
#define OP_SD		(1 << 1)
#define OP_DD		(1 << 1)
#define OP_SM		(1 << 2)

struct op {
	u32 (* const fn)(int dd, int dn, int dm, u32 fpscr);
	u32 flags;
};

extern void vfp_save_state(void *location, u32 fpexc);
