/* Disassembler using the XED library */
#include "perf.h"
#include "util/session.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/dis.h"

#include <xed/xed-interface.h>
#include <xed/xed-decode.h>
#include <xed/xed-decoded-inst-api.h>

static int dis_resolve(xed_uint64_t addr, char *buf, xed_uint32_t buflen,
		xed_uint64_t *off, void *data)
{
	struct perf_dis *x = data;
	struct addr_location al;

	memset(&al, 0, sizeof(struct addr_location));

	thread__find_addr_map(x->thread, x->cpumode, MAP__FUNCTION, addr, &al);
	if (!al.map)
		thread__find_addr_map(x->thread, x->cpumode, MAP__VARIABLE,
					addr, &al);
	al.cpu = x->cpu;
	al.sym = NULL;

	if (al.map)
		al.sym = map__find_symbol(al.map, al.addr);

	if (!al.sym)
		return 0;

	if (al.addr < al.sym->end)
		*off = al.addr - al.sym->start;
	else
		*off = al.addr - al.map->start - al.sym->start;
	snprintf(buf, buflen, "%s", al.sym->name);
	return 1;
}

/* x must be set up earlier */
char *disas_inst(struct perf_dis *x, uint64_t ip, u8 *inbuf, int inlen,
		 int *lenp)
{
	xed_decoded_inst_t inst;
	xed_print_info_t info;
	xed_error_enum_t err;
	static bool init;

	if (!init) {
		xed_tables_init();
		init = true;
	}

	if (lenp)
		*lenp = 0;

	xed_init_print_info(&info);
	info.syntax = XED_SYNTAX_ATT;
	info.disassembly_callback = dis_resolve;
	info.context = x;

	xed_decoded_inst_zero(&inst);
	if (x->is64bit)
		xed_decoded_inst_set_mode(&inst, XED_MACHINE_MODE_LONG_64,
				XED_ADDRESS_WIDTH_64b);
	else
		xed_decoded_inst_set_mode(&inst, XED_MACHINE_MODE_LEGACY_32,
				XED_ADDRESS_WIDTH_32b);

	err = xed_decode(&inst, (uint8_t *)inbuf, inlen);
	if (err != XED_ERROR_NONE) {
		snprintf(x->out, sizeof(x->out), "err: %s for %d bytes",
				xed_error_enum_t2str(err), inlen);
		return x->out;
	}
	if (lenp)
		*lenp = xed_decoded_inst_get_length(&inst);
	info.p = &inst;
	info.buf = x->out;
	info.blen = sizeof(x->out);
	info.runtime_address = ip;
	if (!xed_format_generic(&info))
		strcpy(x->out, "err: cannot format");
	return x->out;
}
