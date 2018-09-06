# SPDX-License-Identifier: GPL-2.0
DT_DOC_CHECKER ?= dt-doc-validate
DT_EXTRACT_EX ?= dt-extract-example

quiet_cmd_chk_binding = CHKDT   $<
      cmd_chk_binding = (set -e; \
                         $(DT_DOC_CHECKER) $< ; \
                         mkdir -p $(dir $@) ; \
                         $(DT_EXTRACT_EX) $< > $@ )

$(obj)/%.example.dts: $(src)/%.yaml FORCE
	$(call if_changed,chk_binding)

DT_MK_SCHEMA ?= dt-mk-schema
DT_TMP_SCHEMA := .schema.yaml.tmp
extra-y += $(DT_TMP_SCHEMA)

quiet_cmd_mk_schema = SCHEMA  $@
      cmd_mk_schema = mkdir -p $(obj); \
                      $(DT_MK_SCHEMA) -o $@ $(srctree)/$(src)

DT_DOCS = $(shell cd $(srctree)/$(src) && find * -name '*.yaml')
DTS_EXAMPLES = $(patsubst %.yaml,%.example.dts, $(DT_DOCS))
extra-y += $(DTS_EXAMPLES)

DTBS = $(patsubst %.yaml,%.example.dtb, $(DT_DOCS))
extra-y += $(DTBS)

$(obj)/$(DT_TMP_SCHEMA): $(addprefix $(obj)/, $(DTBS)) FORCE
	$(call if_changed,mk_schema)
