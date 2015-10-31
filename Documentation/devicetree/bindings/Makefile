
.PHONY: bindingdocs

quiet_cmd_chk_binding = BINDING $@
define cmd_chk_binding
 (find $(srctree)/$(src) -name '*.yaml' | xargs cat | $(srctree)/scripts/yamltest.py)
endef

dtstree := $(srctree)/$(src)
yamlfiles := $(foreach d,$(dts-dirs), $(wildcard $(dtstree)/$(d)/*.yaml))

bindingdocs: FORCE
	$(call cmd,chk_binding)

