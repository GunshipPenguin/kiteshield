.PHONY: loader packer

all: packer

debug: packer_debug
debug-antidebug: packer_debug_antidebug

# The packer requires the headerized loader, thus the loader is a dependency of
# the packer
packer: loader
	$(MAKE) -C packer

packer_debug: loader_debug
	$(MAKE) debug -C packer

packer_debug_antidebug: loader_debug_antidebug
	$(MAKE) debug-antidebug -C packer

loader:
	$(MAKE) -C loader

loader_debug:
	$(MAKE) debug -C loader

loader_debug_antidebug:
	$(MAKE) debug-antidebug -C loader

clean:
	$(MAKE) clean -C loader
	$(MAKE) clean -C packer
