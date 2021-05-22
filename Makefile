.PHONY: loader packer

all: packer

debug: packer-debug
debug-antidebug: packer-debug-antidebug

# The packer requires the headerized loader, thus the loader is a dependency of
# the packer
packer: loader
	$(MAKE) -C packer

packer-debug: loader-debug
	$(MAKE) debug -C packer

packer-debug-antidebug: loader-debug-antidebug
	$(MAKE) debug-antidebug -C packer

loader:
	$(MAKE) -C loader

loader-debug:
	$(MAKE) debug -C loader

loader-debug-antidebug:
	$(MAKE) debug-antidebug -C loader

clean:
	$(MAKE) clean -C loader
	$(MAKE) clean -C packer
