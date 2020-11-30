.PHONY: loader packer

all: loader packer

debug: loader_debug packer_debug

packer:
	$(MAKE) -C packer

packer_debug:
	$(MAKE) debug -C packer

loader:
	$(MAKE) -C loader

loader_debug:
	$(MAKE) debug -C loader

clean:
	$(MAKE) clean -C loader
	$(MAKE) clean -C packer
