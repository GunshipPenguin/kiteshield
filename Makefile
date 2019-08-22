all: loaders packer

debug: loaders_debug packer 

packer:
	$(MAKE) -C src/packer

loaders:
	$(MAKE) -C src/loaders

loaders_debug:
	$(MAKE) debug -C src/loaders

clean:
	$(MAKE) clean -C src/loaders
	$(MAKE) clean -C src/packer
