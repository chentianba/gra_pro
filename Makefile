SUBDIRS=bf cf tstat-dpdk
ROOTDIR = $(shell pwd)
export ROOTDIR

all:
	@echo $(SUBDIRS);
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $${dir}; \
	done
clean:
	@for dir in $(SUBDIRS); \
	do \
		$(MAKE) -C $${dir} clean; \
	done
