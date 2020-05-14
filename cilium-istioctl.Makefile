export VERSION = $(shell grep "ENV TAG " Dockerfile | cut -d ' ' -f 3)
BUILD_DIR := $(shell $(MAKE) show-target | tail -n 1)/release
RELEASE_DIR := cilium-istioctl-$(VERSION)

RELEASE_TARGETS := linux.tar.gz osx.tar.gz win.zip
RELEASE_FILES := $(foreach target,$(RELEASE_TARGETS),$(RELEASE_DIR)/cilium-istioctl-$(VERSION)-$(target))
RELEASE_FILES += $(foreach archive,$(RELEASE_FILES),$(archive).sha256)

all: build $(RELEASE_DIR) $(RELEASE_FILES)

$(RELEASE_DIR):
	mkdir -p $@

%.sha256: %
	cd $(dir $<) && sha256sum $(notdir $<) > $(notdir $@)

$(RELEASE_DIR)/cilium-istioctl-$(VERSION)-win.zip: $(BUILD_DIR)/istioctl-win.exe
	cp $< cilium-istioctl.exe
	-rm $@
	zip $@ cilium-istioctl.exe
	rm cilium-istioctl.exe

$(RELEASE_DIR)/cilium-istioctl-$(VERSION)-%.tar.gz: $(BUILD_DIR)/istioctl-%
	cp $< cilium-istioctl
	tar cvzf $@ cilium-istioctl
	rm cilium-istioctl

.PHONY: build
build:
	BUILD_WITH_CONTAINER=1 $(MAKE) istioctl-all
