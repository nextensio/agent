# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

# These are generally passed to us by xcode, but we set working defaults for standalone compilation too.
ARCHS ?= x86_64 #TODO: add arm64 to this list once we support apple silicon
SDK_NAME ?= macosx
SDKROOT ?= $(shell xcrun --sdk $(SDK_NAME) --show-sdk-path)
CONFIGURATION_BUILD_DIR ?= $(CURDIR)/out
CONFIGURATION_TEMP_DIR ?= $(CURDIR)/.tmp

export CC ?= clang
LIPO ?= lipo
DESTDIR ?= $(CONFIGURATION_BUILD_DIR)
BUILDDIR ?= $(CONFIGURATION_TEMP_DIR)/nextensio-go-bridge

CFLAGS_PREFIX := $(if $(DEPLOYMENT_TARGET_CLANG_FLAG_NAME),-$(DEPLOYMENT_TARGET_CLANG_FLAG_NAME)=$($(DEPLOYMENT_TARGET_CLANG_ENV_NAME)),) -isysroot $(SDKROOT) -arch
GOARCH_arm64 := arm64
GOARCH_x86_64 := amd64

build: $(DESTDIR)/libnxt-go.a
version-header: $(DESTDIR)/nextensio-go-version.h

REAL_GOROOT := $(shell go env GOROOT 2>/dev/null)
export GOROOT := $(BUILDDIR)/goroot
$(GOROOT)/.prepared:
	[ -n "$(REAL_GOROOT)" ]
	mkdir -p "$(GOROOT)"
	rsync -a --delete --exclude=pkg/obj/go-build "$(REAL_GOROOT)/" "$(GOROOT)/"
	cat goruntime-*.diff | patch -p1 -f -N -r- -d "$(GOROOT)"
	touch "$@"

define libnxt-go-a
$(BUILDDIR)/libnxt-go-$(1).a: export CGO_ENABLED := 1
$(BUILDDIR)/libnxt-go-$(1).a: export CGO_CFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR)/libnxt-go-$(1).a: export CGO_LDFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR)/libnxt-go-$(1).a: export GOOS := darwin
$(BUILDDIR)/libnxt-go-$(1).a: export GOARCH := $(GOARCH_$(1))
$(BUILDDIR)/libnxt-go-$(1).a: $(GOROOT)/.prepared go.mod
	go build -tags ios -ldflags=-w -trimpath -v -o "$(BUILDDIR)/libnxt-go-$(1).a" -buildmode c-archive
	rm -f "$(BUILDDIR)/libnxt-go-$(1).h"
endef
$(foreach ARCH,$(ARCHS),$(eval $(call libnxt-go-a,$(ARCH))))

$(DESTDIR)/nextensio-go-version.h: $(GOROOT)/.prepared go.mod
	go list -m golang.zx2c4.com/nextensio | sed -n 's/.*v\([0-9.]*\).*/#define WIREGUARD_GO_VERSION "\1"/p' > "$@"

$(DESTDIR)/libnxt-go.a: $(foreach ARCH,$(ARCHS),$(BUILDDIR)/libnxt-go-$(ARCH).a)
	@mkdir -vp "$(DESTDIR)"
	$(LIPO) -create -output "$@" $^

clean:
	rm -rf "$(BUILDDIR)" "$(DESTDIR)/libnxt-go.a" "$(DESTDIR)/nextensio-go-version.h"

install: build

.PHONY: clean build version-header install
