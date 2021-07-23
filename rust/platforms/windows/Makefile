PREFIX ?= ./
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "1.0.0")" && \
	[ "$$(cat version.go 2>/dev/null)" != "1.0.0" ] && \
	echo "1.0.0" > version.go && \
	@$(MAKE) nxt-windows

$(eval $(call download,wintun.zip,https://www.wintun.net/builds/wintun-0.12.zip,eba90e26686ed86595ae0a6d4d3f4f022924b1758f5148a32a91c60cc6e604df))

nxt-windows: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: nxt-windows
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/nxt-windows"

test:
	go test -v ./...

clean:
	rm -f nxt-windows

.PHONY: all clean test install generate-version-and-build
