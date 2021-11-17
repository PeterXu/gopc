OS := $(shell uname)
ARCH := $(shell uname -m)

ifeq ($(OS)-$(ARCH),Darwin-x86_64)
PKG_PATH := /usr/local/lib/pkgconfig
build:
	@PKG_CONFIG_PATH=$(PKG_PATH) go build -ldflags "-s -w"
else
build:
	@go build -ldflags "-s -w"
endif
