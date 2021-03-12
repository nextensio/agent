BUILDDIR ?= $(CURDIR)/build
DESTDIR ?= $(CURDIR)/out

RUST_TARGET_MAP_x86 := i686-linux-android
RUST_TARGET_MAP_x86_64 := x86_64-linux-android
RUST_TARGET_MAP_arm := armv7-linux-androideabi
RUST_TARGET_MAP_arm64 := aarch64-linux-android

# Read PLATFORMS.md on where to find these compilers / how to generate them,
# and how to set the PATH variable to point to them etc..
CLANG_MAP_x86 := i686-linux-android-clang
CLANG_MAP_x86_64 := x86_64-linux-android-clang
CLANG_MAP_arm := arm-linux-androideabi-clang
CLANG_MAP_arm64 := aarch64-linux-android-clang

CLANG_FLAGS := --target=$(ANDROID_LLVM_TRIPLE) --gcc-toolchain=$(ANDROID_TOOLCHAIN_ROOT) --sysroot=$(ANDROID_SYSROOT)
CLANG = $(CLANG_MAP_$(ANDROID_ARCH_NAME))

default: $(DESTDIR)/libnxt.so

$(DESTDIR)/libnxt.so: jni.c
	mkdir -p $(DESTDIR)
	$(CLANG) -Oz -flto -ffunction-sections -fdata-sections -dead_strip -I $(ANDROID_TOOLCHAIN_ROOT)/sysroot/usr/include jni.c -L ../../../../../target/$(RUST_TARGET_MAP_$(ANDROID_ARCH_NAME))/release/ -l nextensio -l log -shared -o "$@"

.DELETE_ON_ERROR:
