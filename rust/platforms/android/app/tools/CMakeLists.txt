cmake_minimum_required(VERSION 3.4.1)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

# Work around https://github.com/android-ndk/ndk/issues/602
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold")

file(GLOB DUMMY_SOURCES dummy/*.c)
add_executable(libdummy.so ${DUMMY_SOURCES})
target_include_directories(libdummy.so PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/dummy/")
target_compile_options(libdummy.so PUBLIC -O3 -std=gnu11 -D_GNU_SOURCE)

add_custom_target(libnxt.so WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libnxt/" COMMENT "Building Nextensio Lib" VERBATIM COMMAND make
    ANDROID_ARCH_NAME=${ANDROID_ARCH_NAME}
    ANDROID_C_COMPILER=${ANDROID_C_COMPILER}
    ANDROID_TOOLCHAIN_ROOT=${ANDROID_TOOLCHAIN_ROOT}
    ANDROID_LLVM_TRIPLE=${ANDROID_LLVM_TRIPLE}
    ANDROID_SYSROOT=${ANDROID_SYSROOT}
    ANDROID_PACKAGE_NAME=${ANDROID_PACKAGE_NAME}
    ANDROID_TOOLCHAIN_NAME=${ANDROID_TOOLCHAIN_NAME}
    GRADLE_USER_HOME=${GRADLE_USER_HOME}
    CFLAGS=${CMAKE_C_FLAGS}\ -Wno-unused-command-line-argument
    LDFLAGS=${CMAKE_SHARED_LINKER_FLAGS}\ -fuse-ld=gold
    DESTDIR=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
    BUILDDIR=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../generated-src
)

# Hack to make it actually build as part of the default target
add_dependencies(libdummy.so libnxt.so)
