To be able to compile rust, you need to install the following

0. install rust compile of course

1. sudo apt install libssl-dev pkg-config

2. You need to add the below to your ~/.cargo/config file (create one if doesnt exist)
   to be able to run build_android.sh to compile agent for android

[build]
target = "x86_64-unknown-linux-gnu"

[target.aarch64-linux-android]
ar = ".NDK/arm64/bin/aarch64-linux-android-ar"
linker = ".NDK/arm64/bin/aarch64-linux-android-clang"

[target.armv7-linux-androideabi]
ar = ".NDK/arm/bin/arm-linux-androideabi-ar"
linker = ".NDK/arm/bin/arm-linux-androideabi-clang"

[target.i686-linux-android]
ar = ".NDK/x86/bin/i686-linux-android-ar"
linker = ".NDK/x86/bin/i686-linux-android-clang"

[target.x86_64-linux-android]
ar = ".NDK/x86_64/bin/x86_64-linux-android-ar"
linker = ".NDK/x86_64/bin/x86_64-linux-android-clang"

3. For each of the "targets" above do a rustup target add <target>

4. As seen above, it refers to an "NDK" - thats the android toolchain which you have to download
