# You might have to say "Set-ExecutionPolicy -ExecutionPolicy Unrestricted" in power-shell
# to be able to run  a powershell script
cargo build --target x86_64-pc-windows-gnu --release
cp ..\target\x86_64-pc-windows-gnu\release\libnextensio.a ..\platforms\windows\
