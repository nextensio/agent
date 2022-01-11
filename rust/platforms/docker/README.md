# Pre-Requisites

When compiling an image to run in linux, your ubuntu machine on which you compile needs to have the below

sudo apt-get install libx11-dev libxext-dev libxft-dev libxinerama-dev libxcursor-dev libxrender-dev libxfixes-dev libpango1.0-dev libgl1-mesa-dev libglu1-mesa-dev

The machine on which you RUN the agent doesnt need it, we need it only when compiling

Also you need to manually install the latest cmake from https://cmake.org/download/ - untar the code and run the below to install
./bootstrap
make -j$(nproc)
sudo make install

