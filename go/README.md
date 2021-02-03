# Agent lib and platforms

The agent code itself is compiled as a library, the goal is that this lib 
will be loaded as a CGO module from java (android) / swift (ios) / c# (Win)
platforms which implement a thin layer to just provide us with packets.

The platforms directory contains the platforms where the go code runs natively
(ie without any CGO etc..), today its just a docker test container platform,
tomorrow there can be a linux native agent in there for example

## Android agent

To compile the android agent, do the following

1. Install the android Studio. Do not install it using "snap install" or "apt-get install", 
   those always seem to end up with some issue or the other. Just follow the instructions
   at https://developer.android.com/studio/install to install. Once you install it, you 
   can launch it by saying "studio.sh" assuming you have set the PATHs properly as mentioned
   in the install link / docs above

2. Install the android 'ndk' - ndk allows C/C++ applications to be compiled in the android
   studio, again enable ndk via the android studio, do not install it seperately / manually
   https://developer.android.com/studio/projects/install-ndk

3. Open the platforms/android directory in the android studio. In the android studio UI, 
   somewhere in the top middle, look for an "edit configurations" drop down, and there add
   a configuration from the default template picking "Android App" from the template list,
   and then you can click the "play" button next to it to compile and run the app.

4. To run the app in an emulator, in the devices list next to the configurations drop down
   (mentioned above), you will see an "AVD manager". Click on that device and start it, 
   but to start it you need the following
   a. Make sure your VM is enabled with Intel VT-X extension. Google for it and you will
      find how to do that for your hardware/host OS
   b. Install kvm - sudo apt install qemu-kvm
   c. chown <your username> /dev/kvm

   Now start the device. The chown above disappears after a while and some kvm manager resets
   the ownership back to root. So if you try to start again after a while it might complain
   of /dev/kvm ownership issues, then just do a chown again. Need to find a proper long term
   fix for this

5. Now if we click play on the studio, the app will get launched into the emulator 

6. We can also do a commmand line compile by saying "./gradlew assembleRelease" in the 
   platforms/android directory

## Connector

The connector is expected to run on one platform which is linux, and we will
most likely package the connector as a docker container
