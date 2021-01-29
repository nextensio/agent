# Agent lib and platforms

The agent code itself is compiled as a library, the goal is that this lib 
will be loaded as a CGO module from java (android) / swift (ios) / c# (Win)
platforms which implement a thin layer to just provide us with packets.

The platforms directory contains the platforms where the go code runs natively
(ie without any CGO etc..), today its just a docker test container platform,
tomorrow there can be a linux native agent in there for example
