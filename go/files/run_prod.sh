#!/usr/bin/env sh

mkdir /opt/nextensio
echo $NXT_SECRET > /opt/nextensio/connector.key

if [ "$NXT_GATEWAY" == "" ];
then
  export NXT_GATEWAY=gateway.nextensio.net
fi

/go/bin/connector -gateway $NXT_GATEWAY -logfile /dev/stdout
