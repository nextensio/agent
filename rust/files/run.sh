#!/usr/bin/env bash

echo "$NXT_GW_1_IP $NXT_GW_1_NAME" >> /etc/hosts
echo "$NXT_GW_2_IP $NXT_GW_2_NAME" >> /etc/hosts
echo "$NXT_GW_3_IP $NXT_GW_3_NAME" >> /etc/hosts

# Serve from files to emulate a private webserver
sed -i "s/REPLACE_AGENT_NAME/$NXT_AGENT_NAME/g" /rust/files/index.html
cp /rust/files/index.html /var/www/html/index.lighttpd.html
/etc/init.d/lighttpd start

# login.py is smart enough to retry till node launches the agent
2>&1 /rust/files/login.py $NXT_USERNAME $NXT_PWD > /var/log/login.log &

# If node dies because of some exception etc.., the container will restart
if [ "$NXT_AGENT" == "true" ];
then
    2>&1 /rust/src/app/target/release/docker --service "$NXT_SERVICES" --controller $NXT_CONTROLLER  > /var/log/agent.log &
else
    # Rust only supports agent
    exit 1
fi

tail -f /dev/null