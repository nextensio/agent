#!/usr/bin/env sh

echo "$NXT_GW_1_IP $NXT_GW_1_NAME" >> /etc/hosts
echo "$NXT_GW_2_IP $NXT_GW_2_NAME" >> /etc/hosts
echo "$NXT_GW_3_IP $NXT_GW_3_NAME" >> /etc/hosts

2>/var/log/agent.log 1>/var/log/agent.log /rust/src/app/target/release/docker --controller $NXT_CONTROLLER --username $NXT_USERNAME --password $NXT_PWD &

tail -f /dev/null
