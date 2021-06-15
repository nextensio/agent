#!/usr/bin/env sh

echo "$NXT_GW_1_IP $NXT_GW_1_NAME" >> /etc/hosts
echo "$NXT_GW_2_IP $NXT_GW_2_NAME" >> /etc/hosts
echo "$NXT_GW_3_IP $NXT_GW_3_NAME" >> /etc/hosts

# Add a user who can run local traffic that goes via the agent
useradd -m foobar && echo "foobar:foobar" | chpasswd
iptables -A OUTPUT -t mangle -m owner --uid-owner foobar -j MARK --set-mark 14963

2>/var/log/agent.log 1>/var/log/agent.log  NXT_CONTROLLER=$NXT_CONTROLLER NXT_USERNAME=$NXT_USERNAME NXT_PWD=$NXT_PWD /rust/src/app/target/release/docker &

tail -f /dev/null
