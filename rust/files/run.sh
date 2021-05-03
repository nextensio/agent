#!/usr/bin/env sh

echo "$NXT_GW_1_IP $NXT_GW_1_NAME" >> /etc/hosts
echo "$NXT_GW_2_IP $NXT_GW_2_NAME" >> /etc/hosts
echo "$NXT_GW_3_IP $NXT_GW_3_NAME" >> /etc/hosts

echo 201 nxt >> /etc/iproute2/rt_tables
ip rule add fwmark 1 table nxt
iptables -A PREROUTING -i eth0 -t mangle -j MARK --set-mark 1
# Add a user who can run local traffic that goes via the agent
useradd -m foobar && echo "foobar:foobar" | chpasswd
iptables -A OUTPUT -t mangle -m owner --uid-owner foobar -j MARK --set-mark 1

2>/var/log/agent.log 1>/var/log/agent.log /rust/src/app/target/release/docker --controller $NXT_CONTROLLER --username $NXT_USERNAME --password $NXT_PWD &

tail -f /dev/null
