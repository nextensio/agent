#!/usr/bin/env sh

echo "$NXT_GW_1_IP $NXT_GW_1_NAME" >> /etc/hosts
echo "$NXT_GW_2_IP $NXT_GW_2_NAME" >> /etc/hosts
echo "$NXT_GW_3_IP $NXT_GW_3_NAME" >> /etc/hosts

# Serve from files to emulate a private webserver
sed -i "s/REPLACE_AGENT_NAME/$NXT_AGENT_NAME/g" /go/files/index.html
mkdir -p /var/www/html/
mkdir -p /var/cache/lighttpd/uploads
cp /go/files/index.html /var/www/html/index.lighttpd.html
lighttpd -f /etc/lighttpd/lighttpd.conf

2>&1 /go/bin/connector -service "$NXT_SERVICES" -controller $NXT_CONTROLLER -username $NXT_USERNAME -password $NXT_PWD > /var/log/connector.log &

tail -f /dev/null
