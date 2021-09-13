#!/usr/bin/env sh

echo "$NXT_GW_1_IP $NXT_GW_1_NAME" >> /etc/hosts
echo "$NXT_GW_2_IP $NXT_GW_2_NAME" >> /etc/hosts
echo "$NXT_GW_3_IP $NXT_GW_3_NAME" >> /etc/hosts

mkdir /opt/nextensio
echo $NXT_SECRET > /tmp/connector.key
grep -o '".*"' /tmp/connector.key | sed 's/"//g' > /opt/nextensio/connector.key

# Serve from files to emulate a private webserver. NXT_GW_3_NAME is the name of
# the server hosted by lighthttpd
if [ "$NXT_GW_3_NAME" != "" ];
then
    sed -i "s/REPLACE_AGENT_NAME/$NXT_AGENT_NAME/g" /go/files/index.html
    mkdir -p /var/www/html/
    mkdir -p /var/cache/lighttpd/uploads
    cp /go/files/index.html /var/www/html/index.lighttpd.html
    lighttpd -f /etc/lighttpd/lighttpd.conf

    2>/var/log/connector.log 1>/var/log/connector.log /go/bin/connector -controller $NXT_CONTROLLER -idp $IDP_URI -client $CLIENT_ID&
else
    # Launch connector listening on ports 80 and 443
    2>/var/log/connector.log 1>/var/log/connector.log /go/bin/connector -controller $NXT_CONTROLLER -idp $IDP_URI -client $CLIENT_ID -ports 80,443&

fi

tail -f /dev/null
