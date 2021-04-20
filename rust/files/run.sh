#!/usr/bin/env sh

echo "$NXT_GW_1_IP $NXT_GW_1_NAME" >> /etc/hosts
echo "$NXT_GW_2_IP $NXT_GW_2_NAME" >> /etc/hosts
echo "$NXT_GW_3_IP $NXT_GW_3_NAME" >> /etc/hosts

# Gaah.. We need to rewrite this pkce.go in rust inside the docker/lib/src/main.rs. 
# Taking the lazy route at the moment and just passing in the token directly
TOKEN=`/rust/files/pkce "https://dev-635657.okta.com" $NXT_USERNAME $NXT_PWD` 
2>&1 /rust/src/app/target/release/docker --service "$NXT_SERVICES" --controller $NXT_CONTROLLER --access_token $TOKEN > /var/log/agent.log &

tail -f /dev/null
