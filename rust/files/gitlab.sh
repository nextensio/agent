#!/usr/bin/env sh

cat > /root/.gitconfig <<- EOM
[url "git@gitlab.com:"]
    insteadOf = https://gitlab.com/
EOM

cat > /root/.ssh/config  <<- EOM
Host gitlab.com
    StrictHostKeyChecking no
    IdentityFile /rust/files/gitlab_rsa
EOM
