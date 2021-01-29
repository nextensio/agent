FROM golang:1.15

# Stuff required for selenium automated login script to work (login.py)
# Note that the docker container is huge because of these chromium stuff,
# we need this only for the test/automation environment
RUN apt update
RUN apt install -y python3-pip unzip
RUN pip3 install chromedriver
RUN pip3 install selenium
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt install -y ./google-chrome-stable_current_amd64.deb
RUN rm ./google-chrome-stable_current_amd64.deb
RUN wget https://chromedriver.storage.googleapis.com/88.0.4324.96/chromedriver_linux64.zip
RUN unzip chromedriver_linux64.zip 
RUN mv chromedriver /usr/bin/
RUN rm chromedriver_linux64.zip 

# For emulating a private URL webservice
RUN apt-get install -y lighttpd
RUN mkdir /etc/lighttpd/certs
COPY files/http/certs/* /etc/lighttpd/certs/
RUN chmod 400 /etc/lighttpd/certs/lighttpd.pem
COPY files/http/config/lighttpd.conf /etc/lighttpd/lighttpd.conf
RUN chmod 777 /var/log/lighttpd

# The login files required for okta onboarding
RUN mkdir -p /var/okta/
COPY files/okta/* /var/okta/

# Now compile the code
WORKDIR /go/src/app
RUN mkdir -p /root/.ssh
RUN mkdir -p /go/files/
COPY files/ /go/files
RUN chmod +x /go/files/gitlab.sh
RUN /go/files/gitlab.sh
RUN go env -w GOPRIVATE="gitlab.com"
RUN go env -w GO111MODULE="on"
COPY . .
RUN go get -d -v ./... \
    && go install -v ./...
RUN rm /go/files/gitlab_rsa

RUN chmod +x /go/files/run.sh
EXPOSE 8180/tcp 8081/tcp 8080/tcp
CMD /go/files/run.sh
