FROM node:14.8.0

# Create app directory
WORKDIR /usr/src/app

# Stuff required for selenium automated login script to work (login.py)
RUN apt update
RUN apt install -y python3-pip
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

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./
COPY files ./

RUN npm install
RUN npm install google-protobuf
RUN npm install log-timestamp
RUN npm install ringbufferjs

# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY . .

EXPOSE 8180/tcp 8081/tcp 8080/tcp
CMD ./files/run.sh
