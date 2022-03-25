VERSION=latest
NAME=go-agent
USER=registry.gitlab.com/nextensio/agent

.PHONY: all
all: build

.PHONY: build
build:
	cp ~/.ssh/gitlab_rsa files/
	docker build -f Dockerfile.build -t $(USER)/$(NAME):$(VERSION) .
	docker create $(USER)/$(NAME):$(VERSION)
	rm files/gitlab_rsa

prod:
	cp ~/.ssh/gitlab_rsa files/
	docker build -f Dockerfile.prod -t nextensio/extender:latest .
	docker create nextensio/extender:latest
	rm files/gitlab_rsa

.PHONY: clean
clean:
	rm files/gitlab_rsa

