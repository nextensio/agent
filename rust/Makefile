VERSION=0.1
NAME=agent
USER=registry.gitlab.com/nextensio/rust-agent

.PHONY: all
all: build

.PHONY: build
build:
	cp ~/.ssh/gitlab_rsa files/
	docker build -f Dockerfile.build -t $(USER)/$(NAME)-build:$(VERSION) .
	docker create $(USER)/$(NAME)-build:$(VERSION)
	rm files/gitlab_rsa

.PHONY: clean
clean:
	rm files/gitlab_rsa

