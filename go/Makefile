VERSION=0.1
NAME=agent
USER=registry.gitlab.com/nextensio/agent

.PHONY: all
all: deploy

.PHONY: deploy
deploy:
	cp ~/.ssh/gitlab_rsa files/
	docker build -f Dockerfile -t $(USER)/$(NAME)-deploy:$(VERSION) .
	docker create $(USER)/$(NAME)-deploy:$(VERSION)
	rm files/gitlab_rsa

.PHONY: clean
clean:
	rm files/gitlab_rsa

