VERSION=0.1
NAME=agent
USER=registry.gitlab.com/nextensio/agent

.PHONY: all
all: deploy

.PHONY: deploy
deploy:
	rm -r -f files/version
	echo $(VERSION) > files/version
	docker build -f Dockerfile -t $(USER)/$(NAME)-deploy:$(VERSION) .
	docker create $(USER)/$(NAME)-deploy:$(VERSION)

.PHONY: clean
clean:
	-rm -r -f files/version

