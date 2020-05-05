PKGS_WITH_OUT_EXAMPLES := $(shell go list ./... | grep -v 'example/')
PKGS_WITH_OUT_EXAMPLES_AND_UTILS := $(shell go list ./... | grep -v 'example/\|utils/')
GO_FILES := $(shell find . -name "*.go" -not -name "*_test.go" -not -path "./vendor/*" -not -path ".git/*" -print0 | xargs -0)
BASE_VERSION = 1.4.4
BASEIMAGE_RELEASE=0.4.18
COMPOSE_FILE=$(GOPATH)/src/github.com/aberic/fabric-client-go/example/league.com/docker-compose.yaml

export GOPROXY=https://goproxy.io
export GO111MODULE=on

checkTravis: overalls vet lint misspell staticcheck cyclo const veralls test

checkLocal: images overalls vet lint misspell staticcheck cyclo const test end

images:
	@echo "docker pull images"
    docker pull hyperledger/fabric-baseos:$(BASEIMAGE_RELEASE)
    docker pull hyperledger/fabric-orderer:$(BASE_VERSION)
    docker pull hyperledger/fabric-peer:$(BASE_VERSION)
    docker pull hyperledger/fabric-ccenv:$(BASE_VERSION)

overalls:
	@echo "overalls"
	overalls -project=github.com/aberic/fabric-client-go -covermode=count -ignore='.git,_vendor'

vet:
	@echo "vet"
	go vet $(PKGS_WITH_OUT_EXAMPLES)

lint:
	@echo "golint"
	golint -set_exit_status $(PKGS_WITH_OUT_EXAMPLES_AND_UTILS)

misspell:
	@echo "misspell"
	misspell -source=text -error $(GO_FILES)

staticcheck:
	@echo "staticcheck"
	staticcheck $(PKGS_WITH_OUT_EXAMPLES)

cyclo:
	@echo "gocyclo"
	gocyclo -over 15 $(GO_FILES)
	gocyclo -top 10 $(GO_FILES)

const:
	@echo "goconst"
	goconst $(PKGS_WITH_OUT_EXAMPLES)

veralls:
	@echo "goveralls"
	goveralls -coverprofile=overalls.coverprofile -service=travis-ci -repotoken $(COVERALLS_TOKEN)

traviscodecovtest:
	@echo "travistest"
	go test -race -coverprofile=coverage.txt -covermode=atomic

test:
	@echo "test"
	go test -v -cover $(PKGS_WITH_OUT_EXAMPLES)

end:
	@echo "end"
	docker-compose -f $(COMPOSE_FILE) down