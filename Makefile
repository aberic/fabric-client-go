PKGS_WITH_OUT_EXAMPLES := $(shell go list ./... | grep -v 'example/\|grpc/')
PKGS_WITH_OUT_CUSTOM := $(shell go list ./... | grep -v 'example/\|core/*\|grpc/')
GO_FILES := $(shell find . -name "*.go" -not -name "*_test.go" -not -path "./vendor/*" -not -path ".git/*" -print0 | xargs -0)
BASE_VERSION = 1.4.4
BASEIMAGE_RELEASE=0.4.18
COMPOSE_FILE=$(GOPATH)/src/github.com/aberic/fabric-client-go/example/league.com/docker-compose.yaml

export GOPROXY=https://goproxy.io
export GO111MODULE=on

checkTravis: overalls vet lint misspell staticcheck cyclo const veralls

checkLocal: overalls vet lint misspell staticcheck cyclo const test end

overalls:
	@echo "overalls"
	overalls -project=github.com/aberic/fabric-client-go -covermode=count -ignore='.git,_vendor,core'

vet:
	@echo "vet"
	go vet $(PKGS_WITH_OUT_EXAMPLES)

lint:
	@echo "golint"
	golint -set_exit_status $(PKGS_WITH_OUT_EXAMPLES)

misspell:
	@echo "misspell"
	misspell -source=text -error $(GO_FILES)

staticcheck:
	@echo "staticcheck"
	staticcheck $(PKGS_WITH_OUT_CUSTOM)

cyclo:
	@echo "gocyclo"
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
	go test -v -cover $(PKGS_WITH_OUT_CUSTOM)

end:
	@echo "end"
	docker-compose -f $(COMPOSE_FILE) down