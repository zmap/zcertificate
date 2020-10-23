CMDS = zcertificate
CMD_PREFIX = ./cmd/
GO_ENV = GO111MODULE=on
BUILD = $(GO_ENV) go build
TEST = $(GO_ENV) GORACE=halt_on_error=1 go test -race

all: $(CMDS)

zcertificate: $(CMD_PREFIX)$(@)
	$(BUILD) $(CMD_PREFIX)$(@)

clean:
	rm -f $(CMDS)

test:
	$(TEST) ./...

.PHONY: clean test zcertificate
