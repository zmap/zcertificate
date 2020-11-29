CMDS = zcertificate
CMD_PREFIX = ./cmd/
BUILD = $(GO_ENV) go build
TEST = $(GO_ENV) GORACE=halt_on_error=1 go test -v -race

all: $(CMDS)

zcertificate: $(CMD_PREFIX)$(@)
	$(BUILD) $(CMD_PREFIX)$(@)

clean:
	rm -f $(CMDS)

test:
	$(TEST) ./...

.PHONY: clean test zcertificate
