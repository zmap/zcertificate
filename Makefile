all: zcertificate

zcertificate:
	cd cmd && go build && mv cmd ../zcertificate

.PHONY: zcertificate clean

clean:
	rm -f cmd/cmd zcertificate
