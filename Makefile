.PHONY: build test demo scan install clean

build:
	go build -o bin/coherencelab ./cmd/coherencelab

test:
	go test ./... -count=1

demo:
	go run ./cmd/coherencelab demo --profiles profiles

scan:
	go run ./cmd/coherencelab scan --profiles profiles --profile chrome-131-win

install:
	go install ./cmd/coherencelab

clean:
	rm -rf bin/
