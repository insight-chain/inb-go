# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: ginb android ios ginb-cross swarm evm all test clean
.PHONY: ginb-linux ginb-linux-386 ginb-linux-amd64 ginb-linux-mips64 ginb-linux-mips64le
.PHONY: ginb-linux-arm ginb-linux-arm-5 ginb-linux-arm-6 ginb-linux-arm-7 ginb-linux-arm64
.PHONY: ginb-darwin ginb-darwin-386 ginb-darwin-amd64
.PHONY: ginb-windows ginb-windows-386 ginb-windows-amd64

GOBIN = $(shell pwd)/build/bin
GO ?= latest

ginb:
	build/env.sh go run build/ci.go install ./cmd/ginb
	@echo "Done building."
	@echo "Run \"$(GOBIN)/ginb\" to launch ginb."

swarm:
	build/env.sh go run build/ci.go install ./cmd/swarm
	@echo "Done building."
	@echo "Run \"$(GOBIN)/swarm\" to launch swarm."

all:
	build/env.sh go run build/ci.go install

android:
	build/env.sh go run build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/ginb.aar\" to use the library."

ios:
	build/env.sh go run build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/ginb.framework\" to use the library."

test: all
	build/env.sh go run build/ci.go test

lint: ## Run linters.
	build/env.sh go run build/ci.go lint

clean:
	./build/clean_go_build_cache.sh
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/golang/protobuf/protoc-gen-go
	env GOBIN= go install ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

swarm-devtools:
	env GOBIN= go install ./cmd/swarm/mimegen

# Cross Compilation Targets (xgo)

ginb-cross: ginb-linux ginb-darwin ginb-windows ginb-android ginb-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/ginb-*

ginb-linux: ginb-linux-386 ginb-linux-amd64 ginb-linux-arm ginb-linux-mips64 ginb-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-*

ginb-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/ginb
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep 386

ginb-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/ginb
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep amd64

ginb-linux-arm: ginb-linux-arm-5 ginb-linux-arm-6 ginb-linux-arm-7 ginb-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep arm

ginb-linux-arm-5:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/ginb
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep arm-5

ginb-linux-arm-6:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/ginb
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep arm-6

ginb-linux-arm-7:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/ginb
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep arm-7

ginb-linux-arm64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/ginb
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep arm64

ginb-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/ginb
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep mips

ginb-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/ginb
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep mipsle

ginb-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/ginb
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep mips64

ginb-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/ginb
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/ginb-linux-* | grep mips64le

ginb-darwin: ginb-darwin-386 ginb-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/ginb-darwin-*

ginb-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/ginb
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-darwin-* | grep 386

ginb-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/ginb
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-darwin-* | grep amd64

ginb-windows: ginb-windows-386 ginb-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/ginb-windows-*

ginb-windows-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/ginb
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-windows-* | grep 386

ginb-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/ginb
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/ginb-windows-* | grep amd64
