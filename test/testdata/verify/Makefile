
export CAPATH=./ca
SIGNTOOL=./ssl-tools.sh

init:
	mkdir -p ./ssl
	mkdir -p ./ca
	$(SIGNTOOL) install-mkcert

gen-trusted-ssl: init
	$(SIGNTOOL) copy-trusted-ca-from-mkcert trusted

	CANAME=trusted OUTPATH=./ssl $(SIGNTOOL) d \
		trusted-localhost-ok localhost
	CANAME=trusted OUTPATH=./ssl $(SIGNTOOL) d \
		trusted-localhost-expired localhost 0

gen-selfsigned-ssl: init
	CANAME=selfsigned $(SIGNTOOL) c

	CANAME=selfsigned OUTPATH=./ssl $(SIGNTOOL) d \
		selfsigned-localhost-ok localhost
	CANAME=selfsigned OUTPATH=./ssl $(SIGNTOOL) d \
		selfsigned-localhost-expired localhost 0
	CANAME=selfsigned OUTPATH=./ssl $(SIGNTOOL) s \
		selfsigned-localhost-simple localhost


proto-gen-install:
	GO111MODULE=on go get google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
	GO111MODULE=on go get google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1

gen-proto: proto-gen-install
	protoc \
		--go_out=. \
    	--go-grpc_out=. \
		simple.proto

run-servers:
	docker-compose up --build -d grpcserver
	docker-compose up --force-recreate -d \
		grpc-selfsigned-ok \
		grpc-selfsigned-expired \
		grpc-selfsigned-simple \
		grpc-trusted-ok \
		grpc-trusted-expired
	docker-compose up --build -d httpserver
	docker-compose up --force-recreate -d \
		http-selfsigned-ok \
		http-selfsigned-expired \
		http-selfsigned-simple \
		http-trusted-ok \
		http-trusted-expired

test:
	go test -v ./...
