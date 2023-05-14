grpc:
	cd pkg/proto && protoc --go_out=. --go_opt=paths=source_relative \
        --go-grpc_out=. --go-grpc_opt=paths=source_relative \
        --plugin=protoc-gen-go=/Users/colby/go/bin/protoc-gen-go \
        --plugin=protoc-gen-go-grpc=/Users/colby/go/bin/protoc-gen-go-grpc \
        broseph.proto