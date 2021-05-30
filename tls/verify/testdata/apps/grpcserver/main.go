package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	pb "github.com/gebv/grpc-conn-err-human-msg/api/services/simple"
	"google.golang.org/grpc"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	addr := ":" + port
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Println("Listen:", addr)

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterSimpleServiceServer(grpcServer, &SimpleServer{})
	grpcServer.Serve(lis)
}

type SimpleServer struct {
	pb.UnsafeSimpleServiceServer
}

var _ pb.SimpleServiceServer = (*SimpleServer)(nil)

func (s *SimpleServer) Echo(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	log.Println("simple/SimpleServer.Echo: Request")
	return &pb.EchoResponse{
		Out: fmt.Sprintf("in:%q", req.GetIn()),
	}, nil
}
