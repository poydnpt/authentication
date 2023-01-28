package main

import (
	"context"
	"flag"
	"log"
	"time"

	pb "github.com/poydnpt/authentication/authentication"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultName     = "test001"
	defaultPassword = "P@ssw0rd"
	defaultToken    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzQ5MDcwMjN9.mNtehEVDIcA76y2DUka0dlAcyojBTVyUJse6hNB3nAA"
)

var (
	// addr = flag.String("addr", "localhost:50051", "the address to connect to")
	addr     = flag.String("addr", "localhost:8080", "the address to connect to")
	username = flag.String("username", defaultName, "Username")
	password = flag.String("password", defaultPassword, "Password")
	token    = flag.String("token", defaultToken, "Token")
)

func main() {
	flag.Parse()
	// Set up a connection to the server.
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAuthenticationClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Login
	r, err := c.Login(ctx, &pb.LoginRequest{Username: *username, Password: *password})
	if err != nil {
		log.Fatalf("could not login: %v", err)
	}
	log.Printf("Token: %s", r.GetAccessToken())

	// // Validate Token
	// ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+*token)
	// r, err := c.ValidateToken(ctx, &pb.ValidateRequest{})
	// if err != nil {
	// 	log.Fatalf("could not validate: %v", err)
	// }
	// log.Printf("status: %s", r.GetTokenStatus())

	// // Logout
	// r, err := c.Logout(ctx, &pb.LogoutRequest{Username: *username})
	// if err != nil {
	// 	log.Fatalf("could not logout: %v", err)
	// }
	// log.Printf("Logout status: %s", r.GetStatus)
}
