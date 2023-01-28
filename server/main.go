package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/golang-jwt/jwt"
	pb "github.com/poydnpt/authentication/authentication"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	port   = flag.Int("port", 50051, "The server port")
	cMongo *mongo.Client
	cRedis *redis.Client
)

type server struct {
	pb.UnimplementedAuthenticationServer
}

func main() {
	fmt.Println("Starting Authentication server")
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))

	if err != nil {
		log.Fatalf("Error while listening : %v", err)
	}

	client, ctx, cancel, err := connectMongo("mongodb://localhost:27017")
	if err != nil {
		panic(err)
	}

	if client != nil {
		cMongo = client
	}
	fmt.Println("Connect Mongo Successfully..")

	defer closeMongo(client, ctx, cancel)

	clientRedis := connectRedis()
	if client != nil {
		cRedis = clientRedis
	}
	fmt.Println("Connect Redis Successfully..")

	// // insert user data
	// insertUsers(ctx)

	// // list all users
	// getAllUsers(ctx)

	s := grpc.NewServer()
	pb.RegisterAuthenticationServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Error while serving : %v", err)
	}
}

func (*server) Login(context context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	fmt.Println("Got a new Login request")
	username := req.Username
	password := []byte(req.Password)

	//Get token from Redis in case of user is still login
	val, e := cRedis.Get(username).Result()
	if e != nil {
		fmt.Println(e)
	}

	if len(val) > 0 {
		response := &pb.LoginResponse{
			AccessToken: val,
		}
		fmt.Println("Token from redis")
		return response, nil
	}

	result := findUserByUsername(cMongo, context, username)

	if (result == User{}) == true {
		return nil, status.Errorf(codes.Unauthenticated, "Username not found")
	}

	// Hashing the password with the default cost of 10
	// hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	// if err != nil {
	// 	panic(err)
	// }
	// err = bcrypt.CompareHashAndPassword(hashedPassword, test)

	// Comparing the password with the hash
	err := bcrypt.CompareHashAndPassword([]byte(result.PASSWORD), password)
	fmt.Println(err) // nil means it is a match
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Username or Password is not correct")
	}
	fmt.Println("Login Successfully..")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
		Issuer:    username,
	})

	ss, err := token.SignedString([]byte("MySignatureTest"))
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	//Save token into Redis
	err = cRedis.Set(username, ss, 0).Err()
	if err != nil {
		panic(err)
	}
	fmt.Println("Already add token to Redis for username: ", username)

	response := &pb.LoginResponse{
		AccessToken: ss,
	}
	return response, nil
}

type customClaims struct {
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
	jwt.StandardClaims
}

func (*server) ValidateToken(context context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	fmt.Println("Got a new ValidateToken request")

	md, ok := metadata.FromIncomingContext(context)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	s := values[0]
	token := strings.TrimPrefix(s, "Bearer ")

	if err := validateToken(token); err != nil {
		return &pb.ValidateResponse{
			TokenStatus: "Invalid Token",
		}, status.Errorf(codes.PermissionDenied, "Invalid Token")
	}

	response := &pb.ValidateResponse{
		TokenStatus: "Valid Token",
	}

	return response, nil
}

func (*server) Logout(context context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	fmt.Println("Got a new Logout request")

	md, ok := metadata.FromIncomingContext(context)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	s := values[0]
	token := strings.TrimPrefix(s, "Bearer ")

	t, err := jwt.ParseWithClaims(token, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte("MySignatureTest"), nil
	})

	var username = ""
	claims, ok := t.Claims.(*customClaims)
	fmt.Println("iss:", claims.Issuer)
	if ok && t.Valid {
		username = claims.Issuer
	}
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to extract claims")
	}

	//Remove token from redis
	val, err := cRedis.Del(username).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Remove token from redis:  ", val)
	response := &pb.LogoutResponse{
		Status: "Logout Successfully",
	}

	return response, nil
}

func validateToken(token string) error {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return []byte("MySignatureTest"), nil
	})

	return err
}

func connectMongo(uri string) (*mongo.Client, context.Context, context.CancelFunc, error) {

	ctx, cancel := context.WithTimeout(context.Background(),
		30*time.Second)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	return client, ctx, cancel, err
}

func closeMongo(client *mongo.Client, ctx context.Context,
	cancel context.CancelFunc) {

	defer cancel()

	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()
}

func connectRedis() (clientRedis *redis.Client) {

	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	return client
}

func findUserByUsername(client *mongo.Client, ctx context.Context, username string) (results User) {
	var result User
	collection := client.Database("user").Collection("users")
	filter := bson.D{{"username", username}}
	err := collection.FindOne(ctx, filter).Decode(&result)

	if (result == User{}) == true {
		return User{}
	}

	if err != nil {
		panic(err)
	}
	return result
}

type User struct {
	ID       primitive.ObjectID `bson:"_id"`
	USERNAME string             `bson:"username"`
	PASSWORD string             `bson:"password"`
	NO       string             `bson:"no"`
	EMAIL    string             `bson:"email"`
	ROLE     string             `bson:"role"`
}

// Insert user data
func insertUsers(ctx context.Context) {
	collection := cMongo.Database("user").Collection("users")

	//Default password before encrypt is 'P@ssw0rd'
	var documents = []interface{}{
		bson.D{
			{"username", "test101"},
			{"no", "101"},
			{"email", "test@test.com"},
			{"password", "$2a$10$uRoMfOttIfejBIbc/zmSU.MPU5.OXvZ7PbQy.oitnV2atJdIave3m"},
			{"role", "admin"},
		},
		bson.D{
			{"username", "test102"},
			{"no", "102"},
			{"email", "test@test.com"},
			{"password", "$2a$10$uRoMfOttIfejBIbc/zmSU.MPU5.OXvZ7PbQy.oitnV2atJdIave3m"},
			{"role", "admin"},
		},
	}
	result, err := collection.InsertMany(ctx, documents)

	if err != nil {
		panic(err)
	}

	fmt.Println("Result of InsertMany")
	for id := range result.InsertedIDs {
		fmt.Println(id)
	}
	return
}

// Get list of user
func getAllUsers(ctx context.Context) {
	collection := cMongo.Database("user").Collection("users")
	cursor, err := collection.Find(ctx, bson.D{{}}, options.Find())

	if err != nil {
		panic(err)
	}

	var results []bson.D
	if err := cursor.All(ctx, &results); err != nil {
		panic(err)
	}

	fmt.Println("List all users")
	for _, doc := range results {
		fmt.Println(doc)
	}
}
