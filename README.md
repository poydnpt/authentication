# Authentication service with Go GRPC

## Including Login, Validate Token and Logout services

### Create MongoDB and Redis
Run docker-compose file or run the following command:
```
docker run -d -p 27017:27017 --name mongo mongo:latest
docker run -d -p 6379:6379 --name redis redis:latest
```
You may need to run db script `create_users.js` to mongoDB to insert user data

### Run Services
To start the service, run the main.go file
```
go run main.go
```
#### The gRPC server is serve the requests on port 50051

### Run Envoy Proxy
We need a gateway proxy `Envoy` for serving gRPC server
```
envoy -c envoy.yaml
```
we’ll be connecting to envoy on `8080`
\
&nbsp;

### Service Specification
#### Login
Request: username and password\
Response: access token
\
&nbsp;

#### Validate Token
Request: token from header\
Response: token status
\
&nbsp;

#### Logout
Request: token from header\
Response: logout status