module github.com/xinleishen84-afk/airlock-agent/nerclient

go 1.27.0

replace github.com/xinleishen84-afk/airlock-agent => ../

require (
	github.com/xinleishen84-afk/airlock-agent v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
