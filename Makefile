# make run-server - запустить сервер
.PHONY: run-server
run-server:
	go run server/main.go

# make run-client-scenario-1 - запустить сценарий 1
.PHONY: run-client-scenario-1
run-client-scenario-1:
	go run client/scenario1/scenario1.go

# make run-client-scenario-2 - запустить сценарий 2
.PHONY: run-client-scenario-2
run-client-scenario-2:
	go run client/scenario2/scenario2.go
