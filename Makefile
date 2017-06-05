.PHONY : build

build : buildplugins buildcmd

buildcmd:
	go build -o outback cmd/outback.go

buildplugins:
	go build -buildmode=plugin -o plugins/plugin_aws.so cmd/plugins/plugin_aws.go
