.PHONY : build

build : buildplugins buildcmd

buildcmd:
	go build -ldflags "-s" -o outback cmd/outback.go

buildplugins:
	go build -buildmode=plugin -ldflags "-s" -o plugins/plugin_aws.so cmd/plugins/plugin_aws.go
	go build -buildmode=plugin -ldflags "-s" -o plugins/plugin_gsuite.so cmd/plugins/plugin_gsuite.go