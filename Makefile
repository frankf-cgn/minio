all: getdeps install

checkdeps:
	@echo "Checking deps:"
	@(env bash $(PWD)/buildscripts/checkdeps.sh)

checkgopath:
	@echo "Checking if project is at ${GOPATH}"
	@for mcpath in $(echo ${GOPATH} | sed 's/:/\n/g' | grep -v Godeps); do if [ ! -d ${mcpath}/src/github.com/minio/minio ]; then echo "Project not found in ${mcpath}, please follow instructions provided at https://github.com/minio/minio/blob/master/CONTRIBUTING.md#setup-your-minio-github-repository" && exit 1; fi done

getdeps: checkdeps checkgopath
	@go get github.com/tools/godep && echo "Installed godep:"
	@go get github.com/golang/lint/golint && echo "Installed golint:"
	@go get golang.org/x/tools/cmd/vet && echo "Installed vet:"
	@go get github.com/fzipp/gocyclo && echo "Installed gocyclo:"

verifiers: getdeps vet fmt lint cyclo

vet:
	@echo "Running $@:"
	@go vet ./...
fmt:
	@echo "Running $@:"
	@test -z "$$(gofmt -s -l . | grep -v Godeps/_workspace/src/ | tee /dev/stderr)" || \
		echo "+ please format Go code with 'gofmt -s'"
lint:
	@echo "Running $@:"
	@test -z "$$(golint ./... | grep -v Godeps/_workspace/src/ | tee /dev/stderr)"

cyclo:
	@echo "Running $@:"
	@test -z "$$(gocyclo -over 25 . | grep -v Godeps/_workspace/src/ | tee /dev/stderr)"

build: getdeps verifiers
	@echo "Installing minio:"
	@godep go generate ./...
	@godep go test -race ./...

gomake-all: build
	@godep go install github.com/minio/minio

release: genversion
	@echo "Installing minio for new version.go:"
	@godep go install github.com/minio/minio

genversion:
	@echo "Generating new minio version.go"
	@godep go run genversion.go

godepupdate:
	@(env bash $(PWD)/buildscripts/updatedeps.sh)

install: gomake-all

save:
	@godep save ./...

restore:
	@godep restore

env:
	@godep go env

clean:
	@echo "Cleaning up all the generated files:"
	@rm -fv cover.out
	@rm -fv pkg/utils/split/TESTPREFIX.*
	@rm -fv minio
	@godep go clean
	@find Godeps -name "*.a" -type f -exec rm -vf {} \+
