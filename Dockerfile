FROM registry.access.redhat.com/ubi8/ubi-minimal as builder

# create enviroment variables and files
ENV ENVFILE=/tmp/envfile
RUN echo "export ARCH=`uname -m | sed 's/x86_64/amd64/'`" >> ${ENVFILE}
ENV PATH=$PATH:/usr/local/go/bin

RUN microdnf install -y make tar gzip which && microdnf clean all

RUN . ${ENVFILE}; curl -L https://go.dev/dl/go1.21.6.linux-${ARCH}.tar.gz | tar -C /usr/local -xzf -

WORKDIR /workspace
# Copy the Go Modules manifests and vendor directory
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/

# Copy the go source
COPY Makefile Makefile
COPY main.go main.go
COPY api/ api/
COPY pkg/ pkg/

# Build
RUN . ${ENVFILE}; CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH} GO111MODULE=on make build


FROM registry.access.redhat.com/ubi8/ubi-minimal

RUN microdnf update -y && microdnf clean all

WORKDIR /
COPY --from=builder /workspace/bin/console .
USER 1000

ENTRYPOINT ["/console"]
