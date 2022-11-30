FROM registry.access.redhat.com/ubi8/ubi-minimal as builder

RUN microdnf install -y make tar gzip which && microdnf clean all

RUN curl -L https://go.dev/dl/go1.19.2.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /workspace
# Copy the Go Modules manifests and vendor directory
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/

# Copy the go source
COPY Makefile Makefile
COPY main.go main.go
COPY pkg/ pkg/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on make build


FROM registry.access.redhat.com/ubi8/ubi-minimal

RUN microdnf update -y && microdnf clean all

WORKDIR /
COPY --from=builder /workspace/bin/console .
USER 1000

ENTRYPOINT ["/console"]
