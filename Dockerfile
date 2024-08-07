# Build this Dockerfile using the command: make build-container
#
# This multi-stage image approach prevents issues related to cached builder images,
# which may be incompatible due to different architectures, potentially slowing down or breaking the build process.
#
# By utilizing Go cross-compilation, we can build the target Go binary from the host architecture
# and then copy it to the target image with the desired architecture.

ARG TARGET_ARCH=amd64
FROM registry.access.redhat.com/ubi9/ubi-minimal as builder
ARG TARGET_ARCH

# download packages
RUN microdnf install -y make tar gzip which && microdnf clean all
RUN export ARCH=$(uname -m | sed 's/x86_64/amd64/'); curl -L https://go.dev/dl/go1.22.4.linux-${ARCH}.tar.gz | tar -C /usr/local -xzf -

# create enviroment variables
ENV PATH=$PATH:/usr/local/go/bin

# copy the Go Modules manifests and vendor directory
WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/

# copy the go source
COPY Makefile Makefile
COPY main.go main.go
COPY api/ api/
COPY pkg/ pkg/

# compile for the TARGET_ARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGET_ARCH} make build


FROM --platform=linux/${TARGET_ARCH} registry.access.redhat.com/ubi9/ubi-micro

# copy binary from builder image
WORKDIR /
COPY --from=builder /workspace/bin/console .
USER 1000
ENTRYPOINT ["/console"]
