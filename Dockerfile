FROM golang:1.21 AS builder

WORKDIR /go/src/app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN go build

FROM --platform=$BUILDPLATFORM node:18.18.2 AS console-builder

WORKDIR /skupper-console/
ADD https://github.com/skupperproject/skupper-console/archive/main.tar.gz .
RUN tar -zxf main.tar.gz
WORKDIR ./skupper-console-main
RUN yarn install && yarn build

FROM --platform=$TARGETPLATFORM registry.access.redhat.com/ubi9-minimal

# Create user and group and switch to user's context
RUN microdnf -y install shadow-utils \
&& microdnf clean all
RUN useradd --uid 10000 runner
USER 10000

WORKDIR /app
COPY --from=builder /go/src/app/collector .
COPY --from=console-builder /skupper-console/skupper-console-main/build/ console
ENTRYPOINT ["/app/collector"]
