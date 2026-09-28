FROM golang:1.25.0-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN go build -trimpath -ldflags="-s -w" -o /out/bannerfp-server ./cmd/server && \
    go build -trimpath -ldflags="-s -w" -o /out/bannerfp-client ./cmd/client

# Runtime image: no shell, no package manager, no writable filesystem by default.
FROM scratch AS server
COPY --from=build /out/bannerfp-server /server
COPY rules /etc/bannerfp/rules
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
CMD ["-listen", ":8080", "-rules", "/etc/bannerfp/rules"]

FROM scratch AS client
COPY --from=build /out/bannerfp-client /client
USER 65532:65532
ENTRYPOINT ["/client"]
