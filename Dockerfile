FROM golang:alpine AS build

RUN apk update && apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /local-sts
RUN echo "nobody:x:65534:65534:nobody:/:/sbin/nologin" > /passwd
RUN echo "nogroup:x:65533:" > /group

FROM scratch
COPY --from=build /local-sts /usr/bin/
COPY --from=build /passwd /etc/
COPY --from=build /group /etc/
USER nobody:nogroup
EXPOSE 8080
ENTRYPOINT ["/usr/bin/local-sts"]
