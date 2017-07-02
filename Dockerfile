FROM golang:alpine

COPY bitscan.go $GOPATH/src/github.com/whats-this/bitscan/

RUN apk add --no-cache --virtual .build-deps git && \

    go-wrapper download github.com/Sirupsen/logrus && \
    go-wrapper download github.com/spf13/viper && \
    go-wrapper download github.com/valyala/fasthttp && \
    go-wrapper download github.com/buaazp/fasthttprouter && \
    go-wrapper download github.com/sheenobu/go-clamscan && \
    go-wrapper download github.com/dchest/uniuri && \

    go-wrapper install github.com/whats-this/bitscan && \
    apk del .build-deps

RUN apk add --no-cache clamav freshclam

# TODO: Run anacron for freshclam
RUN freshclam

WORKDIR $GOPATH/src/github.com/whats-this/bitscan
ENTRYPOINT ["go-wrapper", "run"]
