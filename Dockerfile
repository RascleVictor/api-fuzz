FROM golang:1.24 AS go_builder

WORKDIR /build

COPY go.mod ./
RUN go mod download

COPY . .

RUN apt-get update && apt-get install -y libpcap-dev
# Compile ton propre outil
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /build/api-fuzz

# Installer les outils Go dans /go/bin
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/003random/getJS@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest

# ------------------------------------------------------------

FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache curl git python3 py3-pip bash

# Copier les outils Go depuis la première image
COPY --from=go_builder /go/bin/subfinder /usr/local/bin/
COPY --from=go_builder /go/bin/naabu /usr/local/bin/
COPY --from=go_builder /go/bin/waybackurls /usr/local/bin/
COPY --from=go_builder /go/bin/getJS /usr/local/bin/
COPY --from=go_builder /go/bin/gau /usr/local/bin/

# Installer ParamSpider (Python)
RUN git clone https://github.com/devanshbatham/paramspider.git /opt/paramspider && \
    pip install --break-system-packages /opt/paramspider && \
    ln -s /usr/local/bin/paramspider.py /usr/local/bin/paramspider
    #chmod +x /usr/local/bin/paramspider

COPY --chown=app:app entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh


# Ton binaire Go compilé
COPY --from=go_builder /build/api-fuzz /app/api-fuzz

RUN adduser -D -u 1000 -s /sbin/nologin app
USER app

ENTRYPOINT ["/app/entrypoint.sh"]
