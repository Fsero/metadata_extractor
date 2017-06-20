FROM library/golang:1.8-stretch

RUN apt-get update
RUN apt-get install -y libgeoip1 geoip-database geoip-database-extra libgeoip-dev sqlite3 sqlite3

# Godep for vendoring
RUN curl https://glide.sh/get | sh

# Recompile the standard library without CGO
RUN CGO_ENABLED=0 go install -a std

ENV APP_DIR $GOPATH/src/bitbucket.org/fseros/metadata_extractor
RUN mkdir -p $APP_DIR

# Set the entrypoint
#ENTRYPOINT (cd $APP_DIR && ./metadata_extractor)
ADD . $APP_DIR

# Compile the binary and statically link
RUN cd $APP_DIR && CGO_ENABLED=0 /go/bin/glide install
RUN cd $APP_DIR && go build
WORKDIR $APP_DIR
#VOLUME $GOPATH/src/bitbucket.org/fseros/metadata_extractor/.metadata_extractor.yaml