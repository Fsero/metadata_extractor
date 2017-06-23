FROM library/golang:1.8-stretch
USER root
RUN apt-get update
RUN apt-get install -y gnupg
RUN curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add -
RUN curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/stable/deb/draios.list
RUN apt-get update
RUN apt-get install -y libgeoip1 geoip-database geoip-database-extra libgeoip-dev sqlite3 sqlite3 sysdig rsync
RUN adduser --system --no-create-home --home /var/log/traces/ --shell /bin/bash file 
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
VOLUME /var/log/traces
#VOLUME $GOPATH/src/bitbucket.org/fseros/metadata_extractor/.metadata_extractor.yaml
