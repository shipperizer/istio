#!/bin/bash

# Assume this script is run from the current working directory if not
# explicitly configured.
ISTIO_DEV_DIR=${ISTIO_DEV_DIR:-`pwd`}

#
# install build tools
#
# sudo apt-get install ruby ruby-dev rubygems build-essential
# sudo gem install --no-ri --no-rdoc fpm

#
# set up environment
#

export GOPATH=~/go
export PATH=$PATH:${GOPATH}/bin
export ISTIO=${GOPATH}/src/istio.io

mkdir $ISTIO || true
ln -s $ISTIO_DEV_DIR $ISTIO || true

# Please change HUB to the desired HUB for custom docker container
# builds.
export HUB="docker.io/cilium"

# The Istio Docker build system will build images with a tag composed of
# $USER and timestamp. The codebase doesn't consistently use the same timestamp
# tag. To simplify development the development process when later using
# updateVersion.sh you may find it helpful to set TAG to something consistent
# such as $USER.
export TAG=1.5.2

#
# build
#
cd ${ISTIO}/istio
BUILD_WITH_CONTAINER=1 make docker.pilot
# docker save cilium/istio_pilot:${TAG} -o ${ISTIO_DEV_DIR}/cilium-istio-pilot-${TAG}.tar
