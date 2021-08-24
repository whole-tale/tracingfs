#!/bin/bash
docker run \
  --rm \
  -ti \
  --name logstash \
  -p 5959:5959 \
  -v $PWD/logstash/settings/:/usr/share/logstash/config/ \
  -v $PWD/logstash/pipeline/:/usr/share/logstash/pipeline/ \
  docker.elastic.co/logstash/logstash:7.14.0
