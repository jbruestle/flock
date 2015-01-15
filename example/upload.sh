#!/bin/bash
curl -v -X PUT --header "Content-Type: $1" localhost:8000/`cat tid`/$2 --data-binary @$2
