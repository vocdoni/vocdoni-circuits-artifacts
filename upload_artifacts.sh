#!/bin/bash
SPACE="circuits"
BUCKET="dev"

find -type f | grep -E "\.pk|\.vk|\.ccs|\.wasm|\.zkey|\.json" | while read f; do 
  s3cmd put "$f" s3://$SPACE/$BUCKET/
done

s3cmd setacl s3://$SPACE/$BUCKET/ --acl-public --recursive
  
