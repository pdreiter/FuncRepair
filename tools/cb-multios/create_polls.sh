#!/bin/bash

pushd $CGC_CB_DIR

if [[ -d polls ]]; then
    echo "'polls' directory already exists!"
    echo "Please move 'polls' to another directory to prevent clobbering"
else
    ./genpolls.sh
    # this should generate a polls directory with new test content
    
    #the following consolidates original test content in the polls directory
    chals=$(ls challenges | egrep -v 'copyright\.txt')
    for i in $chals; do
        for j in $(ls challenges/poller); do 
          if (( $(ls challenges/$i/poller/$j/*.xml | wc -l)>0 )); then
            mkdir -p polls/$i/poller
            cp -r challenges/$i/poller/$j polls/$i/poller/cb-$j
          fi
        done
    done
fi

echo "done."
