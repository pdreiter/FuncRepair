#!/bin/bash


perl -pi -e's/(\s+)(sink_error)/$1cgc_$2/' $CGC_CB_DIR/challenges/CGC_Board/src/main.c
