#FROM squareslab/manybugs:base
FROM sefcom/sefcom:base
#MAINTAINER Chris Timperley "christimperley@gmail.com"



# this is heavily leveraged from Chris Timperley's infrastructure
MAINTAINER Pemma Reiter "pdreiter@asu.edu"

# need to copy over source code from localhost

#COPY fauxware /experiment/src
COPY . /experiment/src


RUN cd /experiment && \
    sudo chown -R docker /experiment


## fix the GenProg config file
#RUN sed -i "s#bugged-program.txt#manifest.txt#" configuration-default && \
#    sed -i "s#perl compile.pl#./compile.sh#"    configuration-default && \
#    sed -i "s#> /dev/null#\&> /dev/null#"       configuration-default && \
#    echo "--mt-cov" >> configuration-default

# preprocess
#RUN ./preprocess --base && \
#    cd src && \
#    bear make -j$(nproc)

# tidy the source code
RUN cd /experiment/src && \
     bear make -j$(nproc)



