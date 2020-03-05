FROM localhost:5000/cs_base:v1

ADD ./ /home/challenge
RUN chown -R csuser:csuser /home

USER csuser
WORKDIR /home/challenge
RUN make clean
RUN make
CMD ./example_2.bin $ARG_1
