## Description
Example_2 is a simple server that accepts TCP network connections. The application accepts two commands:
1. *CHECKSUM* - run a checksum ("inadvertently" operate on the secret flag)
2. *ECHO: < message size >:< message >* - echo back a message from the user
    - The intended usage of ECHO is something like: `ECHO:4:test`

## Flags
To indicate whether a vulnerability has been triggered we plan to develop a set of effect indicators that cover the classes of vulnerabilities targeted in each phase. While the target classes and observable effects have yet to be defined and recognizing that this list of potential effects flags is non-spanning, we have provided some potential flags for the vulnerabilities in this application.

1. Get the application to send the secret flag "FLAG{SECRET_VALUE}"

## Vulnerability
1. The application allows users to submit messages that are of a different length than what is indicated. The application then sends back the amount of data indicated in the "message size" component of the request. This allows the user to return more information from the request than was sent.
2. The *CHECKSUM* operation operates on the secret flag and loads it into memory such that it can be returned by vulnerability #1.