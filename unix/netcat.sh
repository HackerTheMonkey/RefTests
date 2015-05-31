#!/bin/bash


# Use netcat as a server listening connections over a certain port:
# Once a connection is made to the server, the netcat server terminates.

nc -l localhost 1234

# How to use netcat as a client connecting to a remote server and send everything
# from the standard input to the remote server

echo "Hola" | nc localhost 1234


