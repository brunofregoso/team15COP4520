# COP 4520 Team 15 Project
View our paper [here](about:blank)

## Team Members
todo

## Description
Multithreaded brute force password cracker.

## Development
OpenSSL and support for multithreading is required to build this project. Use the following to compile:
```bash
g++ ./main.cpp -Wall -lssl -lcrypto -lpthread -o main
```
To run, pass a list of plaintext passwords to the program:
```bash
./main passwords.txt
```
