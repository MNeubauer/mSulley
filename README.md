# Fuzzing the MongoDB Wire
A tool for exposing hidden bugs using unexpected input

## Overview
This tool is a fuzz tester for the MongoDB wire. A user can create messages that will be iteratively modified, mutated, and subsequently sent to a mongod server. This iterative process is handled mainly by internals of the Sulley fuzzing framework. Communicating with the framework is programatic and relatively simple.


## Sulley
* This tool was built on they Sulley Fuzzer, for detailed information see the following pages
    - For the official sulley readme, see [SULLEY.md](./SULLEY.md)
    - For the tutorial/manual, see the [Sulley Manual](http://www.fuzzing.org/wp-content/SulleyManual.pdf)

* The Basics
    - **Primitives** are the lowest level item in Sulley. They are used to describe different types of simple data objects such as integers, strings, static data, and random data.
    - **Legos** are user defined primitives, more on this later as this facility is heavily relied on for testing the MongoDB wire.
    - **Blocks** are groups of primitives. Blocks are also primitives, and can therefore be nested within each other.
    - **Requests** are a sequence of blocks and primitives that represent one part of a conversation between Sulley and a server.
    - **Sessions** are a graph of requests, that constitute one or more full conversations between Sulley and a server.
    - Sulley also has some tools available for post mortem analysis and test case replay. See the below for details.

## Post Mortem Tools
**[byte_repeat.py](./post_mortem/byte_repeat.py)** is a python script that sends a test case or sequence of test cases previously sent by Sulley.
* Example calls from the post_mortem directory:
    - `python byte_repeat.py -n 175` will load and send the contents of one test case file (175.txt) over the wire to a mongod server.
    - `python byte_repeat.py -p texts/` will load the test cases located in the `texts/` folder and send their contents to a mongod server.
        - When `-n` is not specified, the script will search `texts/` (or the specified directory) for `1.txt`. If this file exists, the script will load this text file with every subsequent in-order `<#>.txt` file. If it does not exist, the script will exit.
            - If the directory contains `1.txt` `2.txt` and `3.txt`, all three will be sent over the wire.
            - If the directory contains `1.txt` `3.txt` and `4.txt`, only `1.txt` will be sent over the wire.
* Specify `-h` for more options

## Getting Started
To be continued


## Design
* The purpose of this project is to allow developers and testers a way to easily send well formed MongoDB wire messages to a mongod server. This is accomplished by having an interface that allows users to specify the intuitive content of the message without being conerned with low level details such as bit ordering or Sulley internals.

* One of the main reasons Sulley was selected as the framework for fuzzing the MongoDB wire was that the user's code is written in a programming language (python) and can take advantage of its facilities.

* **Lego's** take advantage of pythons facilities and their use encourage a programatic way of representing wire messages that encourages code reuse - especially via inheritance. Each MongoDB command can be represented as its own lego which can be found in [sulley/legos/mongo.py](./sulley/legos/mongo.py).
    - All legos in Sulley's [block](./sulley/blocks) class. The [Mongo_op](./sulley/legos/Mongo_op) extends the block class and is a base class for legos that represent MongoDB messages. Mongo_op has a few main purposes:
        - Create the msgHeader for each message
        - Hides some repeated code making it easier to read the code in its subclasses
        - Wrap simple lines of code if they are planned to become more complex in the future
            - E.G. Making the bson interpretation more complex

## Usage
To be continued

## Developer info
To be continued








