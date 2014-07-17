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
#### Requests
* The Sulley definition of a call for a lego is `def s_lego(lego_type, value=None, options={})`
* All `lego_type`'s can be found in [sulley/legos/\__init\__.py](sulley/legos/__init__.py)
* Calls to s_lego for MongoDB messages use the options dict as a way of passing initial values for the message.
* See the [MongoDB wire protocol spec](http://docs.mongodb.org/meta-driver/latest/legacy/mongodb-wire-protocol/) for details on what is expected for each message.
* Notes on the **MsgHeader**:
    - The messageLength field is calculated by a sizer upon initialization of each lego
    - The opCode field is implied by the type of lego that is called
    - It is suggested that the user leave out the responseTo field
        - SSL handshake is expected if this field is not 0 or -1
        - The fuzzer will test across both of these values if the field is not specified
* The `fullCollectionName` field is not expected. Instead pass separate `db` and `collection` fields wherever the spec calls for `fullCollectionName`. This is so Sulley can fuzz the delimiter properly.
* Legos currently do not expect options for fields that are reserved and filled with zeros.
* Multiple requests can be made per file in a the [requests](./requests) directory.
* Each request starts with `s_initialize("example request")`.
    - A session uses this request as a node with a call to `sess.connect("example request")`.
* An example request containing one insert message:
```python
s_initialize("insert")
s_lego("OP_INSERT", options=
    {
        # MsgHeader
        "requestID": 98134,
        # OP_INSERT
        "flags": 1,
        "db": "test",
        "collection": "fuzzing",
        "documents": [
            {
                "_id": 0,
                "number": 100,
                "str": "hello there",
                "obj":{"nested": "stuff"}
            }
        ]
    })
```
* An example request containing one kill cursor message:
    - This request contains a nested block, so that if this request is extended, future sulley primitives can reference the block by name.
    ```python
    s_initialize("kill cursor")
    if s_block_start("kill_cursor_msg"):
        s_lego("OP_KILL_CURSORS", options=
        {
            "requestID": 124098,
            "numberOfCursorIDs": 5,
            "cursorIDs": [
                2346245,
                123465663,
                76254,
                85662214,
                6245246
            ]
        })
    s_block_end("kill_cursor_msg")
    ```
* An example of an update message
```python
s_initialize("update")
s_lego("OP_UPDATE", options=
    {
        "requestID": 56163,
        "db": "test",
        "collection": "fuzzing",
        "flags": 1,
        "selector": {
            "_id": 0,
        },
        "update": {
            "number": 11,
            "str": "Hello again",
            "obj":{"birds": "nest"}
        }
    })
```

## Developer info
### Important components
* Creating a simple MongoDB message lego using [Mongo_op](./sulley/legos/Mongo_op.py):
```python
class OP_NEW(Mongo_op.Mongo_op):
    """This sulley lego represents an OP_NEW MongoDB message"""
    def __init__(self, name, request, value, options):
        # Create the super class and push a header to the block.
        options = self.init_options(options, NEW_OPCODE)
        Mongo_op.Mongo_op.__init__(self, name, request, options)
        
        # Save the appropriate options in case we need to 
        # reference them again in the future and set defaults
        self.db = options.get("db", "test")
        self.collection = options.get("collection", "fuzzing")
        self.flags = options.get("flags", NEW_FLAGS)
        self.document = options.get("document", {})
       
        # This command has 32 bits of reserved space.
        self.push(primitives.dword(0, signed=True))
        # cstring fullCollectionname
        self.push_namespace(self.db, self.collection)
        # int32 flags
        self.push(primitives.dword(self.flags, signed=True))
        # bson document
        self.push_bson_doc(self.document)

        # Always end with this command!
        self.end_block()
```
