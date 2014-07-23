from mSulley.sulley import s_initialize
from mSulley.sulley import s_block_start
from mSulley.sulley import s_block_end
from mSulley.sulley import s_lego

s_initialize("one insert")
if s_block_start("insert block"):
    s_lego("OP_INSERT", None, options=
        {
            "requestID": 98134,
            # Do not use the responseTo field unless you have good reason
            # MongoDB expects SSL handshake unless responseTo is 0 or -1
            # Let the fuzzer handle both values for you
            #"responseTo": 0,
            "documents": [
            {
                "_id": 0,
                "number": 100,
                "str": "hello there",
                "obj":{"innards": "stuff"}
            }
            ]
        })
s_block_end("insert block")