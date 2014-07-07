from sulley import *

s_initialize("one insert")
s_size("insert block", inclusive=True, signed=True, fuzzable=False)
if s_block_start("insert block"):
    s_lego("OP_INSERT", None, options={
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