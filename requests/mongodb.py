from sulley import (s_block_start,
                    s_block_end,
                    s_delim,
                    s_initialize,
                    s_int,
                    s_lego,
                    s_random,
                    s_size,
                    s_string)


#### Requests from this file which may be copy and pasted to session files
# sess.connect(s_get("one insert"))
# sess.connect(s_get("get more"))
# sess.connect(s_get("MONGODB OP_GET_MORE"))
####

s_initialize("one insert")
s_lego("OP_INSERT", None, options=
    {
        "requestID": 98134,
        "documents": [
        {
            "_id": 0,
            "number": 100,
            "str": "hello there",
            "obj":{"innards": "stuff"}
        }
        ]
    })

s_initialize("get more")
s_lego("OP_GET_MORE")

s_initialize("MONGODB OP_GET_MORE")
# s_size prepends the messageLength to the following block.
s_size("OP_GET_MORE", inclusive=True, fuzzable=True);
if s_block_start("OP_GET_MORE"):
    # MsgHeader
    s_int(9999, fuzzable=False)
    s_int(0, fuzzable=False)
    s_int(2005, fuzzable=False)

    # OP_GET_MORE specific
    s_int(0, fuzzable=False)
    s_string("test", fuzzable=True)
    s_delim(".", fuzzable=True)
    s_string("fuzzing", fuzzable=True)
    s_int(10, fuzzable=False)
    s_random("", 8, 8, num_mutations=1)
s_block_end()
