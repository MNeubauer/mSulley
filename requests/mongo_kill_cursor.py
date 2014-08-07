from sulley import (s_initialize,
                    s_block_start,
                    s_block_end,
                    s_lego)
from pymongo import MongoClient

DBNAME = "test"
COLNAME = "cursor_kill"

# Seed the database with dummy documents to improve code coverage.
client = MongoClient('localhost', 27017)
db = client[DBNAME]
db[COLNAME].drop()


###############################################################################
for i in xrange(1000):
    db[COLNAME].insert({"a":i})

cursors = []
for i in xrange(10):
    CURSOR_NO_TIMEOUT = 16
    cursor = db[COLNAME].find().add_option(CURSOR_NO_TIMEOUT)
    for doc in cursor:
        cursors.append(cursor.cursor_id)
        # We are only interested in getting the cursor ID which can be
        # acquired after one step through the cursor iteration, so we
        # do not need to continue.
        break

s_initialize("one kill cursor")
if s_block_start("kill_message"):
    s_lego("OP_KILL_CURSORS", None, options=
        {
            "requestID": 124098,
            # Do not use the responseTo field unless you have good reason.
            # MongoDB expects an SSL handshake unless responseTo is 0 or -1.
            # Let the fuzzer handle both values for you.
            #"responseTo": 0,
            "numberOfCursorIDs": len(cursors),
            "cursorIDs": cursors
        })
s_block_end("kill_message")

###############################################################################
