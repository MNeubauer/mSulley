from mSulley.sulley import *
from pymongo import MongoClient

DBNAME = "test"
COLNAME = "cursor_kill"

# Use Pymongo to prepare the database to improve code coverage while fuzzing
client = MongoClient('localhost', 27017)
db = client[DBNAME]
db[COLNAME].drop()


###############################################################################
for i in range(0,1000):
    db[COLNAME].insert({"a":i})

cursors = []
for i in range(0,7):
    cursor = db[COLNAME].find().sort('a').limit(10)
    for Doc in cursor:
        cursors.append(cursor.cursor_id)
        break

s_initialize("one kill cursor")
# The block is only actually necessary if you 
# wish to reference the lego by name
if s_block_start("kill_message"):
    s_lego("OP_KILL_CURSORS", None, options=
        {
            "requestID": 124098,
            # Do not use the responseTo field unless you have good reason
            # MongoDB expects SSL handshake unless responseTo is 0 or -1
            # Let the fuzzer handle both values for you
            #"responseTo": 0,
            "numberOfCursorIDs": len(cursors),
            "cursorIDs": cursors
        })
s_block_end("kill_message")

###############################################################################
