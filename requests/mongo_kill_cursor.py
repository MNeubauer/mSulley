from sulley import s_initialize
from sulley import s_block_start
from sulley import s_block_end
from sulley import s_lego
from pymongo import MongoClient

DBNAME = "test"
COLNAME = "cursor_kill"

# Use Pymongo to prepare the database to improve code coverage while fuzzing
client = MongoClient('localhost', 27017)
db = client[DBNAME]
db[COLNAME].drop()


###############################################################################
for i in xrange(1000):
    db[COLNAME].insert({"a":i})

cursors = []
for i in xrange(7):
    cursor = db[COLNAME].find().sort('a').limit(10)
    for doc in cursor:
        cursors.append(cursor.cursor_id)
        # We are only interested in getting the cursor ID which can be 
        # acquired after one step through the cursor iteration, so we 
        # do not need to continue.
        break

# Note, the cursors seem to get deleted before the Sulley code begins to 
# execute. More time needs to be spent understanding what is happening
# to make the above code useful or find a different way to get code
# coverage using a kill cursor command.

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
