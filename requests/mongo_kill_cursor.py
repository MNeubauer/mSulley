from sulley import *
from pymongo import MongoClient

DBNAME = "test"
COLNAME = "fuzzing"

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
    for doc in cursor:
        cursors.append(cursor.cursor_id)
        break

s_initialize("one kill cursor")
# begin each message with the size (32 bit is default)
s_size("kill_message", inclusive=True, signed=True, fuzzable=False)
if s_block_start("kill_message"):
    s_lego("OP_KILL_CURSORS", None, options={
                                        "header_opts" : {
                                            "requestID": None, 
                                            "responseTo": None,
                                        },
                                        "numberOfCursorIDs": len(cursors),
                                        "cursorIDs": cursors
                                    })
s_block_end()

###############################################################################
