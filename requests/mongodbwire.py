# Sulley fuzzing block definitions for MongoDB Wire API
# 
# TODOs
# 1. Implement OP_UPDATE, OP_INSERT, OP_QUERY, OP_GET_MORE, OP_DELETE and OP_KILL_CURSORS blocks
# 2. Represent the binary BSON blobs as fuzzable Sulley blocks
# 3. Get the process monitor to work on *nix or OS X
# 4. For OP_QUERY implement actual commands objects as fuzzable Sulley objects
# 5. Connect to code coverage too 
#
# struct MsgHeader {
#    int32   messageLength; // total message size, including this
#    int32   requestID;     // identifier for this message
#    int32   responseTo;    // requestID from the original request
#                            //   (used in reponses from db)
#    int32   opCode;        // request type - see table below
# }

from sulley import s_int, s_string, s_delim, s_random, s_initialize, s_block_start, s_block_end, s_size
from pymongo import MongoClient

DBNAME = "test"
COLNAME = "fuzzing"

# Use Pymongo to prepare the database to improve code coverage while fuzzing
client = MongoClient('localhost', 27017)
db = client[DBNAME]
db[COLNAME].drop()
db[COLNAME].insert({"a":1})

########################################################################################################################
# OP_UPDATE   2001    update document
# struct OP_UPDATE {
#    MsgHeader header;             // standard message header
#    int32     ZERO;               // 0 - reserved for future use
#    cstring   fullCollectionName; // "dbname.collectionname"
#    int32     flags;              // bit vector. see below
#    document  selector;           // the query to select the document
#    document  update;             // specification of the update to perform
# }

########################################################################################################################
# OP_INSERT   2002    insert new document
# struct {
# MsgHeader header;             // standard message header
# int32     flags;              // bit vector - see below
# cstring   fullCollectionName; // "dbname.collectionname"
# document* documents;          // one or more documents to insert into the collection
# }

########################################################################################################################
# OP_QUERY    2004    query a collection
# struct OP_QUERY {
# MsgHeader header;                 // standard message header
#    int32     flags;                  // bit vector of query options.  See below for details.
#    cstring   fullCollectionName ;    // "dbname.collectionname"
#    int32     numberToSkip;           // number of documents to skip
#    int32     numberToReturn;         // number of documents to return
#                                      //  in the first OP_REPLY batch
#    document  query;                  // query object.  See below for details.
#    [ document  returnFieldsSelector; ] // Optional. Selector indicating the fields
#                                        //  to return.  See below for details.
# }

########################################################################################################################
# OP_GET_MORE 2005    Get more data from a query. See Cursors
# struct {
#    MsgHeader header;             // standard message header
#    int32     ZERO;               // 0 - reserved for future use
#    cstring   fullCollectionName; // "dbname.collectionname"
#    int32     numberToReturn;     // number of documents to return
#    int64     cursorID;           // cursorID from the OP_REPLY
# }

s_initialize("MONGODB OP_GET_MORE")
s_size("OP_GET_MORE", inclusive=True, fuzzable=True);

if s_block_start("OP_GET_MORE"):
    # MsgHeader
    s_int(9999, fuzzable=False)
    s_int(0, fuzzable=False)
    s_int(2005, fuzzable=False)

    # OP_GET_MORE specific
    s_int(0, fuzzable=False)
    s_string(DBNAME, fuzzable=True)
    s_delim(".", fuzzable=True)
    s_string(COLNAME, fuzzable=True)
    s_int(10, fuzzable=False)
    s_random("", 8, 8, num_mutations=1)
s_block_end()

########################################################################################################################
# OP_DELETE   2006    Delete documents
# struct {
#    MsgHeader header;             // standard message header
#    int32     ZERO;               // 0 - reserved for future use
#    cstring   fullCollectionName; // "dbname.collectionname"
#    int32     flags;              // bit vector - see below for details.
#    document  selector;           // query object.  See below for details.
# }

########################################################################################################################
# OP_KILL_CURSORS 2007    Tell database client is done with a cursor


