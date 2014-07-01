from sulley import *

s_initialize("one kill cursor")
s_size("kill_block", inclusive=True, signed=True)

if s_block_start("kill_block"):
    s_lego("OP_KILL_CURSORS", None, {"numberOfCursorIDs": 2342,
                                     "cursorIDs": 2672 })
s_block_end()

"""
    struct OP_UPDATE {
        MsgHeader header;             // standard message header
        int32     ZERO;               // 0 - reserved for future use
        cstring   fullCollectionName; // "dbname.collectionname"
        int32     flags;              // bit vector. see below
        document  selector;           // the query to select the document
        document  update;             // specification of the update to perform
    }

    bit num name      description
    0   Upsert        If set, the database will insert the supplied object into the collection if no matching document is found.
    1   MultiUpdate   If set, the database will update all matching objects in the collection. Otherwise only updates first matching doc.
    2-31  Reserved    Must be set to 0.
"""

"""
    struct OP_INSERT {
        MsgHeader header;             // standard message header
        int32     flags;              // bit vector - see below
        cstring   fullCollectionName; // "dbname.collectionname"
        document* documents;          // one or more documents to insert into the collection
    }

    0   ContinueOnError   If set, the database will not stop processing a bulk insert if one fails (eg due to duplicate IDs). This makes bulk insert behave similarly to a series of single inserts, except lastError will be set if any insert fails, not just the last one. If multiple errors occur, only the most recent will be reported by getLastError. (new in 1.9.1)
    1-31    Reserved      Must be set to 0.
"""

"""
    struct OP_QUERY {
        MsgHeader header;                   // standard message header
        int32     flags;                    // bit vector of query options.  See below for details.
        cstring   fullCollectionName ;      // "dbname.collectionname"
        int32     numberToSkip;             // number of documents to skip
        int32     numberToReturn;           // number of documents to return
                                            //  in the first OP_REPLY batch
        document  query;                    // query object.  See below for details.
        [ document  returnFieldsSelector; ] // Optional. Selector indicating the fields
                                            //  to return.  See below for details.
    }


    Flags
    bit num name         description
    0   Reserved         Must be set to 0.
    1   TailableCursor   Tailable means cursor is not closed when the last data is retrieved. Rather, the cursor marks the final object’s position. You can resume using the cursor later, from where it was located, if more data were received. Like any “latent cursor”, the cursor may become invalid at some point (CursorNotFound) – for example if the final object it references were deleted.
    2   SlaveOk          Allow query of replica slave. Normally these return an error except for namespace “local”.
    3   OplogReplay      Internal replication use only - driver should not set
    4   NoCursorTimeout  The server normally times out idle cursors after an inactivity period (10 minutes) to prevent excess memory use. Set this option to prevent that.
    5   AwaitData        Use with TailableCursor. If we are at the end of the data, block for a while rather than returning no data. After a timeout period, we do return as normal.
    6   Exhaust          Stream the data down full blast in multiple “more” packages, on the assumption that the client will fully read all data queried. Faster when you are pulling a lot of data and know you want to pull it all down. Note: the client is not allowed to not read all the data unless it closes the connection.
    7   Partial          Get partial results from a mongos if some shards are down (instead of throwing an error)
    8-31    Reserved     Must be set to 0.
"""


"""
    struct OP_GET_MORE {
        MsgHeader header;             // standard message header
        int32     ZERO;               // 0 - reserved for future use
        cstring   fullCollectionName; // "dbname.collectionname"
        int32     numberToReturn;     // number of documents to return
        int64     cursorID;           // cursorID from the OP_REPLY
    }
"""


"""
    struct OP_DELETE {
        MsgHeader header;             // standard message header
        int32     ZERO;               // 0 - reserved for future use
        cstring   fullCollectionName; // "dbname.collectionname"
        int32     flags;              // bit vector - see below for details.
        document  selector;           // query object.  See below for details.
    }


    0       SingleRemove    If set, the database will remove only the first matching document in the collection. Otherwise all matching documents will be removed.
    1-31    Reserved        Must be set to 0.

"""




"""
    struct OP_MSG {
        MsgHeader header;  // standard message header
        cstring   message; // message for the database
    }
"""