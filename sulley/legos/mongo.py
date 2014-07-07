#from sulley import primitives, blocks, legos
from sulley import *
from struct import pack
from random import randint
from random import seed
from random import getrandbits
from bson import BSON

seed(6)

###############################################################################
"""
    struct MsgHeader {
        int32   messageLength; // total message size, including this
        int32   requestID;     // identifier for this message
        int32   responseTo;    // requestID from the original request
                               //   (used in reponses from db)
        int32   opCode;        // request type - see table below
    }

    opCode      value   Comment
    
    OP_REPLY         1      Reply to a client request. responseTo is set
    OP_MSG           1000   generic msg command followed by a string
    OP_UPDATE        2001   update document
    OP_INSERT        2002   insert new document
    RESERVED         2003   formerly used for OP_GET_BY_OID
    OP_QUERY         2004   query a collection
    OP_GET_MORE      2005   Get more data from a query. See Cursors
    OP_DELETE        2006   Delete documents
    OP_KILL_CURSORS  2007   Tell database client is done with a cursor
"""

class MsgHeader(blocks.block):
    def __init__(self, name, request, value, options=None):
        blocks.block.__init__(self, name, request, None, None, None, None)
        self.requestID = options.get("requestID", 12452)
        self.responseTo = options.get("responseTo", None)
        self.opCode = options["opCode"] # The opCode must be specified.
        # Form an internal block.
        message = blocks.block(name + "_header", request)
        message.push(primitives.dword(self.requestID, signed=True, fuzzable=False))
        # MongoDB assumes SSL if responseTo is not 0 or -1
        if self.responseTo == None:
            message.push(primitives.group("not_SSL", 
                                          [pack('<i',0), pack('<i',-1)]))
        else:
            message.push(
                primitives.dword(self.responseTo, signed=True,fuzzable=False))
        message.push(
            primitives.dword(self.opCode, signed=True))
        # Add block to self.
        self.push(message)

###############################################################################

"""
    struct OP_UPDATE {
        MsgHeader header;               // standard message header_opts
        int32     ZERO;                 // 0 - reserved for future use
        cstring   fullCollectionname;   // "dbname.collectionname"
        int32     flags;                // bit vector. see below
        document  selector;             // the query to select the document
        document  update;               // specification of the update 
                                        // to perform
    }

    bit num     name        description
    0           Upsert      If set, the database will insert the supplied 
                            object into the collection if no matching document 
                            is found.
    1           MultiUpdate If set, the database will update all matching 
                            objects in the collection. Otherwise only updates 
                            first matching doc.
    2-31        Reserved    Must be set to 0.

"""
class OP_UPDATE(blocks.block):
    def __init__(self, name, request, value, options=None):
        blocks.block.__init__(self, name, request, None, None, None, None)
        self.db = options.get("db", "test")
        self.collection = options.get("collection", "fuzzing")
        self.flags = options.get("flags", 2)
        self.selector = options.get("selector", {})
        self.update = options.get("update", {})
        # Form an internal block
        message = blocks.block(name + "_update", request)
        # Push a message header onto the message
        header_opts = options.get("header_opts", {})
        header_opts["opCode"] = 2001
        header = sulley.legos.BIN["MsgHeader"]("Upd_"+str(getrandbits(32)),
                                               blocks.CURRENT, 
                                               None, 
                                               options=header_opts)
        message.push(header)
        message.push(primitives.dword(0, signed=True))
        message.push(primitives.string(self.db))
        message.push(primitives.delim("."))
        message.push(primitives.string(self.collection))
        message.push(primitives.dword(self.flags, signed=True))
        message.push(primitives.random_data(BSON.encode(self.selector), 0,
                                            16*(2**20)))
        message.push(primitives.random_data(BSON.encode(self.update), 0,
                                            16*(2**20)))
        self.push(message)

###############################################################################

"""
    struct OP_INSERT {
        MsgHeader header;             // standard message header_opts
        int32     flags;              // bit vector - see below
        cstring   fullCollectionname; // "dbname.collectionname"
        document* documents;          // one or more documents to 
                                      // insert into the collection
    }

    bit num     name                description 
    0           ContinueOnError     If set, the database will not stop 
                                    processing a bulk insert if one fails 
                                    (eg due to duplicate IDs). This makes bulk
                                    insert behave similarly to a series of 
                                    single inserts, except lastError will be 
                                    set if any insert fails, not just the last
                                    one. If multiple errors occur, only the 
                                    most recent will be reported by 
                                    getLastError.
    1-31        Reserved            Must be set to 0
"""
class OP_INSERT(blocks.block):
    def __init__(self, name, request, value, options=None):
        blocks.block.__init__(self, name, request, None, None, None, None)
        self.flags = options.get("flags", 1)
        self.db = options.get("db", "test")
        self.collection = options.get("collection", "fuzzing")
        self.documents = options.get("documents", [{}])
        # Form an internal block.
        message = blocks.block(name + "_insert", request)
        # Push a message header onto the message
        header_opts = options.get("header_opts", {})
        header_opts["opCode"] = 2002
        header = sulley.legos.BIN["MsgHeader"]("Ins_"+str(getrandbits(32)),
                                               blocks.CURRENT, 
                                               None, 
                                               options=header_opts)
        message.push(header)
        message.push(primitives.dword(self.flags, signed=True))
        message.push(primitives.string(self.db))
        message.push(primitives.delim("."))
        message.push(primitives.string(self.collection))
        # Add all documents to the message
        for doc in self.documents:
            message.push(primitives.random_data(BSON.encode(doc), 0, 
                                                16*(2**20)))
        self.push(message)


###############################################################################

"""
    struct OP_KILL_CURSORS {
        MsgHeader header;            // standard message header
        int32     ZERO;              // 0 - reserved for future use
        int32     numberOfCursorIDs; // number of cursorIDs in message
        int64*    cursorIDs;         // sequence of cursorIDs to close
    }
"""
# Need to come up with a way to have cursors and know their cursor_id

class OP_KILL_CURSORS(blocks.block):
    def __init__(self, name, request, value, options=None):
        blocks.block.__init__(self, name, request, None, None, None, None)
        self.numberOfCursorIDs = options.get('numberOfCursorIDs', 10)
        self.cursorIDs = options.get('cursorIDs', None)
        if not self.cursorIDs or len(self.cursorIDs) != self.numberOfCursorIDs:
            self.cursorIDs = []
            for i in range(0,self.numberOfCursorIDs):
                self.cursorIDs.append(randint(0,999999999))
        # Form an internal block.
        message = blocks.block(name + "kill_cursors", request)
        # Create a message header block. It must have a unique name.
        header_opts = options.get("header_opts", {})
        header_opts["opCode"] = 2007
        header = sulley.legos.BIN["MsgHeader"]("Kill_"+str(getrandbits(32)),
                                               blocks.CURRENT, 
                                               None, 
                                               options=header_opts)
        message.push(header)
        # The docs say that this is always zero, do we want to fuzz this?
        # In the future this may change so this needs to be changed
        message.push(primitives.dword(0, signed=True))
        message.push(primitives.dword(self.numberOfCursorIDs, signed=True))
        for ID in self.cursorIDs:
            message.push(primitives.qword(ID, signed=True))
        # Add block to self.
        self.push(message)

###############################################################################
