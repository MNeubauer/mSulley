from mSulley.sulley import primitives
from struct import pack
from random import randint
from random import seed
from mSulley.sulley.legos.Mongo_op import Mongo_op

# Sulley is a deterministic fuzzer. This seed is set to keep client code
# deterministic as well. The actual seed was chosen randomly.
seed(6)
       
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
class OP_UPDATE(Mongo_op):
    """This sulley lego represents an OP_UPDATE MongoDB message"""
    def __init__(self, name, request, value, options):
        # Create the super class and push a header to the block.
        options = self.init_options(options, 2001)
        Mongo_op.__init__(self, name, request, options)
        
        self.db = options.get("db", "test")
        self.collection = options.get("collection", "fuzzing")
        self.flags = options.get("flags", 2)
        self.selector = options.get("selector", {})
        self.update = options.get("update", {})
       
        # int32 ZERO
        self.push(primitives.dword(0, signed=True))
        # cstring fullCollectionname
        self.push_namespace(self.db, self.collection)
        # int32 flags
        self.push(primitives.dword(self.flags, signed=True))
        # document selector
        self.push_bson_doc(self.selector)
        # document update
        self.push_bson_doc(self.update)
        self.end_block()

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
class OP_INSERT(Mongo_op):
    """This sulley lego represents an OP_INSERT MongoDB message."""
    def __init__(self, name, request, value,  options):
        # Create the super class and push a header to the block.
        options = self.init_options(options, 2002)
        Mongo_op.__init__(self, name, request, options)

        self.flags = options.get("flags", 1)
        self.db = options.get("db", "test")
        self.collection = options.get("collection", "fuzzing")
        self.documents = options.get("documents", [{}])
        
        # int32 flags
        self.push(primitives.dword(self.flags, signed=True))
        # cstring fullCollectionname
        self.push_namespace(self.db, self.collection)
        # document* documents
        for doc in self.documents:
            self.push_bson_doc(doc)
        self.end_block()


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

class OP_KILL_CURSORS(Mongo_op):
    """This sulley lego represents an OP_KILL_CURSORS MongoDB message."""
    def __init__(self, name, request, value, options):
        # Create the super class and push a header to the block.
        options = self.init_options(options, 2007)
        Mongo_op.__init__(self, name, request, options)

        self.numberOfCursorIDs = options.get('numberOfCursorIDs', 10)
        self.cursorIDs = options.get('cursorIDs', None)
        if not self.cursorIDs or len(self.cursorIDs) != self.numberOfCursorIDs:
            self.cursorIDs = []
            for i in range(0,self.numberOfCursorIDs):
                self.cursorIDs.append(randint(0,2**63-1))

        # int32 ZERO
        self.push(primitives.dword(0, signed=True))
        # int32 numberOfCursorIDs
        self.push(primitives.dword(self.numberOfCursorIDs, signed=True))
        # int64* cursorIDs
        for ID in self.cursorIDs:
            self.push(primitives.qword(ID, signed=True))
        self.end_block()

###############################################################################
