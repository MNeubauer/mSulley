from mSulley.sulley import blocks
from mSulley.sulley import primitives
from random import seed
from random import randint
from random import getrandbits
from struct import pack
from bson import BSON

seed(475)

class Mongo_op(blocks.block):
    """An abstract class representing all legos for MongoDB operations"""
    def __init__(self, name, request, options):
        blocks.block.__init__(self, name, request, None, None, None, None)
        self.block_name = name + "_"
        self.block = blocks.block(self.block_name, request)
        self.requestID = options.get("requestID", randint(1, (2**31)-1))
        self.responseTo = options.get("responseTo", 
                                          [pack('<i',0), pack('<i',-1)])
        self.opCode = options["opCode"]
        self.push_header()

    def init_options(self, options, opCode):
        if not options:
            options = {}
        options["opCode"] = opCode
        return options

    def push_header(self):
        """
            struct MsgHeader {
                int32   messageLength; // total message size, including this
                int32   requestID;     // identifier for this message
                int32   responseTo;    // requestID from the original request
                                       //   (used in reponses from db)
                int32   opCode;        // request type - see table below
            }

            opCode      value   Comments
            
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
        # Size the inner block.
        blocks.block.push(self, blocks.size(self.block_name, 
                                            self.request, 
                                            inclusive=True, 
                                            signed=True))
        # Add the rest of the header to the inner block.
        self.block.push(primitives.dword(self.requestID, signed=True))
        if isinstance(self.responseTo, list):
            self.block.push(primitives.group(self.block_name + "responseTo",
                                             self.responseTo))
        else:
            self.block.push(primitives.dword(self.responseTo, signed=True))
        self.block.push(primitives.dword(self.opCode, signed=True))

    def push_namespace(self, db, collection):
        self.block.push(primitives.string(db))
        self.block.push(primitives.delim("."))
        self.block.push(primitives.string(collection))

    def push_bson_doc(self, doc):
        self.block.push(primitives.random_data(
            BSON.encode(doc), 0, 16*(2**20)))

    def push(self, item):
        self.block.push(item)

    def end_block(self):
        blocks.block.push(self, self.block)
