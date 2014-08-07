from bson import BSON
from pymongo.common import MAX_BSON_SIZE
from random import seed, randint, getrandbits
from struct import pack
from sulley.blocks import (block as SulleyBlock,
                           size as s_sizer)
from sulley.primitives import dword, random_data, group, delim, string

# Sulley is a deterministic fuzzer. This seed is set to keep client code
# deterministic as well. The actual seed was chosen randomly.
# TODO: Change the seed for each run, but record it so the run is reproducable.
seed(475)

class MongoMsg(SulleyBlock):
    """A base class representing all legos for MongoDB operations"""

    def __init__(self, name, request, options):
        SulleyBlock.__init__(self, name, request, None, None, None, None)
        self.block_name = name + "_"
        self.block = SulleyBlock(self.block_name, request)
        self.requestID = options.get("requestID", randint(0, (2**31)-1))
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

            opCode           value  Comments
            
            OP_REPLY         1      Reply to a client request
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
        SulleyBlock.push(self, s_sizer(self.block_name, 
                                   self.request, 
                                   inclusive=True, 
                                   signed=True))
        # Add the rest of the header to the inner block.
        self.block.push(dword(self.requestID, signed=True))
        if isinstance(self.responseTo, list):
            self.block.push(group(self.block_name + "responseTo",
                                  self.responseTo))
        else:
            self.block.push(dword(self.responseTo, signed=True))
        self.block.push(dword(self.opCode, signed=True))

    def push_namespace(self, db, collection):
        self.block.push(string(db))
        self.block.push(delim("."))
        self.block.push(string(collection))

    def push_bson_doc(self, doc):
        self.block.push(random_data(BSON.encode(doc), min_length=0,
                        max_length=MAX_BSON_SIZE))

    def push(self, item):
        self.block.push(item)

    def end_block(self):
        SulleyBlock.push(self, self.block)
