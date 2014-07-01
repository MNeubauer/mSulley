from sulley import blocks, primitives, legos

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

class MsgHeader(blocks.blocks):
    def __init__(self, name, request, value, options={"requestID": None, 
                                                      "responseTo": None,
                                                      "opCode": None}):
        blocks.block.__init__(self, name, request, None, None, None, None)
        self.requestID = options["requestID"]
        self.responseTo = options["responseTo"]
        self.opCode = options["opCode"]
        # Form an internal block.
        message = blocks.block(name + "header", request)
        message.push(primitives.dword(self.requestID, signed=True))
        message.push(primitives.dword(self.responseTo, signed=True))
        message.push(primitives.dword(self.opCode, signed=True))
        # Add block to self.
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

class OP_KILL_CURSORS(blocks.blocks):
    def __init__(self, name, request, value, options={
                                                    "numberOfCursorIDs": None,
                                                    "cursorIDs": None
                                                     }):
        blocks.block.__init__(self, name, request, None, None, None, None)
        self.opCode = 2007
        self.numberOfCursorIDs = options["numberOfCursorIDs"]
        self.cursorIDs = options["cursorIDs"]
        # Form an internal block.
        message = blocks.block(name + "kill_cursors", request)
        message.push(s_lego("MsgHeader", None, options=
                                                    {"requestID": 2342, 
                                                     "responseTo": 2453,
                                                     "opCode": self.opcode}))
        # For now, this is always zero, do we want to fuzz this?
        message.push(primitives.dword(0, signed=True))
        message.push(primitives.dword(self.numberOfCursorIDs, signed=True))
        message.push(primitives.qword(self.cursorIDs, signed=True))
        # Add block to self.
        self.push(message)

###############################################################################