from sulley import *

s_initialize("one kill cursor")

# begin each message with the size (32 bit is default)
s_size("kill_message", inclusive=True, signed=True)
if s_block_start("kill_message"):
    s_lego("MsgHeader", None, options={"requestID": 2341,
                               "responseTo": 5212,
                               "opCode": 2007})
    s_lego("OP_KILL_CURSORS", None, options={"numberOfCursorIDs": 2342,
                                     "cursorIDs": 2672 })
s_block_end()
