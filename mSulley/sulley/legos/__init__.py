import ber
import dcerpc
import misc
import xdr
import mongo
# all defined legos must be added to this bin.
BIN = {}

BIN["OP_KILL_CURSORS"]      = mongo.OP_KILL_CURSORS
BIN["OP_INSERT"]            = mongo.OP_INSERT

BIN["ber_string"]           = ber.string
BIN["ber_integer"]          = ber.integer
BIN["dns_hostname"]         = misc.dns_hostname
BIN["ndr_conformant_array"] = dcerpc.ndr_conformant_array
BIN["ndr_wstring"]          = dcerpc.ndr_wstring
BIN["ndr_string"]           = dcerpc.ndr_string
BIN["tag"]                  = misc.tag
BIN["xdr_string"]           = xdr.string
