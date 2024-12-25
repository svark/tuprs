tup:include('../TupDefines.lua')
inps = {"in0.txt"}
outs = {"outs.txt", extra_outputs = "../<mygrp>"}
copy_rule(inps, outs)

