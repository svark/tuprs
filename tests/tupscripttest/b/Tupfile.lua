tup:include('../TupDefines.lua')
inps = {'in1.txt', extra_inputs = {'../<mygrp>'}}
outs = {"outs.txt"}
copy_rule(inps, outs)
