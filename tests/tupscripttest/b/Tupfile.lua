tup:include('../TupDefines.lua')
inps = {'in1.txt', extra_inputs = {'../<mygrp>'}}
outs = {"outs.txt", bin = "mybin"}
copy_rule(inps, outs)
