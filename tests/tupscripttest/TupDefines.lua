OPTIONS = '-r';

function copy_rule (inputs, outputs)
    rule = 'cp ' .. OPTIONS .. ' %f %o'
    return tup:frule(inputs,rule,outputs)
end