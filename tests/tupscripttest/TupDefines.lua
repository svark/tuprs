OPTIONS = '-r';

function copy_rule (inputs, outputs)
    rule = 'cp ' .. OPTIONS .. ' %f %o'
    return tup:rule(inputs,rule,outputs)
end