struct IfEq {
    lhs: String,
    rhs : String
};

struct IfnEq {
    lhs: String,
    rhs : String
};
struct Include
{
    fpath : String
};
struct Preload
{
    fpath : String
};
struct Assignment
{
    lhs: String,
    rhs : String
};

struct Rule
{
    prefix: String,
    command : String
};

struct RuleApplication
{
    src: String,
    osrc: String,
    rule: Rule,
    otgt: String,
    tgt: String
};

