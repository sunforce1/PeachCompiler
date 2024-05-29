#include "compiler.h"
#include <string.h>
#include <assert.h>
#include "helpers/vector.h"
#include "helpers/buffer.h"
#include "compiler.h"
#include "ctype.h"

#define LEX_GET_C_IF(buffer, c, exp)     \
    for (c == peekc(); exp; c = peekc()) \
    {                                    \
        buffer_write(buffer, c);         \
        nextc();                         \
    }

static struct lex_process *lex_process;
bool lex_is_in_expression();
static struct token tmp_token;
struct token *read_next_token();

static char peekc()
{
    return lex_process->function->peek_char(lex_process);
};

static char nextc()
{
    char c = lex_process->function->next_char(lex_process);

    if (lex_is_in_expression()) {
        buffer_write(lex_process->parentheses_buffer, c);
    }

    lex_process->pos.col += 1;

    if (c == '\n')
    {
        lex_process->pos.col = 1;
        lex_process->pos.line = +1;
    }

    return c;
}

static void pushc(char c)
{
    return lex_process->function->push_char(lex_process, c);
}

static char assert_next_char(char c) {
    char next_c = nextc();

    assert(c == next_c);
    return next_c;
}
static struct token *token_create(struct token *token)
{
    memcpy(&tmp_token, token, sizeof(struct token));
    tmp_token.pos = lex_process->pos;

    if (lex_is_in_expression()) {
        tmp_token.between_brackets = buffer_ptr(lex_process->parentheses_buffer);
    }

    return &tmp_token;
}

static struct token *handle_whitespace()
{

    struct token *last_token = vector_back_or_null(lex_process->token_vec);

    if (last_token)
    {
        last_token->whitespace = true;
    }

    nextc();
    return read_next_token();
}

const char *read_number_str()
{
    const char *NUM = NULL;
    struct buffer *buffer = buffer_create();
    char c = peekc();

    LEX_GET_C_IF(buffer, c, (c >= '0' && c <= '9'));

    buffer_write(buffer, 0x00);

    return buffer_ptr(buffer);
}

unsigned long long read_number()
{
    const char *s = read_number_str();
    return atoll(s);
}

int lexer_number_type(char c) {
    
    int a = NUMBER_TYPE_NORMAL;

    if (c == 'L') {
        a = NUMBER_TYPE_LONG;
    } else if (c == 'F') {
        a = NUMBER_TYPE_FLOAT;
    }

    return a;
}

struct token *token_make_number_for_value(unsigned long number)
{
    int number_type = lexer_number_type(peekc());
    
    if (number_type != NUMBER_TYPE_NORMAL) {
        nextc();
    }
    return token_create(&(struct token){.type = TOKEN_TYPE_NUMBER, .llnum = number, .num = number_type});
}

struct token *token_make_number()
{

    return token_make_number_for_value(read_number());
}

struct token *token_make_string(char start_delim, char end_delim)
{

    struct buffer *string_buffer = buffer_create();
    assert(nextc() == start_delim);
    char c = peekc();

    for (; c != end_delim && c != EOF; c = nextc())
    {

        if (c == '\\')
        {

            continue;
        }

        buffer_write(string_buffer, c);
    }

    buffer_write(string_buffer, 0x00);

    return token_create(&(struct token){.type = TOKEN_TYPE_STRING, .sval = buffer_ptr(string_buffer)});
}

static bool op_treated_as_one(char op)
{

    return op == '(' ||
           op == '[' ||
           op == ',' ||
           op == '.' ||
           op == '*' ||
           op == '?';
}

static bool is_single_operator(char op)
{

    return op == '+' ||
           op == '-' ||
           op == '/' ||
           op == '*' ||
           op == '=' ||
           op == '>' ||
           op == '<' ||
           op == '|' ||
           op == '&' ||
           op == '^' ||
           op == '%' ||
           op == '~' ||
           op == '!' ||
           op == '(' ||
           op == '[' ||
           op == ',' ||
           op == '.' ||
           op == '?';
}

bool op_valid(const char *op)
{

    return S_EQ(op, "+") ||
           S_EQ(op, "-") ||
           S_EQ(op, "*") ||
           S_EQ(op, "/") ||
           S_EQ(op, "!") ||
           S_EQ(op, "^") ||
           S_EQ(op, "+=") ||
           S_EQ(op, "-=") ||
           S_EQ(op, "*=") ||
           S_EQ(op, "/=") ||
           S_EQ(op, ">>") ||
           S_EQ(op, "<<") ||
           S_EQ(op, ">=") ||
           S_EQ(op, "<=") ||
           S_EQ(op, ">") ||
           S_EQ(op, "<") ||
           S_EQ(op, "||") ||
           S_EQ(op, "&&") ||
           S_EQ(op, "|") ||
           S_EQ(op, "&") ||
           S_EQ(op, "++") ||
           S_EQ(op, "--") ||
           S_EQ(op, "=") ||
           S_EQ(op, "!=") ||
           S_EQ(op, "==") ||
           S_EQ(op, "->") ||
           S_EQ(op, "(") ||
           S_EQ(op, "[") ||
           S_EQ(op, ",") ||
           S_EQ(op, ".") ||
           S_EQ(op, "...") ||
           S_EQ(op, "~") ||
           S_EQ(op, "?") ||
           S_EQ(op, "%");
}

const char *read_op()
{

    bool single_operator = true;
    char op = nextc();
    struct buffer *buffer = buffer_create();
    buffer_write(buffer, op);

    if (!op_treated_as_one(op))
    {
        op == peekc();

        if (is_single_operator(op))
        {

            buffer_write(buffer, op);
            nextc();
            single_operator = false;
        }
    }

    buffer_write(buffer, 0x00);
    char *ptr = buffer_ptr(buffer);

    if (!single_operator)
    {
        if (!op_valid(ptr))
        {

            const char *data = ptr;
            int len = buffer->len;

            for (int i = len - 1; i >= 1; --i)
            {
                if (data[i] == 0x00)
                {
                    continue;
                }
                pushc(data[i]);
            }
            ptr[1] = 0x00;
        }
    }
    else if (!op_valid(ptr))
    {
        compiler_error(lex_process->compiler, "The operator %s is not valid\n", ptr);
    }

    return ptr;
}

static void lex_new_expression()
{

    lex_process->current_expression_count++;

    if (lex_process->current_expression_count == 1)
    {
        lex_process->parentheses_buffer = buffer_create();
    }
}

static void lex_finish_expression()
{
    lex_process->current_expression_count--;
    if (lex_process->current_expression_count < 0)
    {

        compiler_error(lex_process->compiler, "You closed an expression that you never opened\n");
    }
}

bool lex_is_in_expression()
{
    return lex_process->current_expression_count > 0;
}

static struct token *token_make_operator_or_string()
{
    char op = peekc();

    if (op == '<')
    {
        struct token *last_token = vector_back_or_null(lex_process->token_vec);

        if (token_is_keyword(last_token, "include"))
        {

            return token_make_string('<', '>');
        }
    }

    struct token *token = token_create(&(struct token){.type = TOKEN_TYPE_OPERATOR, .sval = read_op()});

    if (op == '(')
    {
        lex_new_expression();
    }

    return token;
}

static struct token *token_make_symbol()
{
    char c = nextc();

    if (c == ')')
    {
        lex_finish_expression();
    }

    struct token *token = token_create(&(struct token){.type = TOKEN_TYPE_SYMBOL, .cval = c});
    return token;
}

bool is_keyword(const char *str)
{
    return S_EQ(str, "unsigned") ||
           S_EQ(str, "signed") ||
           S_EQ(str, "char") ||
           S_EQ(str, "int") ||
           S_EQ(str, "short") ||
           S_EQ(str, "float") ||
           S_EQ(str, "double") ||
           S_EQ(str, "long") ||
           S_EQ(str, "void") ||
           S_EQ(str, "struct") ||
           S_EQ(str, "union") ||
           S_EQ(str, "static") ||
           S_EQ(str, "_ignore_typecheck") ||
           S_EQ(str, "return") ||
           S_EQ(str, "include") ||
           S_EQ(str, "sizeof") ||
           S_EQ(str, "if") ||
           S_EQ(str, "else") ||
           S_EQ(str, "while") ||
           S_EQ(str, "for") ||
           S_EQ(str, "do") ||
           S_EQ(str, "break") ||
           S_EQ(str, "continue") ||
           S_EQ(str, "switch") ||
           S_EQ(str, "case") ||
           S_EQ(str, "default") ||
           S_EQ(str, "goto") ||
           S_EQ(str, "typedef") ||
           S_EQ(str, "const") ||
           S_EQ(str, "extern") ||
           S_EQ(str, "restrict");
}

static struct token *token_make_identifier_or_keyword()
{

    struct buffer *buffer = buffer_create();
    char c = peekc();

    LEX_GET_C_IF(buffer, c, (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_');

    // write null terminator
    buffer_write(buffer, 0x00);

    if (is_keyword(buffer_ptr(buffer))) {
        
        return token_create(&(struct token){.type = TOKEN_TYPE_KEYWORD, .sval = buffer_ptr(buffer)});
    }

    return token_create(&(struct token){.type = TOKEN_TYPE_IDENTIFIER, .sval = buffer_ptr(buffer)});
}

static struct token *read_special_token()
{
    char c = peekc();
    if (isalpha(c) || c == '_')
    {
        return token_make_identifier_or_keyword();
    }

    return NULL;
}

static struct token *token_make_newline() {
    char c = nextc();

    return token_create(&(struct token){.type = TOKEN_TYPE_NEWLINE});

}

static struct token *token_make_one_line_comment() {
    struct buffer *buffer = buffer_create();
    char c = 0;

    LEX_GET_C_IF(buffer, c, (c != '\n' && c != EOF));

    return token_create(&(struct token){.type = TOKEN_TYPE_COMMENT, .sval = buffer_ptr(buffer)});
}

static struct token *token_make_multiline_comment() {
    struct buffer *buffer = buffer_create();
    char c = 0;

    while (1) {

        LEX_GET_C_IF(buffer, c, c!= '*' && c!= EOF);

        if (c == EOF) {
            compiler_error(lex_process -> compiler, "Multiline comment not closed");
        } else if (c == '*') {
            nextc();
            if (peekc() == '/') {
                nextc();
                break;
            }
        }
    }

    return token_create(&(struct token){.type = TOKEN_TYPE_COMMENT, .sval = buffer_ptr(buffer)});
}

struct token *handle_comment() {
    char c = peekc();

    if (c == '/') {
        nextc();
        if (peekc() == '/') {
            nextc();
            return token_make_one_line_comment();
        } else if (peekc() == '*') {
            nextc();
            return token_make_multiline_comment();
        }
        pushc('/');

        return token_make_operator_or_string();

    }
    return NULL;
}

static char get_escaped_char(char c) {

    char co = 0;

    switch(c) {
        case 'n':
            co = '\n';
            break;
        
        case 't':
            co = '\t';
            break;
        
        case '\\':
            co = '\\';
            break;
        
        case '\'':
            co = '\'';
            break;
    }

    return co;
}

const char *make_hexadecimal_number_str() {
    struct buffer *buffer = buffer_create();
    char c = peekc();

    LEX_GET_C_IF(buffer, c, ((c >= '0' && c <= '9') || (c >= 'a' && 'f') || (c >= 'A' && c <= 'F')));

    buffer_write(buffer, 0x00);
    return buffer_ptr(buffer);
}
static struct token *token_make_hexadecimal_number() {
    // skip the x

    nextc();

    unsigned long number = 0;
    const char *hexadecimal_number = make_hexadecimal_number_str();
    number = strtol(hexadecimal_number, 0, 16);

    return token_make_number_for_value(number);
}

void validate_binary_number(const char* bin) {

    size_t len = strlen(bin);

    for (int i = 0; i < len; i++) {

        if (bin[i] != '0' && bin[i] != '1') {
            compiler_error(lex_process->compiler, "This is not a binary number");
        }
    }
}

static struct token *token_make_binary_number() {
    // skip the b
    nextc();
    unsigned long number = 0;
    const char *binary_number = read_number_str();

    //validate binary number
    validate_binary_number(binary_number);

    number = strtol(binary_number, 0, 2);

    return token_make_number_for_value(number);
}

static struct token *token_make_special_number() {

    struct token *token = NULL;
    struct token *last_token = vector_back_or_null(lex_process->token_vec);

    if (!last_token || !(last_token->type == TOKEN_TYPE_NUMBER && last_token ->llnum == 0)) {
        return token_make_identifier_or_keyword();
    }

    vector_pop(lex_process->token_vec);

    char c = peekc();


    // hexadecimal case
    if (c == 'x') {
        token = token_make_hexadecimal_number();
    } else if (c == 'b') {
        token = token_make_binary_number();
    }

    return token;

}

struct token* token_make_quotes() {

    assert_next_char('\'');
    char c = nextc();

    if (c =='\\') {
        c = nextc();
        c = get_escaped_char(c);
    }

    if (nextc() != '\'') {
        compiler_error(lex_process->compiler, "Quote is not closed");
    }

    return token_create(&(struct token){.type = TOKEN_TYPE_NUMBER, .cval = c});
}

struct token *read_next_token()
{
    struct token *token = NULL;

    char c = peekc();

    token = handle_comment();

    if (token) {
        return token;
    }
    
    switch (c)
    {

    // decimal number case
    NUMERIC_CASE:
        token = token_make_number();
        break;

    // operator case excluding division
    OPERATOR_CASE_EXCLUDING_DIVISION:
        token = token_make_operator_or_string();
        break;

    SYMBOL_CASE
        token = token_make_symbol();
        break;

    case 'b':
        token = token_make_special_number();
        break;
    case 'x':
        token = token_make_special_number();
        break;
    // strings case
    case '"':
        token = token_make_string('"', '"');
        break;
    
    // quote case
    case '\'':
        token = token_make_quotes();
        break;
    // whitespace or tab case
    case ' ':
    case '\t':
        token = handle_whitespace();
        break;
    // case newline
    case '\n':
        token = token_make_newline();
        break;
    case EOF:
        break;

    default:

        token = read_special_token();
        if (!token)
        {
            compiler_error(lex_process->compiler, "Unexpected token\n");
        }
    }

    return token;
};

int lex(struct lex_process *process)
{

    process->current_expression_count = 0;
    process->parentheses_buffer = NULL;
    lex_process = process;
    process->pos.filename = process->compiler->cfile.abs_path;

    struct token *token = read_next_token();

    while (token)
    {

        vector_push(process->token_vec, token);
        token = read_next_token();
    }


    return LEXICAL_ANALYIS_ALL_OK;
}
char lexer_string_buffer_next(struct lex_process* process) {

    struct buffer* buffe = lex_process_private(process);
    return buffer_read(buffe);

}
char lexer_string_buffer_peak(struct lex_process* process) {

    struct buffer* buffe = lex_process_private(process);
    return buffer_peek(buffe);

}
void lexer_string_buffer_push(struct lex_process* process, char c) {

    struct buffer* buffe = lex_process_private(process);
    return buffer_write(buffe, c);

}


struct lex_process_functions lexer_str_buffer_funct =  {
    .next_char = lexer_string_buffer_next,
    .peek_char = lexer_string_buffer_peak,
    .push_char = lexer_string_buffer_push
};


struct lex_process* tokens_build_tokens_from_string(struct compile_process* compiler, const char* str) {

    struct buffer* buffer = buffer_create();
    buffer_printf(buffer, str);

    struct lex_process* lex_process= lex_process_create(compiler, &lexer_str_buffer_funct, buffer);

    if (!lex_process) {
        return NULL;
    }

    if (lex(lex_process) != LEXICAL_ANALYIS_ALL_OK) {
        return NULL;
    }

    return lex_process;
}