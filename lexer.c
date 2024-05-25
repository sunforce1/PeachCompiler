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
static struct token tmp_token;
struct token *read_next_token();

static char peekc()
{
    return lex_process->function->peek_char(lex_process);
};

static char nextc()
{
    char c = lex_process->function->next_char(lex_process);
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

static struct token *token_create(struct token *token)
{
    memcpy(&tmp_token, token, sizeof(struct token));
    tmp_token.pos = lex_process->pos;

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

struct token *token_make_number_for_value(unsigned long number)
{
    return token_create(&(struct token){.type = TOKEN_TYPE_NUMBER, .llnum = number});
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
        if (!op_valid(ptr)) {

            const char *data = ptr;
            int len = buffer -> len;

            for (int i = len - 1; i >= 1; --i) {
                if (data[i] == 0x00) {
                    continue;
                }
                pushc(data[i]);                
            }
            ptr[1] = 0x00;  
        }
    } else if (!op_valid(ptr)) {
        compiler_error(lex_process->compiler, "The operator %s is not valid\n", ptr);
    }

    return ptr;
}

static void lex_new_expression() {

    lex_process -> current_expression_count++;

    if (lex_process->current_expression_count == 1) {
        lex_process->parentheses_buffer = buffer_create();
    }
}

static void lex_finish_expression() {
    lex_process->current_expression_count--;
    if (lex_process -> current_expression_count < 0) {

        compiler_error(lex_process->compiler, "You closed an expression that you never opened\n");
    }

}

bool lex_is_in_expression() {
    return lex_process->current_expression_count > 0;
}

static struct token *token_make_operator_or_string()
{
    char op = peekc();

    if (op == '<') {
        struct token* last_token = vector_back_or_null(lex_process->token_vec);

        if(token_is_keyword(last_token,"include")) {
            
            return token_make_string('<', '>');
        }
    }

    struct token* token = token_create(&(struct token){.type = TOKEN_TYPE_OPERATOR, .sval = read_op()});

    if (op == '(') {
        lex_new_expression();
    }

    return token;
}

static struct token* token_make_symbol()
{
    char c = nextc();

    if (c == ')') {
        lex_finish_expression();
    }

    struct token* token = token_create(&(struct token){.type = TOKEN_TYPE_SYMBOL, .cval = c});
    return token;

}

static struct token* token_make_identifier_or_keyword() {
    
    struct buffer* buffer = buffer_create();
    char c = peekc();

    LEX_GET_C_IF(buffer, c, (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||(c >= '0' && c <= '9')|| c=='_');

    //write null terminator
    buffer_write(buffer, 0x00);

     return token_create(&(struct token){.type = TOKEN_TYPE_IDENTIFIER, .sval = buffer_ptr(buffer)});

}

static struct token* read_special_token() {
    char c = peekc();
    if (isalpha(c) || c == '_') {
        return token_make_identifier_or_keyword();
    }

    return NULL;
}



struct token *read_next_token()
{
    struct token *token = NULL;

    char c = peekc();

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
    // strings case
    case '"':
        token = token_make_string('"', '"');
        break;

    // whitespace or tab case
    case ' ':
    case '\t':
        token = handle_whitespace();
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