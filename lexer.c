#include "compiler.h"
#include <string.h>
#include "helpers/vector.h"
#include "helpers/buffer.h"

#define LEX_GET_C_IF(buffer, c, exp) \
    for (c == peekc(); exp; c = peekc()) \
    {                                    \
        buffer_write(buffer,c);          \
        nextc();                         \
    }


static struct lex_process* lex_process;
static struct token tmp_token;
struct token* read_next_token();

static char peekc() {
    return lex_process->function->peek_char(lex_process);
};

static char nextc() {
    char c = lex_process->function->next_char(lex_process);
    lex_process->pos.col += 1;

    if (c == '\n') {
        lex_process->pos.col = 1;
        lex_process->pos.line =+ 1;
    }

    return c;
}

static void pushc(char c) {
    return lex_process->function->push_char(lex_process, c);
}

static struct token* token_create(struct token* token) {
    memcpy(&tmp_token, token, sizeof(struct token));
    tmp_token.pos = lex_process->pos;

    return &tmp_token;
}

static struct token* handle_whitespace() {

    struct token* last_token = vector_back_or_null(lex_process->token_vec);

    if (last_token) {
        last_token -> whitespace = true;
    }

    nextc();
    return read_next_token();
}

const char* read_number_str() {
    const char* NUM = NULL;
    struct buffer* buffer = buffer_create();
    char c = peekc();

    LEX_GET_C_IF(buffer, c, (c >= '0' && c <= '9'));

    buffer_write(buffer, 0x00);

    return buffer_ptr(buffer);

}

unsigned long long read_number() {
    const char* s = read_number_str();
    return atoll(s);
}
struct token* token_make_number_for_value(unsigned long number) {
    return token_create(&(struct token){.type = TOKEN_TYPE_NUMBER, .llnum = number});
}



struct token* token_make_number() {

    return token_make_number_for_value(read_number());
}

struct token* read_next_token() {
    struct token* token = NULL;

    char c = peekc();

    switch(c) {

        NUMERIC_CASE:
        token = token_make_number();
        break;

        case ' ':
        case '\t':
            handle_whitespace();
            break;


        case EOF:
        break;

        default:
            compiler_error(lex_process->compiler,"Unexpected token\n");
    }

    return token;
};

int lex(struct lex_process* process) {

    process->current_expression_count = 0;
    process->parentheses_buffer = NULL;
    lex_process = process;
    process->pos.filename = process->compiler->cfile.abs_path;

    struct token* token = read_next_token();

    while (token) {
        
        vector_push(process->token_vec, token);
        token = read_next_token();
    }
    return LEXICAL_ANALYIS_ALL_OK;
}