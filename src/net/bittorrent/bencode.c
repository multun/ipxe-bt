#include <ipxe/bencode.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define BTBUF_EOF ( -1 )

static void bencode_free_dict ( struct bdict * cur ) {
	for ( struct bdict *prev = NULL; cur || prev;
	      prev = cur, !cur || ( cur = cur->next ) )
		if ( prev ) {
			bencode_free ( prev->key );
			bencode_free ( prev->value );
			free ( prev );
		}
}


static void bencode_free_list ( struct blist * list ) {
	struct blist_node * cur = list->tail;
	for ( struct blist_node * prev = NULL; cur || prev;
	      prev = cur, !cur || ( cur = cur->next ) )
		if ( prev ) {
			bencode_free ( prev->value );
			free ( prev );
		}
}

void bencode_free ( struct bdata * benc ) {
	if ( !benc )
		return;

	switch ( benc->type ) {
	case BINT:
	case BSTR:
		break;
	case BDICT:
		bencode_free_dict ( benc->data.dict );
		break;
	case BLIST:
		bencode_free_list ( &benc->data.list );
		break;
	}

	free ( benc );
}

static int btbuf_peek ( struct btbuf * buf ) {
	return buf->begin != buf->end ? *buf->begin : BTBUF_EOF;
}

static void btbuf_shrink ( struct btbuf * buf, size_t size ) {
	buf->begin += size;
	assert ( buf->begin <= buf->end );
}

static int btbuf_pop ( struct btbuf * buf ) {
	int res = btbuf_peek ( buf );
	if ( res == BTBUF_EOF )
		return res;

	btbuf_shrink ( buf, 1 );
	return res;
}

// dest_parse modifies its target buffer metadata
static struct bdata * bencode_dest_parse ( struct btbuf * buf );

static bool parse_uint ( bint_t * res, struct btbuf * buf, char stop ) {
	*res = 0;

	while ( btbuf_size ( buf ) ) {
		int cchr = btbuf_pop ( buf );
		if ( cchr == BTBUF_EOF )
			return true;

		if ( cchr == stop )
			return false;

		if ( cchr < '0' || cchr > '9' )
			return true;

		/* Overflow check */
		if ( *res >= ( BINT_MAX - 10 ) / 10 )
			return true;

		*res = *res * 10 + ( cchr - '0' );
	}

	return true;
}

static bool parse_int ( bint_t * res, struct btbuf * buf, char stop ) {
	bool sign;
	if ( ( sign = ( btbuf_peek ( buf ) == '-' ) ) )
		btbuf_pop ( buf );

	if ( parse_uint ( res, buf, stop ) )
		return true;

	if ( sign )
		*res *= -1;

	return false;
}

static struct bdata *bencode_int_parse ( struct btbuf * buf ) {
	if ( btbuf_pop ( buf ) != 'i' )
		return NULL;

	bint_t i;
	if ( parse_int ( &i, buf, 'e' ) )
		return NULL;

	struct bdata *res = malloc ( sizeof ( *res ) );
	if ( !res )
		return NULL;

	res->type = BINT;
	res->data.i = i;
	return res;
}

static struct bdata *bencode_str_parse ( struct btbuf * buf ) {
	bint_t string_size;
	if ( parse_uint ( &string_size, buf, ':' ) )
		return NULL;

	size_t ussize = string_size;
	if ( ussize > btbuf_size ( buf ) )
		return NULL;

	struct bdata * res = malloc ( sizeof ( *res ) );
	if ( !res )
		return NULL;

	res->type = BSTR;
	res->data.str = ( struct btbuf ) {
		.begin = buf->begin,
		.end = buf->begin + string_size,
	};

	btbuf_shrink ( buf, string_size );
	return res;
}

static struct bdict *bdict_parse_item ( struct btbuf * buf ) {
	struct bdata * key = bencode_str_parse ( buf );
	if ( !key )
		goto err_key;

	struct bdata * value = bencode_dest_parse ( buf );
	if ( !value )
		goto err_value;

	struct bdict * res = malloc ( sizeof ( *res ) );
	if ( !res )
		goto err_node;

	res->key = key;
	res->value = value;
	res->next = NULL;
	return res;

err_node:
	bencode_free ( value );
err_value:
	bencode_free ( key );
err_key:
	return NULL;
}

static struct bdata * bencode_dict_parse ( struct btbuf * buf ) {
	if ( btbuf_pop ( buf ) != 'd' )
		return NULL;

	struct bdata * res = malloc ( sizeof ( *res ) );
	if ( !res )
		return NULL;

	res->type = BDICT;
	res->data.dict = NULL;

	for ( struct bdict ** ip = &res->data.dict;
	      btbuf_peek ( buf ) != BTBUF_EOF; ) {
		if ( btbuf_peek ( buf ) == 'e' ) {
			btbuf_pop ( buf );
			return res;
		}

		struct bdict * dcur = bdict_parse_item ( buf );
		if ( !dcur )
			goto err_node_alloc;

		*ip = dcur;
		ip = &dcur->next;
	}

	return NULL;

err_node_alloc:
	bencode_free_dict ( res->data.dict );
	free ( res );
	return NULL;
}

static struct blist_node * blist_parse_item ( struct btbuf * buf ) {
	struct bdata * value = bencode_dest_parse ( buf );
	if ( !value )
		return NULL;

	struct blist_node * res = malloc ( sizeof ( *res ) );
	if ( !res )
		return NULL;

	res->value = value;
	res->next = NULL;
	return res;
}

static struct bdata *bencode_list_parse ( struct btbuf * buf ) {
	if ( btbuf_pop ( buf ) != 'l' )
		return NULL;

	struct bdata * res = malloc ( sizeof ( *res ) );
	if ( !res )
		return NULL;

	res->type = BLIST;

	res->data.list.tail = NULL;
	res->data.list.size = 0;

	struct blist_node ** ip = &res->data.list.tail;
	while ( btbuf_peek ( buf ) != BTBUF_EOF ) {
		if ( btbuf_peek ( buf ) == 'e' ) {
			btbuf_pop ( buf );
			return res;
		}

		struct blist_node * dcur = blist_parse_item ( buf );
		if ( !dcur )
			goto err_node_alloc;

		*ip = dcur;
		ip = &dcur->next;
		res->data.list.size++;
	}

	return NULL;

err_node_alloc:
        bencode_free_list ( &res->data.list );
        free ( res );
        return NULL;
}

static struct bdata * bencode_dest_parse ( struct btbuf * buf ) {
	char * orig_begin = buf->begin;
	int cchr = btbuf_peek ( buf );
	if ( cchr == BTBUF_EOF )
		return NULL;

	struct bdata * res;
	if ( cchr == 'l' )
		res = bencode_list_parse ( buf );
	else if ( cchr == 'd' )
		res = bencode_dict_parse ( buf );
	else if ( cchr == 'i' )
		res = bencode_int_parse ( buf );
	else if ( cchr >= '0' && cchr <= '9' )
		res = bencode_str_parse ( buf );
	else
		return NULL;

	res->range = ( struct btbuf ) {
		.begin = orig_begin,
		.end =  buf->begin
	};

	return res;
}

struct bdata * bencode_parse ( const struct btbuf * buf ) {
	struct btbuf buf_cpy = *buf;
	return bencode_dest_parse ( &buf_cpy );
}

struct bdata * bdict_find ( const struct bdict *dict, char * key ) {
	for ( ; dict; dict = dict->next ) {
		if ( dict->key->type != BSTR )
			continue;

		if ( strncmp ( dict->key->data.str.begin, key,
			       btbuf_size ( &dict->key->data.str ) ) == 0 )
			return dict->value;
	}

	return NULL;
}
