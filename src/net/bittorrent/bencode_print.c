#include <ipxe/bencode.h>

#include <ctype.h>
#include <stddef.h>

static const struct {
	char c;
	const char * eq;
} char_map[] = {
	{'\\', "\\\\"}, {'"', "\\\""}, {'\b', "\\b"}, {'\f', "\\f"},
	{'\n', "\\n"},  {'\r', "\\r"}, {'\t', "\\t"},
};

static void bdata_print_ol ( const struct bdata * benc );

static void json_putchar ( char c ) {
	if ( !isprint ( c ) ) {
		unsigned char uc = c;
		printf ( "\\u00%02X", uc );
	} else {
		for ( size_t i = 0;
		      i < sizeof ( char_map ) / sizeof ( *char_map ); i++ )
			if ( char_map[ i ].c == c ) {
				printf ( "%s\n", char_map[ i ].eq );
				return;
			}
		putchar ( c );
	}
}

static void bstr_print ( const struct bdata * s ) {
	const struct btbuf * str = &s->data.str;

	putchar ( '"' );

	for ( const char * cur = str->begin; cur < str->end; cur++ )
		json_putchar ( *cur );

	putchar ( '"' );
}

static void bint_print ( const struct bdata * s ) {
	printf ( BINT_F, s->data.i );
}

static void blist_print ( const struct bdata * s ) {
	putchar ( '[' );

	const struct blist * list = &s->data.list;

	for ( const struct blist_node * node = list->tail; node;
	      node = node->next ) {
		bdata_print_ol ( node->value );
		if ( node->next )
			putchar ( ',' );
	}

	putchar ( ']' );
}

static void bdict_print ( const struct bdata * s ) {
	putchar ( '{' );

	for ( const struct bdict *dict = s->data.dict; dict;
	      dict = dict->next ) {
		bdata_print_ol ( dict->key );
		putchar ( ':' );
		bdata_print_ol ( dict->value );

		if ( dict->next )
			putchar ( ',' );
	}

	putchar ( '}' );
}

typedef void ( * bdata_printer ) ( const struct bdata * );

static bdata_printer bdata_get_printer ( const struct bdata * benc ) {
	switch ( benc->type ) {
	case BINT:
		return bint_print;
	case BSTR:
		return bstr_print;
	case BDICT:
		return bdict_print;
	case BLIST:
		return blist_print;
	default:
		return NULL;
	}
}

static void bdata_print_ol ( const struct bdata * benc ) {
	bdata_printer printer = bdata_get_printer ( benc );
	assert ( printer != NULL );
	printer ( benc );
}

void bdata_json_print ( const struct bdata * benc ) {
	bdata_print_ol ( benc );
	putchar ( '\n' );
}
