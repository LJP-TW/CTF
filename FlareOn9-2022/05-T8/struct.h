typedef struct wstring_t {
    union {
        char *ptr;
        char arr[16];
    } content; // 0
    _DWORD size; // 16
    _DWORD capacity; // 20
} wstring_t;

/*
vtable:
.rdata:0044B918 ; const CClientSock::`vftable'
.rdata:0044B918 ??_7CClientSock@@6B@ dd offset sub_4035F0
.rdata:0044B918                                         ; DATA XREF: t8_client_t_constructor+3D↑o
.rdata:0044B918                                         ; sub_4035F0+9↑o
.rdata:0044B91C                 dd offset t8_client_setmethod_403770
.rdata:0044B920                 dd offset t8_client_sethash_4037a0
.rdata:0044B924                 dd offset sub_403C20
.rdata:0044B928                 dd offset sub_403CE0
.rdata:0044B92C                 dd offset sub_4036D0
.rdata:0044B930                 dd offset sub_403860
.rdata:0044B934                 dd offset sub_403D70
.rdata:0044B938                 dd offset sub_404200
.rdata:0044B93C                 dd offset sub_4043F0
.rdata:0044B940                 dd offset t8_client_maybe_md5_hash_403910
*/

struct t8_client_vtable;

// size: 76
typedef struct t8_client_t {
    struct t8_client_vtable *vtable; // 0
    _WORD httpMethod[8]; // 4
    wstring_t servername; // 20
    wstring_t hash; // 44
    char *content; // 68
    _DWORD datalen; // 72
} __attribute__ ((packed)) t8_client_t;

typedef struct t8_client_vtable {
    void *method1;
    void *t8_client_setmethod_403770;
    void *(*t8_client_sethash_4037a0)(t8_client_t *this, wstring_t *wstr);
    void *t8_client_b64encode_403c20;
    void *t8_client_b64decode_403ce0;
    void *t8_client_method2_4036d0;
    int (__thiscall *t8_client_encrypt_with_hash_403860)(t8_client_t *, wstring_t, _WORD *, LPDWORD);
    void (__thiscall *t8_client_stage1_403d70)(t8_client_t *, wstring_t, char);
    void *t8_client_stage2_404200;
    void *t8_client_some_decode_4043f0;
    void *t8_client_md5_hash_403910;
    void *t8_client_method8;    
} t8_client_vtable;

typedef struct t8_instance_t {
    wstring_t wstr;
    _DWORD size; // 24
    t8_client_t *some_instance;
} t8_instance_t;

typedef struct crypt_context {
    char buf[256];
    int a;
    int b;
    int c;
} crypt_context;
