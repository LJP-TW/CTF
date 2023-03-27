typedef struct gamestate_t {
	char quit; // 0
	char padding1[7]; // 1
	void *p_render; // 8
	char padding2[80]; // 12
	char buf1[0x10]; // 92
	char padding3[12]; // 108
	void *p_texture; // 120
	char padding4[20]; // 124
	_DWORD num1; // 144
	_DWORD num2; // 148
	_DWORD num3; // 150
	_DWORD num4; // 156
	char padding5[88]; // 160
	char *content; // 248
	char padding6[12]; // 252
	_DWORD left_space; // 264
	_DWORD cnt2; // 268
	char buf2[72]; // 272
	_WORD ret; // 344
	char padding7[2]; // 346
	_DWORD num5; // 348
	_DWORD num6; // 352
	char up; // 356
	char down; // 357
	char left; // 358
	char right; // 359
} gamestate_t;