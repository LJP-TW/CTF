int __cdecl main(int a1)
{
  size_t v1; // eax@1
  void *v2; // esp@1
  size_t v3; // eax@1
  void *v4; // esp@1
  int v6; // [sp-4h] [bp-94h]@1
  char buf; // [sp+0h] [bp-90h]@1
  char *dest; // [sp+64h] [bp-2Ch]@1
  size_t v9; // [sp+68h] [bp-28h]@1
  void *s; // [sp+6Ch] [bp-24h]@1
  size_t v11; // [sp+70h] [bp-20h]@1
  size_t nbytes; // [sp+74h] [bp-1Ch]@1
  int *v13; // [sp+84h] [bp-Ch]@1

  v13 = &a1;
  nbytes = 0;
  memset(&buf, 0, 0x64u);
  read(0, &buf, 0x64u);
  v1 = strlen(&buf); // 0x60
  v11 = v1 - 1;
  v2 = alloca(0x10 * ((v1 + 0xf) / 0x10)); // sub esp, eax // 0x60
  s = &v6;
  nbytes = strlen(&buf); //  0x60
  memset(s, 0, (unsigned __int8)(nbytes & 0xF8) + 8); // 0x68
  read(0, s, nbytes); // 0x60
  v3 = strlen((const char *)s); // 0x60
  v9 = v3 - 1;
  v4 = alloca(0x10 * ((v3 + 0xf) / 0x10)); // sub esp, eax // 0x60
  dest = (char *)&v6;
  strcpy((char *)&v6, (const char *)s);
  strcpy((char *)s, &buf);
  strcpy(&buf, dest);
  return 0;
}