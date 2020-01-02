static u32 hxp2019__check__h578f31d490e10a31(u32 p0, u32 p1) {
  u32 l2 = 0, l3 = 0, endPos = 0, holder = 0, inputByte = 0, l7 = 0, l8 = 0, l9 = 0, 
      l10 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2;
  i0 = g0;
  i1 = 32u;
  i0 -= i1;
  l2 = i0;
  g0 = i0;
  i0 = 0u;
  l3 = i0;
  
  // if (p1 != 50) {got EXIT;}
  i0 = p1;
  i1 = 50u;
  i0 = i0 != i1;
  if (i0) {goto EXIT;}
  
  i0 = l2;
  i1 = 50u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 0u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 4u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  
  
  i0 = p0;
  i0 = i32_load8_s((&memory), (u64)(i0 + 4));
  i1 = 4294967231u; // 0xffffffbf, -65
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B2;}
  
  
  i0 = p0;
  i1 = 1049664u;
  i0 = i0 == i1;
  if (i0) {goto B1;}
  
  
  i0 = 0u;
  l3 = i0;
  i0 = p0;
  i0 = i32_load((&memory), (u64)(i0));
  i1 = 2070968424u; // '{pxh'
  i0 = i0 == i1;
  if (i0) {goto B1;}
  goto EXIT;
  
  // B2 -------------------------------------------------------------------------------------------------------------------------------
  B2:;
  i0 = l2;
  i1 = l2;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l2;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  core__str__traits___impl_core__slice__SliceIndex_str__for_core__ops__range__Range_usize____index____closure____h81e1d06525c0564b(i0);
  UNREACHABLE;
  
  // B1 -------------------------------------------------------------------------------------------------------------------------------
  B1:;
  i0 = l2;
  i1 = 50u;
  i32_store((&memory), (u64)(i0 + 4), i1);
  i0 = l2;
  i1 = p0;
  i32_store((&memory), (u64)(i0), i1);
  i0 = l2;
  i1 = 49u;
  i32_store((&memory), (u64)(i0 + 8), i1);
  i0 = l2;
  i1 = 50u;
  i32_store((&memory), (u64)(i0 + 12), i1);
  i0 = p0;
  i0 = i32_load8_s((&memory), (u64)(i0 + 49)); // Get last char '}'
  p1 = i0;
  i1 = 4294967231u; // 0xffffffbf, -65
  i0 = (u32)((s32)i0 <= (s32)i1);
  if (i0) {goto B3;}
  
  // endPos = p0 + 49
  i0 = p0;
  i1 = 49u;
  i0 += i1;
  endPos = i0;
  
  i1 = 1049668u; // 1049664: hxp{}e_seem/agibtrn/ewmsu_rdrxtr_wbe_hkm.oaeyirncm
  i0 = i0 == i1;
  if (i0) {goto B4;}
  i0 = 0u;
  l3 = i0;
  i0 = p1;
  i1 = 125u; // '}'
  i0 = i0 != i1;
  if (i0) {goto EXIT;}
  
  // B4 -------------------------------------------------------------------------------------------------------------------------------
  B4:;
  i0 = p0;
  i1 = 4u; // Ignore '{pxh'
  i0 += i1;
  p0 = i0;
  i0 = 0u;
  p1 = i0;
  i0 = 1u;
  l3 = i0;
  
  // L7 -------------------------------------------------------------------------------------------------------------------------------
  L7:
    // if (i1 == endPos) {goto EXIT;}
    i0 = endPos;
    i1 = p0;
    i0 = i0 == i1;
    if (i0) {goto EXIT;}
    
    // holder = p0 + 1;
    i0 = p0;
    i1 = 1u;
    i0 += i1;
    holder = i0;
    
    // inputByte = memory[p0]
    i0 = p0;
    i0 = i32_load8_s((&memory), (u64)(i0));
    inputByte = i0;
    
    // if (inputByte > -1) {goto B9;}
    i1 = 4294967295u; // 0xffffffff
    i0 = (u32)((s32)i0 > (s32)i1);
    if (i0) {goto B9;}
    
    i0 = holder;
    i1 = endPos;
    i0 = i0 != i1;
    if (i0) {goto B11;}
    i0 = 0u;
    l7 = i0;
    i0 = endPos;
    l8 = i0;
    goto B10;
    B11:;
    i0 = p0;
    i0 = i32_load8_u((&memory), (u64)(i0 + 1));
    i1 = 63u;
    i0 &= i1;
    l7 = i0;
    i0 = p0;
    i1 = 2u;
    i0 += i1;
    holder = i0;
    l8 = i0;
    
    // B10 -------------------------------------------------------------------------------------------------------------------------------
    B10:;
    i0 = inputByte;
    i1 = 31u;
    i0 &= i1;
    l9 = i0;
    
    // if (inputByte > 223)
    i0 = inputByte;
    i1 = 255u;
    i0 &= i1;
    inputByte = i0;
    i1 = 223u;
    i0 = i0 > i1; 
    if (i0) {goto B12;} 
        
    i0 = l7;
    i1 = l9;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    inputByte = i0;
    goto B8;
    B12:;
    i0 = l8;
    i1 = endPos;
    i0 = i0 != i1;
    if (i0) {goto B14;}
    i0 = 0u;
    l10 = i0;
    i0 = endPos;
    l8 = i0;
    goto B13;
    B14:;
    i0 = l8;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    l10 = i0;
    i0 = l8;
    i1 = 1u;
    i0 += i1;
    holder = i0;
    l8 = i0;
    B13:;
    i0 = l10;
    i1 = l7;
    i2 = 6u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    l7 = i0;
    i0 = inputByte;
    i1 = 240u;
    i0 = i0 >= i1;
    if (i0) {goto B15;}
    i0 = l7;
    i1 = l9;
    i2 = 12u;
    i1 <<= (i2 & 31);
    i0 |= i1;
    inputByte = i0;
    goto B8;
    B15:;
    i0 = l8;
    i1 = endPos;
    i0 = i0 != i1;
    if (i0) {goto B17;}
    i0 = 0u;
    inputByte = i0;
    goto B16;
    B17:;
    i0 = l8;
    i1 = 1u;
    i0 += i1;
    holder = i0;
    i0 = l8;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = 63u;
    i0 &= i1;
    inputByte = i0;
    B16:;
    i0 = l7;
    i1 = 6u;
    i0 <<= (i1 & 31);
    i1 = l9;
    i2 = 18u;
    i1 <<= (i2 & 31);
    i2 = 1835008u;
    i1 &= i2;
    i0 |= i1;
    i1 = inputByte;
    i0 |= i1;
    inputByte = i0;
    i1 = 1114112u;
    i0 = i0 == i1;
    if (i0) {goto EXIT;}
    goto B8;
    
    // B9 -------------------------------------------------------------------------------------------------------------------------------
    B9:;
    // i0 = inputByte; i1 = 255
    i0 = inputByte;
    i1 = 255u;
    i0 &= i1;
    inputByte = i0;
    
    // B8 -------------------------------------------------------------------------------------------------------------------------------
    B8:;
    // if (length > 44) {goto GG;}
    i0 = p1;
    i1 = 44u;
    i0 = i0 > i1;
    if (i0) {goto GG;}
    
    // i0 = p1; i0 <<= 2
    i0 = p1;
    i1 = 2u;
    i0 <<= (i1 & 31);
    
    // i0 += 1049716
    i1 = 1049716u;
    i0 += i1;
    
    // i0 = memory[i0]
    i0 = i32_load((&memory), (u64)(i0));
    
    // i1 = p1 * 1337
    i1 = p1;
    i2 = 1337u;
    i1 *= i2;
    
    // l8 = i0 ^= i1
    i0 ^= i1;
    l8 = i0;
    
    // if (i0 > 44) {goto GG2;}
    i1 = 44u;
    i0 = i0 > i1;
    if (i0) {goto GG2;}
    
    // Update index (p1)
    i0 = p1;
    i1 = p0;
    i0 -= i1;
    i1 = holder;
    i0 += i1;
    p1 = i0;
    
    // Update startPos (p0)
    i0 = holder;
    p0 = i0;
    
    i0 = l8;
    i1 = 1049669u; // 1049669: 'e_seem/agibtrn/ewmsu_rdrxtr_wbe_hkm.oaeyirncm'
    i0 += i1;
    i0 = i32_load8_u((&memory), (u64)(i0));
    i1 = inputByte;
    i2 = 255u;
    i1 &= i2;
    i0 = i0 == i1;
    if (i0) {goto L7;}
  i0 = 0u;
  l3 = i0;
  goto EXIT;
  GG:;
  i0 = 1049908u;
  i1 = p1;
  i2 = 45u;
  core__panicking__panic_bounds_check__h1fae5a314994f748(i0, i1, i2);
  UNREACHABLE;
  GG2:;
  i0 = 1049924u;
  i1 = l8;
  i2 = 45u;
  core__panicking__panic_bounds_check__h1fae5a314994f748(i0, i1, i2);
  UNREACHABLE;
  B3:;
  i0 = l2;
  i1 = l2;
  i2 = 12u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 24), i1);
  i0 = l2;
  i1 = l2;
  i2 = 8u;
  i1 += i2;
  i32_store((&memory), (u64)(i0 + 20), i1);
  i0 = l2;
  i1 = l2;
  i32_store((&memory), (u64)(i0 + 16), i1);
  i0 = l2;
  i1 = 16u;
  i0 += i1;
  core__str__traits___impl_core__slice__SliceIndex_str__for_core__ops__range__Range_usize____index____closure____h81e1d06525c0564b(i0);
  UNREACHABLE;
  EXIT:;
  i0 = l2;
  i1 = 32u;
  i0 += i1;
  g0 = i0;
  i0 = l3;
  FUNC_EPILOGUE;
  return i0;
}