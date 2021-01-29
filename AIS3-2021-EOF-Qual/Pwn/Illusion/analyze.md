* Program Header, PT_DYNAMIC
  * ![image-20210109172142143](C:\Users\LJP\AppData\Roaming\Typora\typora-user-images\image-20210109172142143.png)

  * VA: 0x4df8
  * File Offset: 0x3df8

* PT_DYNAMIC Segment

  * ![image-20210109172708678](C:\Users\LJP\AppData\Roaming\Typora\typora-user-images\image-20210109172708678.png)

    * ```c
      typedef struct {
              Elf64_Xword d_tag;
              union {
                      Elf64_Xword     d_val;
                      Elf64_Addr      d_ptr;
              } d_un;
      } Elf64_Dyn;
      ```

    * DT_STRTAB

      * d_tag: 5
      * d_ptr: 0x04a0
      * ![image-20210109172937258](C:\Users\LJP\AppData\Roaming\Typora\typora-user-images\image-20210109172937258.png)
      * strtab[0x10]: puts
      * strtab[0x32]: printf

    * DT_SYMTAB

      * d_tag: 6
      * d_ptr: 0x0338
      * ![image-20210109173006453](C:\Users\LJP\AppData\Roaming\Typora\typora-user-images\image-20210109173006453.png)
      * symtab[3] (0x380): puts symbol
      * symtab[5] (0x3b0): printf symbol

    * DT_JMPREL

      * d_tag: 0x17
      * d_ptr: 0x700
      * ![image-20210109173028189](C:\Users\LJP\AppData\Roaming\Typora\typora-user-images\image-20210109173028189.png)
      * jmprel[2] (0x718): puts jmprel
      * jmprel[4] (0x748): printf jmprel

