# The Jumps
Checksec: SMAP, SMEP, KPTI, nokaslr
### Bug:
```c
unsigned __int64 __fastcall proc_write(__int64 a1, __int64 a2, unsigned __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  char input[32]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v9; // [rsp+20h] [rbp-10h]

  v9 = __readgsqword(0x28u);
  memset(input, 0, sizeof(input));
  if ( a3 > 0x3FF )
    return proc_write_cold(a1, a2, a3, a4, a5, a6);
  if ( (unsigned int)copy_from_user(
                       proc_data,
                       a2,
                       a3 - 1,
                       a4,
                       a5,
                       a6,
                       *(_QWORD *)input,
                       *(_QWORD *)&input[8],
                       *(_QWORD *)&input[16],
                       *(_QWORD *)&input[24],
                       v9) )
    return -14LL;
  _memcpy(input, proc_data, a3);
  proc_data[a3] = 0;
  return a3;
}
```
-> `a3 <= 0x3FF` -> `_memcpy(input[32], proc_data, 0x3FF);` -> BOF
```c
__int64 __fastcall proc_read(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  __int64 result; // rax
  _QWORD v5[7]; // [rsp+0h] [rbp-38h] BYREF

  v5[4] = __readgsqword(0x28u);
  if ( a3 > 0x400 )
    return proc_read_cold();
  _memcpy(proc_data, v5, a3);
  LODWORD(result) = copy_to_user(a2, proc_data, a3);
  if ( !(_DWORD)result )
    LODWORD(result) = a3;
  return (int)result;
}
```
-> Data leak
