# 3dfx_glide_sourceforge
Glide for 3dfx - Forked from Glide sourceforge project, development branch

## Tools needed to build:
(what I used)
- Ms Windows Xp sp3 (in virtual machine)
- Ms Visual cpp 6.0 (pro)
- Ms Windows XP DDK (5.1.2600)
- Ms DirectX 9 SDK
- NASM 0.98.38
- GNU make 3.81
  
## Build instructions
make -f Makefile.win32 realclean \
make -f Makefile.win32 FX_GLIDE_HW=h5 H4=1 USE_X86=1 USE_3DNOW=1 USE_MMX=1 USE_SSE=1 USE_SSE2=1 TEXUS2=1

### Additional versions information \
make - GNU Make 3.81 \
nasm - NASM version 0.98.38 compiled on Sep 12 2003

### Copy of my current path
echo %path% \
C:\NASM;C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\DXSDK9.0\Bin\DXUtils;C:\Program Files\GnuWin32\bin;C:
\WINDDK\2600\bin\x86;C:\Program Files\Microsoft Visual Studio\Common\Tools\WinNT;C:\Program Files\Microsoft Visual Studi
o\Common\MSDev98\Bin;C:\Program Files\Microsoft Visual Studio\Common\Tools;C:\Program Files\Microsoft Visual Studio\VC98
\bin;C:\Program Files\Microsoft SDK_03\Bin\.;C:\Program Files\Microsoft SDK_03\Bin\WinNT\.
