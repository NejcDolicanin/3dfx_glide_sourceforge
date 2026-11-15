#!/bin/bash
# Build the user's Glide h5 (3dfx_glide_sourceforge, develop) on this box with VC6 under Wine, the way the README's
# `make -f Makefile.win32 FX_GLIDE_HW=h5 USE_X86=1 USE_3DNOW=1 USE_MMX=1 USE_SSE=1 USE_SSE2=1 TEXUS2=1` does, without
# make / nasm: every C source of glide3/src and minihwc is compiled into $OUT with the Makefile's release flags (+ the
# DX9 SDK first and WINVER=0x0500 for winsurf.c); the nasm objects (xdraw2/xdraw3/xtexdl variants), the texus2
# objects and glide.res are reused from the tree; the link line is the Makefile's.  Output: $OUT/glide3x.dll.
set -e
export WINEPREFIX=/home/nejc/work_utility/wineprefix-vc6
export WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree,mshtml="
W=/mnt/4c4334e3-42c1-428b-934d-dae5f30fc6ce/Retro/DriverDevelopment/_work
DEV=$W/Devtools
VC98=$DEV/msvc6_0/VC98
DX=$DEV/IzWin10/DXSDK9.0
R=$W/3dfx_glide_sourceforge/glide3x
SRC=$R/h5/glide3/src
OUT=${OUT:-$(dirname "$0")/gbuild}
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
w() { winepath -w "$1"; }
export WINEPATH="$(w "$VC98/Bin")"
export INCLUDE="$(w "$DX/Include");$(w "$VC98/Include")"
export LIB="$(w "$DX/Lib");$(w "$VC98/Lib")"
CDEFS="-D__WIN32__ -DFX_DLL_ENABLE -DHWC_ACCESS_DDRAW=1 -DHWC_EXT_INIT=1 -DGLIDE_ALT_TAB=1 -DHWC_MINIVDD_HACK=1 -DWIN40COMPAT=1 -DWINXP_ALT_TAB_FIX=1 -DWINXP_SAFER_ALT_TAB_FIX=1 -DNEED_MSGFILE_ASSIGN -DGLIDE3 -DGLIDE3_ALPHA -DGLIDE_HW_TRI_SETUP=1 -DGLIDE_INIT_HWC -DGLIDE_PACKED_RGB=0 -DGLIDE_PACKET3_TRI_SETUP=1 -DGLIDE_TRI_CULLING=1 -DUSE_PACKET_FIFO=1 -DGLIDE_CHECK_CONTEXT -DH3 -DFX_GLIDE_H5_CSIM=1 -DFX_GLIDE_NAPALM=1 -DGLIDE_PLUG -DGLIDE_SPLASH -DHAVE_TEXUS2"
CFLAGS="-nologo -W3 -WX -D__MSC__=1 -DNDEBUG -MT -G6 -O2 -I. -I../../incsrc -I../../minihwc -I../../../swlibs/fxmisc -I../../../swlibs/newpci/pcilib -I../../../swlibs/fxmemmap -I../../../swlibs/texus2/lib $CDEFS -DGL_AMD3D -DGL_MMX -DGL_SSE -DGL_SSE2 -DGL_X86 -DFX_C_TRISETUP_SHIM -DWINVER=0x0500"
SOURCES="fifo distate gstrip distrip diget gsplash g3df gu gpci diglide disst ditex gsfc gbanner gerror gaa gdraw gglide glfb gsst gtex gtexdl gamefix xtexdl_def cpuid gxdraw gthread winsurf"
cd "$SRC"
for s in $SOURCES; do
  [ -n "$ONLY" ] && ! [[ " $ONLY " == *" $s "* ]] && continue
  echo "== $s.c"
  wine "$VC98/Bin/CL.EXE" $CFLAGS -c -Fo"$(w "$OUT")\\$s.obj" $s.c
done
# minihwc: compiled the same way (the Makefile builds ../../minihwc/*.obj with these CFLAGS from glide3/src)
MINIHWC="hwcio gdebug minihwc win_mode"
for s in $MINIHWC; do
  [ -n "$ONLY" ] && ! [[ " $ONLY " == *" $s "* ]] && continue
  echo "== minihwc/$s.c"
  INCLUDE="$INCLUDE;$(w "$DEV/win98ddk/inc/win98")" \
    wine "$DEV/msvc6_4.pak/vc98/Bin/CL.EXE" $CFLAGS -c -Fo"$(w "$OUT")\\hwc_$s.obj" ../../minihwc/$s.c   # Win98 DDK headers; the
                                         # processor-pack compiler (minihwc.c's dither loop uses pminsw)
done
OBJS=""
for s in $SOURCES; do OBJS="$OBJS $(w "$OUT/$s.obj")"; done
for s in xdraw2_def xdraw3_def xdraw2_3dnow xdraw3_3dnow xtexdl_3dnow xtexdl_mmx xdraw2_sse xdraw3_sse xtexdl_sse2; do OBJS="$OBJS $(w "$SRC/$s.obj")"; done
for s in $MINIHWC; do OBJS="$OBJS $(w "$OUT/hwc_$s.obj")"; done
for f in "$R"/swlibs/texus2/lib/*.obj; do OBJS="$OBJS $(w "$f")"; done
cd "$OUT"
echo "== link"
wine "$VC98/Bin/LINK.EXE" -out:glide3x.dll -nologo -dll -opt:WIN98 -machine:IX86 -nodefaultlib $OBJS user32.lib kernel32.lib ddraw.lib gdi32.lib dxguid.lib advapi32.lib LIBCMT.lib "$(w "$SRC/glide.res")"
ls -la --time-style=+%F_%H:%M "$OUT/glide3x.dll"
