/*
** gamefix.c -- per-game runtime binary patches, driver-side.
**
** See gamefix.h for the boundary and GlideXp/GLIDE2X/GAME-PATCHING.md for the
** method.  No Glide internals here: <windows.h> and the C runtime only, so
** this file stays interchangeable with the wrapper's copy.
**
** Why a game needs patching at all
** --------------------------------
** Glide is a screen-space API.  The game does its own projection and its own
** 2D layout against whatever resolution it BELIEVES it has, so forcing a
** bigger framebuffer behind its back just draws the old image into a corner.
** Three independent things must all be true, and they fail in ways that look
** alike on screen:
**
**   1. the mode must EXIST          -> the driver (FX_GLIDE_OVERRIDE_RESOLUTION)
**   2. the game must ASK for it     -> its own settings, or a patch to them
**   3. the projection/layout must   -> a patch to the game image
**      be right for the new aspect
**
** Nothing on disk is modified.  Patching a game's files statically works and
** is a fine way to PROVE a theory, but shipping it means shipping modified
** game files.
**
** Timing
** ------
** DLL_PROCESS_ATTACH is too early: games pull their renderer and their module
** set in with LoadLibrary, and on Win9x GetModuleHandleA still returns NULL
** while such a load is in progress.  grGlideInit is the reliable first hook --
** a Glide game's video layer calls it before it does anything with the screen.
** grSstWinOpen is the second, by which point the driver has decided whether
** the override actually applies.  grBufferSwap is the third, for modules that
** only arrive later.  Everything here is idempotent, so all three cost nothing
** once the work is done.
*/

#include <windows.h>
#include <stdarg.h>
#include <string.h>

#include "gamefix.h"

/* The configuration file, read from beside the host exe.  Same name the
   wrapper uses, so one file configures both halves of a mixed install. */
#define GAMEFIX_INI "wideDriver.ini"
#define GAMEFIX_LOG "g3fix.txt"

/*
** A single patch.  `find` and `replace` are the same length by construction;
** nothing here resizes or relocates anything, so no branch target moves and no
** code cave is needed.  Idempotency comes free: if the `find` bytes are gone
** the patch is skipped.
**
** `relocs` handles a pattern that quotes an absolute address -- `mov
** ds:0x6fba7034,eax` and friends.  A DLL with a .reloc section can be loaded
** somewhere other than its preferred base, and then every such address in its
** code differs from the one written here by a constant, so the pattern misses
** and the fix silently does nothing.  Diablo II is exactly this case: five of
** its nine patterns quote a global.
**
** So: a NULL-or-0xFF-terminated list of byte offsets, each naming the start of
** a 4-byte absolute address inside `find`/`replace`.  ApplyProfile reads the
** module's original ImageBase back out of its own PE header (still there in
** memory), works out the delta, and biases those four bytes before searching.
** Offsets are bytes, so a pattern must stay under 255 long -- they all are,
** and a longer one would be a signature that had stopped being a signature.
*/
#define RELOC_END 0xFFu

typedef struct {
    const char          *name;
    const unsigned char *find;
    const unsigned char *replace;
    unsigned int         length;
    const unsigned char *relocs;
} BytePatch;

/*
** A game profile.  `exeName` is matched against the tail of the host process's
** own module path, so a profile can say "Game.exe" and still match whatever
** absolute path the process was launched from.  `moduleName` is the module
** actually carrying the code to patch, which is frequently not the exe at all;
** NULL means the host's own main image.
*/
typedef struct {
    const char        *exeName;
    const char        *moduleName;
    const BytePatch   *patches;
    unsigned int       patchCount;
    /*
    ** NULL, or a flag that must be non-zero for this profile to be applied.
    ** Exists so a group of patches can be turned off from wideDriver.ini and a
    ** failure bisected without a rebuild -- which on this target means a build
    ** in a VM and a trip to the Win98 box per guess.  A profile that is off is
    ** logged as such, so an inert run is never mistaken for one that did not
    ** happen.
    */
    const int         *enable;
} GameProfile;

/*
** Target resolution -- taken from the driver, never hardcoded.
**
** 640x480 is the default because it makes every fix inert, and because
** GameFix_Apply refuses to run at all until a real override has been adopted.
** With the override disabled the game is left completely alone: it is running
** at a mode it was designed for and there is nothing to fix.
*/
static unsigned int g_targetW   = 640;
static unsigned int g_targetH   = 480;
static unsigned int g_targetRes = 0;      /* Glide enum; 0 = no override */

/*
** Retry bookkeeping.
**
** A game's modules do not all arrive at once.  Diablo II is the clean example:
** Game.exe statically imports D2gfx.dll, which loads D2Glide.dll, which calls
** grGlideInit -- so those two are mapped by the time we first run.  But
** D2Client.dll is not imported by anything; it is pulled in dynamically much
** later, and it is the module carrying the live screen size.  A frame budget
** would be a guess about how long the main menu lasts, and the wrong guess
** silently leaves the fix half-applied.
**
** So: a bitmask of profiles already done, and a per-frame probe that is one
** GetModuleHandleA call per outstanding profile.  The expensive pattern scan
** runs once, when the module actually appears.
*/
static int          g_matched     = 0;
static unsigned int g_profileDone = 0;    /* bit per profile */
static int          g_pending     = 0;    /* some matched profile still absent */
static unsigned int g_applyRuns   = 0;

/*
** The host exe path, resolved once.
**
** It cannot change for the life of the process, and the per-frame retry probe
** needs it -- but GetModuleFileNameA is a loader call, and calling one from
** inside grBufferSwap on every swap, in a fullscreen Glide context on Win9x,
** is asking for trouble.  Resolved on the first GameFix_Apply, which runs from
** grGlideInit where a loader call is unremarkable.
*/
static char         g_exePath[MAX_PATH];
static int          g_exeKnown    = 0;

/*
** Master switch, so there is a true "driver only" control run: the override
** still forces the mode, but gamefix touches nothing.  Off via
**   [GameFix] enable=0   in wideDriver.ini, or FX_GLIDE_GAMEFIX=0.
** Separating "the values are wrong" from "this code should not be running
** here" otherwise costs a rebuild, and a rebuild here means a VM and a trip to
** the Win98 box.
*/
static int          g_enabled     = -1;   /* -1 = not yet decided */


/* ======================================================================== */
/* Shared machinery                                                         */
/* ======================================================================== */

/* Little-endian store, so byte tables stay readable as x86. */
static void PutU32(unsigned char *at, unsigned int v)
{
    at[0] = (unsigned char)(v      );
    at[1] = (unsigned char)(v >>  8);
    at[2] = (unsigned char)(v >> 16);
    at[3] = (unsigned char)(v >> 24);
}

static unsigned int ReadU32(const unsigned char *at)
{
    return (unsigned int)at[0]
         | ((unsigned int)at[1] <<  8)
         | ((unsigned int)at[2] << 16)
         | ((unsigned int)at[3] << 24);
}

/* The raw bits of a float, so it can be written as an x86 immediate. */
static unsigned int FloatBits(float f)
{
    union { float f; unsigned int u; } c;
    c.f = f;
    return c.u;
}

/* Emit `movl $imm,ds:addr` -- the ten-byte absolute-store form. */
static void PutMovAbsImm(unsigned char *at, unsigned int addr, unsigned int imm)
{
    at[0] = 0xc7;
    at[1] = 0x05;
    PutU32(at + 2, addr);
    PutU32(at + 6, imm);
}

/*
** Case-insensitive tail comparison: does `path` end in `name`?
** Deliberately ASCII-only and locale-independent.
*/
static BOOL PathEndsWith(const char *path, const char *name)
{
    size_t      lp, ln;
    const char *tail;

    if (!path || !name) return FALSE;

    lp = strlen(path);
    ln = strlen(name);
    if (ln > lp) return FALSE;

    tail = path + (lp - ln);
    while (*tail) {
        char a = *tail++;
        char b = *name++;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return FALSE;
    }
    return TRUE;
}

/*
** Build a path to a file sitting next to the host exe -- not the current
** directory, which the game may well have changed by the time we run.
*/
static BOOL PathBesideExe(const char *leaf, char *out)
{
    char *slash, *p;

    out[0] = '\0';
    if (GetModuleFileNameA(NULL, out, MAX_PATH) == 0) return FALSE;

    slash = out;
    for (p = out; *p; p++)
        if (*p == '\\' || *p == '/') slash = p + 1;

    if ((size_t)(slash - out) + (size_t)lstrlenA(leaf) + 1 >= (size_t)MAX_PATH)
        return FALSE;
    lstrcpyA(slash, leaf);
    return TRUE;
}

/*
** Locate a module's executable code range from its PE headers.
**
** Scanning only the code section keeps the search small and, more importantly,
** keeps it off the import and data sections where a byte sequence could
** coincide without ever being an instruction.  Returns nothing rather than
** guessing.
*/
static BOOL GetCodeRange(HMODULE mod, unsigned char **base, unsigned int *size)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)mod;
    const IMAGE_NT_HEADERS *nt;

    if (!mod) return FALSE;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    nt = (const IMAGE_NT_HEADERS *)((const unsigned char *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    if (!nt->OptionalHeader.BaseOfCode || !nt->OptionalHeader.SizeOfCode)
        return FALSE;

    *base = (unsigned char *)mod + nt->OptionalHeader.BaseOfCode;
    *size = (unsigned int)nt->OptionalHeader.SizeOfCode;
    return TRUE;
}

/*
** Locate a named section, clamped to its INITIALISED part.
**
** Needed because some patch targets are data, not code, and GetCodeRange
** deliberately cannot see them.  The clamp is the point: a section's
** VirtualSize covers its BSS tail, and that tail can be enormous.  Scanning
** the virtual extent would fault every one of those pages in for nothing, and
** only the raw part can contain a pattern that was in the file.
**
** Note objdump -h prints SizeOfRawData, not VirtualSize -- a section can read
** as 0x33000 in a dump and really be 14 MB, nearly all BSS.  Scan the raw
** part, address the virtual part.
*/
static BOOL GetSectionRange(HMODULE mod, const char *name,
                            unsigned char **base, unsigned int *size)
{
    const IMAGE_DOS_HEADER     *dos = (const IMAGE_DOS_HEADER *)mod;
    const IMAGE_NT_HEADERS     *nt;
    const IMAGE_SECTION_HEADER *sec;
    unsigned int i, n;

    if (!mod) return FALSE;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    nt = (const IMAGE_NT_HEADERS *)((const unsigned char *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    sec = IMAGE_FIRST_SECTION(nt);
    n   = nt->FileHeader.NumberOfSections;

    for (i = 0; i < n; i++) {
        unsigned int len;
        char         nm[9];

        memcpy(nm, sec[i].Name, 8);
        nm[8] = '\0';
        if (lstrcmpiA(nm, name) != 0) continue;

        len = sec[i].SizeOfRawData;
        if (sec[i].Misc.VirtualSize && sec[i].Misc.VirtualSize < len)
            len = sec[i].Misc.VirtualSize;
        if (!len) return FALSE;

        *base = (unsigned char *)mod + sec[i].VirtualAddress;
        *size = len;
        return TRUE;
    }
    return FALSE;
}

/*
** How many times does `pattern` occur?  Used by the status log to separate
** "already patched" (0) from "ambiguous" (>1), which look identical from the
** outside and mean opposite things.
*/
static unsigned int CountPattern(const unsigned char *base, unsigned int size,
                                 const unsigned char *pattern, unsigned int len)
{
    unsigned int i, hits = 0;

    if (len == 0 || len > size) return 0;

    for (i = 0; i <= size - len; i++)
        if (base[i] == pattern[0] && memcmp(base + i, pattern, len) == 0)
            hits++;

    return hits;
}

/*
** Find `pattern` in [base, base+size).  Requires exactly one match.
**
** Insisting on uniqueness is the point.  A pattern that has become ambiguous
** in some other build of the target is a pattern we no longer understand, and
** patching the first of several candidates would be a guess.  Not patching is
** the safe answer.  Verify with a count, never by eye -- short signatures
** bite, and a byte scan will happily match an instruction interior.
*/
static unsigned char *FindUnique(unsigned char *base, unsigned int size,
                                 const unsigned char *pattern, unsigned int len)
{
    unsigned char *hit = NULL;
    unsigned int   i;

    if (len == 0 || len > size) return NULL;

    for (i = 0; i <= size - len; i++) {
        if (base[i] == pattern[0] && memcmp(base + i, pattern, len) == 0) {
            if (hit) return NULL;          /* ambiguous -- refuse */
            hit = base + i;
        }
    }
    return hit;
}

/*
** Write over read-execute image pages.
**
** Win9x honours VirtualProtect on mapped image sections and the pages are
** copy-on-write, so this affects only our process.  The old protection is put
** back rather than left writable: leaving a game's code section RWX for the
** rest of the run would be a gratuitous change to its memory hygiene.
*/
static BOOL WriteCode(unsigned char *at, const unsigned char *bytes,
                      unsigned int len)
{
    DWORD oldProtect = 0;

    if (!VirtualProtect(at, len, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy(at, bytes, len);

    VirtualProtect(at, len, oldProtect, &oldProtect);

    /* Harmless on the single-core boxes this targets, but correct on anything
       that caches decoded instructions. */
    FlushInstructionCache(GetCurrentProcess(), at, len);
    return TRUE;
}


/* ======================================================================== */
/* Status log                                                               */
/* ======================================================================== */
/*
** GAME-PATCHING.md section 6: write a status log before you write a theory.
**
** "Nothing happens" on hardware is consistent with three unrelated failures --
** gamefix never ran, ran and matched nothing, or patched correctly and the
** screen size is driven from somewhere else -- and each guess costs a full
** round trip.  The log has to cover both halves to separate them:
**
**   - what we DID, at patch time: the exe path matched, the resolution
**     adopted, and a per-patch hit count sampled BEFORE the patches consume
**     their own find bytes;
**   - what the game then BELIEVED, sampled per frame and logged on change and
**     periodically, never only on change.
**
** Buffered in memory and rewritten whole, because a file write per frame
** perturbs exactly the timing being measured.  wvsprintfA is used rather than
** the CRT because it is small, always present on Win9x and cannot pull in
** locale machinery; it has no float conversion, so print fixed point.
*/

/*
** 32K was not enough once the trace could re-arm: 94 sites x 3 samples, plus
** a backtrace line each, fills it in about three seconds -- so a panel opened
** after that was recorded nowhere and the log merely looked uneventful.
**
** The reserve exists because the LOG FULL notice itself needs room.  At 32K
** the buffer stopped five bytes short of the cap, the notice did not fit, and
** a truncated log read as a complete one.  A diagnostic that can fail to say
** it stopped is worse than one that stops.
*/
#define GAMEFIX_LOG_CAP    (192u * 1024u)
#define GAMEFIX_LOG_NOTICE 24u          /* always kept free for the notice */

static char         g_logBuf[GAMEFIX_LOG_CAP];
static unsigned int g_logLen   = 0;
static int          g_logOn    = -1;    /* -1 = not yet decided */
static int          g_logDirty = 0;
static int          g_logFull  = 0;

/*
** Set while executing inside grBufferSwap, and it suppresses the flush.
**
** THIS IS NOT A TUNING KNOB.  Writing a file from inside grBufferSwap froze
** the machine hard on Win98: a fullscreen Glide app is holding the display
** exclusively, and CreateFile/WriteFile there goes down the 16-bit filesystem
** thunk and takes the Win16Mutex.  It cost several hardware runs, and the tell
** was the diagnostic's OWN absence -- the first periodic sample is written at
** frame 20 and flushed immediately, and no run ever produced that line.
**
** So the log accumulates in memory during the render loop and is written out
** from the setup calls (grGlideInit, grSstWinOpen) and from GameFix_Shutdown.
** Those are not inside a frame and have been observed to be safe.
*/
static int          g_inSwap   = 0;

static void GameFix_LogFlush(void);

/*
** Is the running exe one this file has a profile for?
**
** Everything below is gated on it, and that is not tidiness -- it is the
** difference between a driver-wide feature and a per-game one.  glide3x.dll is
** loaded by every Glide app on the machine, and the Glide2 wrapper next door
** uses the SAME config filename and the SAME [GameFix] section for its own
** games.  Ungated, this file read GTA2's, Ignition's and Driver's
** wideDriver.ini, and would write g3fix.txt and the watchdog's g3watch.txt
** into their folders.
**
** Defined after g_profiles, so this is only the prototype.
*/
static int GameFix_ExeIsOurs(void);

/*
** Enabled by [GameFix] log=1 in wideDriver.ini beside the exe.  Decided once
** and cached: this is called from per-frame paths.
**
** One switch, deliberately.  There used to be a second, the environment
** variable FX_GLIDE_GAMEFIX_LOG, and a second switch is a second thing to
** remember to turn off: with no ini present at all the log is silent, but an
** environment variable set once in a shell or a shortcut keeps writing
** g3fix.txt with nothing on disk to explain why.  Removed so that "no ini, no
** log" is the whole rule.
*/
static int GameFix_LogEnabled(void)
{
    char ini[MAX_PATH];

    if (g_logOn >= 0) return g_logOn;

    /* Another game's ini is not ours to read, and its folder is not ours to
       write into.  The wrapper's games use this very filename. */
    if (!GameFix_ExeIsOurs()) { g_logOn = 0; return 0; }

    g_logOn = (PathBesideExe(GAMEFIX_INI, ini) &&
               GetPrivateProfileIntA("GameFix", "log", 0, ini) != 0) ? 1 : 0;

    return g_logOn;
}

void GameFix_Log(const char *fmt, ...)
{
    char    line[1024];   /* wvsprintf's own output limit; a %s can be MAX_PATH */
    va_list ap;
    int     n;

    if (!GameFix_LogEnabled() || g_logFull) return;

    va_start(ap, fmt);
    n = wvsprintfA(line, fmt, ap);
    va_end(ap);

    if (n < 0) return;
    if (g_logLen + (unsigned int)n + 2 >= GAMEFIX_LOG_CAP - GAMEFIX_LOG_NOTICE) {
        /* Say so rather than falling silent.  A diagnostic that stops
           recording looks like an event that never happened.  The room for
           saying so is reserved above, so it cannot itself be what
           does not fit. */
        g_logFull = 1;
        memcpy(g_logBuf + g_logLen, "-- LOG FULL --\r\n", 16);
        g_logLen += 16;
        g_logDirty = 1;
        GameFix_LogFlush();
        return;
    }

    memcpy(g_logBuf + g_logLen, line, (unsigned int)n);
    g_logLen += (unsigned int)n;
    g_logBuf[g_logLen++] = '\r';
    g_logBuf[g_logLen++] = '\n';
    g_logDirty = 1;
}

static void GameFix_LogFlush(void)
{
    char   path[MAX_PATH];
    HANDLE h;
    DWORD  wrote = 0;

    /* Never from inside a frame -- see g_inSwap.  The data stays buffered and
       dirty, and goes out at the next setup call or at shutdown. */
    if (g_inSwap) return;

    if (!g_logDirty || !g_logLen) return;
    if (!PathBesideExe(GAMEFIX_LOG, path)) return;

    /* WRITE_THROUGH plus an explicit flush, because the run this log describes
       usually ends in a hard reset and Win98's write-behind cache otherwise
       loses the tail -- observed as a file truncated mid-word. */
    h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    WriteFile(h, g_logBuf, g_logLen, &wrote, NULL);
    FlushFileBuffers(h);
    CloseHandle(h);
    g_logDirty = 0;
}

/*
** Crash filter.  Chained, and returns EXCEPTION_CONTINUE_SEARCH so the OS
** dialog still appears -- this only writes the log, it does not swallow the
** fault.
**
** Report the faulting address two ways, because each names a different
** culprit: as an absolute address (which module) and as an RVA into whichever
** loaded module contains it (which routine).  Plus the register set, because a
** negative offset into a buffer this code allocated has named a bug in one
** line before now.
*/
static LPTOP_LEVEL_EXCEPTION_FILTER g_prevFilter = NULL;
static int                          g_filterOn   = 0;

static LONG WINAPI GameFix_CrashFilter(struct _EXCEPTION_POINTERS *ep)
{
    if (ep && ep->ExceptionRecord && ep->ContextRecord) {
        EXCEPTION_RECORD *er = ep->ExceptionRecord;
        CONTEXT          *cx = ep->ContextRecord;
        MEMORY_BASIC_INFORMATION mbi;
        unsigned int      rva = 0;
        char              mod[MAX_PATH];

        mod[0] = '\0';
        if (VirtualQuery((LPCVOID)er->ExceptionAddress, &mbi, sizeof(mbi)) &&
            mbi.AllocationBase) {
            rva = (unsigned int)er->ExceptionAddress -
                  (unsigned int)mbi.AllocationBase;
            GetModuleFileNameA((HMODULE)mbi.AllocationBase, mod, MAX_PATH);
        }

        GameFix_Log("CRASH code=%08lx at=%08lx  %s+%08x",
                    (unsigned long)er->ExceptionCode,
                    (unsigned long)(unsigned int)er->ExceptionAddress,
                    mod[0] ? mod : "?", rva);
        GameFix_Log("  eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx",
                    cx->Eax, cx->Ebx, cx->Ecx, cx->Edx);
        GameFix_Log("  esi=%08lx edi=%08lx ebp=%08lx esp=%08lx",
                    cx->Esi, cx->Edi, cx->Ebp, cx->Esp);
        g_logDirty = 1;
        GameFix_LogFlush();
    }

    if (g_prevFilter) return g_prevFilter(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void GameFix_InstallCrashFilter(void)
{
    if (g_filterOn || !GameFix_LogEnabled()) return;
    g_filterOn   = 1;
    g_prevFilter = SetUnhandledExceptionFilter(GameFix_CrashFilter);
}


/* ======================================================================== */
/* Watchdog -- name the loop when the main thread stops making progress     */
/* ======================================================================== */
/*
** Diablo II's freeze leaves the music playing and the keyboard dead.  That is
** not a hardware lockup: a wedged Voodoo takes the whole machine, and a dead
** main thread does not keep DirectSound fed.  It means the MAIN THREAD is
** spinning while other threads run on -- so the process is still there to be
** interrogated, and a crash filter is no use because nothing ever faults.
**
** So: a second thread that samples the main thread's EIP once a second, with
** SuspendThread / GetThreadContext / ResumeThread, and writes each sample to
** its own file.  When the main thread stops advancing, the last line names the
** address it is stuck at -- resolved to module + RVA, which is what turns
** "somewhere in Diablo II" into a routine to read.
**
** Its own file and its own buffer, deliberately: the main thread writes
** g3fix.txt from the setup calls, and two threads racing on one path would
** lose the very record being collected.
**
** Rewrites the whole file each sample, so the last line on disk is always the
** most recent sample -- there is no clean shutdown to flush at.
*/

#define GAMEFIX_WATCH_LOG  "g3watch.txt"

/* Defined with the Diablo II code below, which is where the addresses it is
   used with are documented. */
static BOOL ReadModuleGlobal(HMODULE mod, unsigned int prefVa, unsigned int *out);

/*
** Read a LIVE address, bounds-checked against a module's image.
**
** ReadModuleGlobal takes an address as written in the disassembly and applies
** the load delta.  This one takes an address the program is actually holding
** -- a pointer sampled out of a register -- and only checks that it lands
** inside the module before dereferencing it.  The watchdog needs that: the
** register is the ground truth about which object the loop is spinning on,
** and no amount of reading the disassembly has settled it.
*/
static BOOL ReadLive(HMODULE mod, unsigned int va, unsigned int *out)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)mod;
    const IMAGE_NT_HEADERS *nt;
    unsigned int            base = (unsigned int)mod;

    if (!mod) return FALSE;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    nt = (const IMAGE_NT_HEADERS *)((const unsigned char *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    if (va < base) return FALSE;
    if (va + 4u > base + (unsigned int)nt->OptionalHeader.SizeOfImage)
        return FALSE;

    *out = *(const unsigned int *)va;
    return TRUE;
}

static HANDLE g_mainThread = NULL;
static HANDLE g_watchFile  = INVALID_HANDLE_VALUE;
static int    g_watchOn    = 0;

/*
** One line, appended and forced to the platter immediately.
**
** The whole point of this file is to survive the hard reset that ends the run,
** and the first version did not: it buffered in memory and rewrote the file
** whole on every sample.  Win98 came back with a 52-byte g3watch.txt
** containing the first line of wideDriver.ini -- a directory entry pointing at
** clusters that still held the previous occupant, which is what a reset does
** to a file created moments earlier.  The main log came back truncated
** mid-word for the same reason.
**
** So: the handle is opened once and kept, each line is appended rather than
** the file rewritten (rewriting maximises the window in which the file is
** inconsistent), FILE_FLAG_WRITE_THROUGH bypasses the write-behind cache and
** FlushFileBuffers pushes it out per line.  Slow, and it does not matter --
** this fires once a second on a thread that is otherwise asleep.
*/
static void WatchWrite(const char *fmt, ...)
{
    char    line[512];
    char    path[MAX_PATH];
    va_list ap;
    int     n;
    DWORD   wrote = 0;

    if (g_watchFile == INVALID_HANDLE_VALUE) {
        if (!PathBesideExe(GAMEFIX_WATCH_LOG, path)) return;
        g_watchFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                  CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL |
                                      FILE_FLAG_WRITE_THROUGH,
                                  NULL);
        if (g_watchFile == INVALID_HANDLE_VALUE) return;
    }

    va_start(ap, fmt);
    n = wvsprintfA(line, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(line) - 2) n = (int)sizeof(line) - 2;
    line[n++] = '\r';
    line[n++] = '\n';

    WriteFile(g_watchFile, line, (DWORD)n, &wrote, NULL);
    FlushFileBuffers(g_watchFile);
}

/* Name an address: which module, and the RVA inside it.  An RVA is what can be
   looked up in a disassembly; a raw address cannot. */
static void WatchName(unsigned int addr, char *modOut, unsigned int *rvaOut)
{
    MEMORY_BASIC_INFORMATION mbi;

    modOut[0] = '\0';
    *rvaOut   = 0;

    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) && mbi.AllocationBase) {
        char  full[MAX_PATH];
        char *leaf = full;
        char *p;

        *rvaOut = addr - (unsigned int)mbi.AllocationBase;
        full[0] = '\0';
        if (GetModuleFileNameA((HMODULE)mbi.AllocationBase, full, MAX_PATH)) {
            for (p = full; *p; p++)
                if (*p == '\\' || *p == '/') leaf = p + 1;
            lstrcpynA(modOut, leaf, 40);
        }
    }
}

static DWORD WINAPI GameFix_WatchdogProc(LPVOID unused)
{
    unsigned int lastEip = 0;
    unsigned int same    = 0;
    unsigned int n       = 0;
    int          dumped  = 0;

    (void)unused;

    /* Written before the first sleep, so the file's existence proves the
       thread started.  "Watchdog never ran" and "watchdog ran and saw
       nothing" are different diagnoses and must not look alike. */
    WatchWrite("watchdog started, sampling the main thread once a second");

    for (;;) {
        CONTEXT      ctx;
        char         mod[48];
        unsigned int rva = 0;
        unsigned int eip;
        BOOL         ok;

        Sleep(1000);
        n++;

        if (!g_mainThread) continue;

        memset(&ctx, 0, sizeof(ctx));
        /* INTEGER as well as CONTROL: esi is the object the eviction loop is
           spinning on, and that register is the only thing that has actually
           settled which one it is. */
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

        if (SuspendThread(g_mainThread) == (DWORD)-1) {
            WatchWrite("%u: SuspendThread failed (%lu)", n,
                       (unsigned long)GetLastError());
            continue;
        }
        ok = GetThreadContext(g_mainThread, &ctx);
        ResumeThread(g_mainThread);

        if (!ok) {
            WatchWrite("%u: GetThreadContext failed (%lu)", n,
                       (unsigned long)GetLastError());
            continue;
        }

        eip = (unsigned int)ctx.Eip;
        WatchName(eip, mod, &rva);

        /*
        ** D2Glide's texture-cache pools, dumped from the watchdog because
        ** nothing else can see them at the right moment: they are built after
        ** grSstWinOpen returns, and the hang arrives long before the per-frame
        ** sampler's next turn.
        **
        ** The hang is a three-instruction spin at D2GLIDE+0x8652/86ac/86b2:
        **
        **     while (used == capacity) evict_one();
        **
        ** and evict_one() cannot decrement `used` when it is already zero. So
        ** the loop is unbreakable for exactly one state -- capacity == 0 and
        ** used == 0 -- and this says which of the four pools is in it, and
        ** what the texture-memory span it was sized from actually was.
        **
        ** Pool array: 0x6f866460, stride 0x20; +0 elemSize, +4 capacity,
        ** +8 used.  texMin[] at 0x6f865a38, texMax[] at 0x6f865a64.
        */
        if (!dumped) {
            HMODULE gl = GetModuleHandleA("D2Glide.dll");
            unsigned int v[4];

            if (gl &&
                ReadModuleGlobal(gl, 0x6f865a38u, &v[0]) &&
                ReadModuleGlobal(gl, 0x6f865a3cu, &v[1]) &&
                ReadModuleGlobal(gl, 0x6f865a64u, &v[2]) &&
                ReadModuleGlobal(gl, 0x6f865a68u, &v[3])) {
                unsigned int i;

                WatchWrite("   texMin[0]=%08lx texMin[1]=%08lx"
                           " texMax[0]=%08lx texMax[1]=%08lx",
                           (unsigned long)v[0], (unsigned long)v[1],
                           (unsigned long)v[2], (unsigned long)v[3]);

                for (i = 0; i < 4u; i++) {
                    unsigned int base = 0x6f866460u + 0x20u * i;
                    unsigned int es = 0, cap = 0, used = 0;

                    ReadModuleGlobal(gl, base,      &es);
                    ReadModuleGlobal(gl, base + 4u, &cap);
                    ReadModuleGlobal(gl, base + 8u, &used);
                    WatchWrite("   pool[%u] elem=%08lx cap=%u used=%u%s",
                               i, (unsigned long)es, cap, used,
                               (cap == 0u) ? "   <-- CAPACITY ZERO" : "");
                }
                /* Once it has been seen full, dumping it every second only
                   buries the EIP trace that matters. */
                if (v[2]) dumped = 1;
            }
        }

        /* "Advancing" is generous on purpose: a tight loop stays within a few
           hundred bytes, while normal play wanders across whole modules. */
        if (lastEip && (eip > lastEip ? eip - lastEip : lastEip - eip) < 0x400u)
            same++;
        else
            same = 0;
        lastEip = eip;

        WatchWrite("%u: eip=%08lx %s+%08x esp=%08lx esi=%08lx ebx=%08lx%s", n,
                   (unsigned long)eip, mod[0] ? mod : "?", rva,
                   (unsigned long)ctx.Esp, (unsigned long)ctx.Esi,
                   (unsigned long)ctx.Ebx,
                   (same >= 3u) ? "   <-- STUCK" : "");

        /*
        ** Once stuck, dump the object esi actually points at, every sample.
        **
        ** The earlier one-shot dump fired about a second after grSstWinOpen,
        ** which showed the pools at birth -- all four with used=0 -- and that
        ** says nothing about the state at the hang.  What matters is capacity
        ** and used AT THE MOMENT IT SPINS, read through the live pointer
        ** rather than through an address guessed from the disassembly.
        **
        ** Pool layout: +0 elemSize, +4 capacity, +8 used, +0xc LRU head.
        */
        if (same >= 3u) {
            HMODULE      gl = GetModuleHandleA("D2Glide.dll");
            unsigned int esi = (unsigned int)ctx.Esi;
            unsigned int elem = 0, cap = 0, used = 0, lru = 0;

            if (gl &&
                ReadLive(gl, esi,       &elem) &&
                ReadLive(gl, esi + 4u,  &cap)  &&
                ReadLive(gl, esi + 8u,  &used) &&
                ReadLive(gl, esi + 12u, &lru))
                WatchWrite("   spinning on %08lx: elem=%08lx cap=%u used=%u"
                           " lru=%08lx  (pool index %ld)",
                           (unsigned long)esi, (unsigned long)elem, cap, used,
                           (unsigned long)lru,
                           (long)(((long)esi - 0x6f866460L) / 0x20L));
            else
                WatchWrite("   esi=%08lx is not inside D2Glide -- not a pool",
                           (unsigned long)esi);
        }
    }

    /* Not reached.  Present because MSVC treats a non-void function with no
       return as an error, not a warning. */
    return 0;
}

static void GameFix_StartWatchdog(void)
{
    DWORD tid = 0;

    if (g_watchOn || !GameFix_LogEnabled()) return;
    g_watchOn = 1;

    /* GetCurrentThread() is a pseudo-handle, meaningless to another thread, so
       it has to be duplicated into a real one.  OpenThread would be simpler
       and does not exist on Win9x. */
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                         GetCurrentProcess(), &g_mainThread,
                         THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                         FALSE, 0)) {
        GameFix_Log("gamefix: watchdog DuplicateHandle failed (%lu)",
                    (unsigned long)GetLastError());
        g_mainThread = NULL;
        return;
    }

    if (!CreateThread(NULL, 0, GameFix_WatchdogProc, NULL, 0, &tid))
        GameFix_Log("gamefix: watchdog CreateThread failed (%lu)",
                    (unsigned long)GetLastError());
    else
        GameFix_Log("gamefix: watchdog running -> " GAMEFIX_WATCH_LOG);
}


/* ======================================================================== */
/* Profile application                                                      */
/* ======================================================================== */

/* Longest pattern the reloc scratch buffers can hold.  Signatures are tens of
   bytes; anything approaching this would have stopped being a signature. */
#define PATCH_MAX 128u

/* The module's original ImageBase, read back out of its own PE header in
   memory, so a rebased DLL can be recognised as such.  Zero if unreadable. */
static unsigned int ModuleImageBase(HMODULE mod)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)mod;
    const IMAGE_NT_HEADERS *nt;

    if (!mod) return 0;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    nt = (const IMAGE_NT_HEADERS *)((const unsigned char *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    return (unsigned int)nt->OptionalHeader.ImageBase;
}

/* Copy `src` into `dst`, biasing every 4-byte absolute address named by
   `relocs` by `delta`. */
static void BiasPattern(unsigned char *dst, const unsigned char *src,
                        unsigned int len, const unsigned char *relocs,
                        unsigned int delta)
{
    unsigned int i;

    memcpy(dst, src, len);
    if (!relocs || !delta) return;

    for (i = 0; relocs[i] != RELOC_END; i++) {
        unsigned int at = relocs[i];
        if (at + 4 > len) continue;             /* malformed table -- ignore */
        PutU32(dst + at, ReadU32(dst + at) + delta);
    }
}

/*
** Apply one profile.  Returns TRUE if the module was present and reachable --
** FALSE means "try again later", not "failed".
*/
static BOOL ApplyProfile(const GameProfile *profile)
{
    HMODULE        mod;
    unsigned char *code = NULL;
    unsigned int   codeSize = 0;
    unsigned int   delta = 0;
    unsigned int   i;
    unsigned char  findBuf[PATCH_MAX];
    unsigned char  replBuf[PATCH_MAX];

    /* NULL moduleName means the host process's own main image.
       Otherwise: NOT LoadLibrary.  If the module is not already mapped we are
       simply too early (or this game does not use it), and forcing it in would
       change the game's own load order. */
    mod = GetModuleHandleA(profile->moduleName);
    if (!mod) return FALSE;

    if (!GetCodeRange(mod, &code, &codeSize)) return FALSE;

    delta = (unsigned int)mod - ModuleImageBase(mod);

    GameFix_Log("profile %s / %s: base=%08lx delta=%08lx code=%08lx+%lx",
                profile->exeName,
                profile->moduleName ? profile->moduleName : "(exe)",
                (unsigned long)(unsigned int)mod,
                (unsigned long)delta,
                (unsigned long)(unsigned int)code,
                (unsigned long)codeSize);

    for (i = 0; i < profile->patchCount; i++) {
        const BytePatch     *p = &profile->patches[i];
        const unsigned char *find, *repl;
        unsigned char       *at;
        unsigned int         hits;

        if (p->length == 0) continue;

        if (delta && p->relocs) {
            if (p->length > PATCH_MAX) {
                GameFix_Log("  %-24s TOO LONG TO REBASE", p->name);
                continue;
            }
            BiasPattern(findBuf, p->find,    p->length, p->relocs, delta);
            BiasPattern(replBuf, p->replace, p->length, p->relocs, delta);
            find = findBuf;
            repl = replBuf;
        } else {
            find = p->find;
            repl = p->replace;
        }

        /* Counted before the patch consumes its own find bytes, so a later
           reading of the log can tell "already applied" from "no longer
           present in this build" from "ambiguous, refused".  Purely
           diagnostic, and it doubles the scanning, so it is skipped when
           nothing will read it. */
        hits = GameFix_LogEnabled()
             ? CountPattern(code, codeSize, find, p->length) : 0;

        at = FindUnique(code, codeSize, find, p->length);
        if (!at) {
            GameFix_Log("  %-24s hits=%u SKIPPED", p->name, hits);
            continue;
        }

        if (WriteCode(at, repl, p->length))
            GameFix_Log("  %-24s hits=%u at=%08lx OK", p->name, hits,
                        (unsigned long)(unsigned int)at);
        else
            GameFix_Log("  %-24s hits=%u at=%08lx WRITE FAILED", p->name, hits,
                        (unsigned long)(unsigned int)at);
    }

    return TRUE;
}


/* ======================================================================== */
/* Diablo II -- Lord of Destruction, patch 1.13d (Game.exe 1.0.13.64)        */
/* ======================================================================== */
/*
** The first Glide3 game here.  Its renderer is D2Glide.dll, which imports
** glide3x.dll directly, so the Glide2 wrapper is never in the process and the
** wrapper's copy of gamefix cannot reach it.
**
** Nothing is protected: every module is a plain, unencrypted PE (whole-file
** entropy 5.0-6.5).  `Diablo II.exe` is a 36 KB launcher whose only imports
** are KERNEL32 and USER32 and whose only interesting string is
** CreateProcessA -- the host process is `Game.exe`.
**
** WHAT KIND OF GAME THIS IS
** -------------------------
** Diablo II is 2D throughout: an isometric sprite engine with no projection
** matrix anywhere.  There is therefore no aspect-ratio correction to do -- a
** wider screen simply shows more map, at 1:1 pixels.  That removes most of
** what part one of GAME-PATCHING.md is about and leaves two questions: does
** the game believe the screen size, and does its 2D layer follow (section 36).
**
** The second question has an encouraging first answer.  D2Client.dll refers to
** its screen-width and screen-height globals 389 and 350 times respectively,
** and writes them in exactly TWO routines.  A layer that reads the size that
** often is parametric, not hardcoded; compare the five literal 640s and eight
** literal 800s in the whole 840 KB code section.  So the first build patches
** the resolution chain and NOTHING else, which is precisely the one-minute
** experiment section 36 prescribes: run wide with no 2D work and look at the
** HUD.  Spread out and centred means nearly done; huddled in a corner means
** per-element work.
**
** THE RESOLUTION CHAIN
** --------------------
** Three modules each keep their own copy of the size, and all three must
** agree (section 9 -- resolution must have exactly one source of truth, and
** where the game insists on several, every one of them gets patched):
**
**   D2gfx.dll   ord 10064, GetResolutionSize(mode, *w, *h) at 0x6fa8b0e0.
**               A four-entry jump table: mode 0 -> 640x480, modes 1 and 2 ->
**               800x600, mode 3 -> 1344x700 (Blizzard's own unused fourth
**               slot).  This is the module-level answer to "how big is mode
**               N", and D2Win asks it when sizing the window.
**
**   D2Client.dll  two routines that set the live size, and they do NOT ask
**               D2gfx -- they carry their own copies of the numbers, which is
**               why patching D2gfx alone would do nothing:
**                 0x6fadc220  SetResolutionMode(mode): mode 0 -> 640x480,
**                             mode 2 -> 800x600.  Writes W to 0x6fba7034 and
**                             0x6fba703c and 0x6fbd3d64, H to 0x6fba7038, and
**                             computes H-40 into 0x6fbd3d60.
**                 0x6faf6269 / 0x6faf6382  the video-options screen, same
**                             globals -- but here H-40 is a LITERAL (0x1b8,
**                             0x230), so it needs patching too.
**
**   D2Glide.dll 0x6f85d5a0, the mode->Glide open path: mode 0 -> 640x480 and
**               GR_RESOLUTION_640x480, otherwise 800x600 and
**               GR_RESOLUTION_800x600, then grSstWinOpen.  Its own size
**               globals are 0x6f865a78 (W) and 0x6f865b14 (H).
**
** The resolution enum it passes is deliberately NOT patched: the driver's
** override replaces it inside grSstWinOpen regardless (gsst.c), so rewriting
** it here would be a second source of truth for the same decision.  The two
** size globals ARE patched, because nothing else tells D2Glide what the
** driver did.
**
** Every mode arm is patched, not a chosen one.  Which mode Diablo II starts in
** depends on its own saved video settings, and patching only the arm we
** guessed would leave the other one live -- see "With an override active,
** patch EVERY mode entry" in GAME-PATCHING.md section 9.
**
** WHAT IS DELIBERATELY LEFT ALONE IN THIS FIRST BUILD
** ---------------------------------------------------
**   - 0x6fbcd2b4, D2Client's "this is the 800x600 layout" flag.  It selects
**     which UI art the game loads.  Forcing it changes the asset set at the
**     same time as the resolution, and then a wrong result has two possible
**     causes instead of one.
**   - D2Glide's texture-memory partitioning at 0x6f85d405, which has an
**     explicit `W == 800 && H == 600` arm and a general fallback.  The
**     fallback is what a patched build will take; whether that is adequate is
**     a question for the hardware, not for reading.
*/

/*
** All Diablo II byte patterns are verified unique in the shipped 1.13d
** modules, and each is verified to sit at the address named above.  Patterns
** that quote a global carry a `relocs` list so a rebased DLL still matches.
**
** The immediates are placeholders: they are rewritten by
** Diablo2AdoptResolution from the driver's override before any of this is
** applied.  The `find` copies keep the stock values, which is what makes the
** whole set idempotent.
*/

/* --- D2gfx.dll: GetResolutionSize, three arms.  No absolute addresses. --- */

static const unsigned char d2_gfx_m0_find[] = {
    0x8b, 0x44, 0x24, 0x08,                     /* mov  eax,[esp+8]       */
    0x8b, 0x4c, 0x24, 0x0c,                     /* mov  ecx,[esp+0xc]     */
    0xc7, 0x00, 0x80, 0x02, 0x00, 0x00,         /* mov  [eax],640         */
    0xc7, 0x01, 0xe0, 0x01, 0x00, 0x00,         /* mov  [ecx],480         */
    0xc2, 0x0c, 0x00                            /* ret  0xc               */
};
static unsigned char d2_gfx_m0_repl[] = {
    0x8b, 0x44, 0x24, 0x08,
    0x8b, 0x4c, 0x24, 0x0c,
    0xc7, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x01, 0x00, 0x00, 0x00, 0x00,
    0xc2, 0x0c, 0x00
};

static const unsigned char d2_gfx_m1_find[] = {
    0x8b, 0x54, 0x24, 0x08,                     /* mov  edx,[esp+8]       */
    0x8b, 0x44, 0x24, 0x0c,                     /* mov  eax,[esp+0xc]     */
    0xc7, 0x02, 0x20, 0x03, 0x00, 0x00,         /* mov  [edx],800         */
    0xc7, 0x00, 0x58, 0x02, 0x00, 0x00,         /* mov  [eax],600         */
    0xc2, 0x0c, 0x00
};
static unsigned char d2_gfx_m1_repl[] = {
    0x8b, 0x54, 0x24, 0x08,
    0x8b, 0x44, 0x24, 0x0c,
    0xc7, 0x02, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc2, 0x0c, 0x00
};

static const unsigned char d2_gfx_m3_find[] = {
    0x8b, 0x4c, 0x24, 0x08,                     /* mov  ecx,[esp+8]       */
    0x8b, 0x54, 0x24, 0x0c,                     /* mov  edx,[esp+0xc]     */
    0xc7, 0x01, 0x40, 0x05, 0x00, 0x00,         /* mov  [ecx],1344        */
    0xc7, 0x02, 0xbc, 0x02, 0x00, 0x00,         /* mov  [edx],700         */
    0xc2, 0x0c, 0x00
};
static unsigned char d2_gfx_m3_repl[] = {
    0x8b, 0x4c, 0x24, 0x08,
    0x8b, 0x54, 0x24, 0x0c,
    0xc7, 0x01, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x02, 0x00, 0x00, 0x00, 0x00,
    0xc2, 0x0c, 0x00
};

/* Width and height immediates sit at the same offsets in all three arms. */
#define D2_GFX_W_AT 10
#define D2_GFX_H_AT 16

/* --- D2Client.dll: SetResolutionMode, both arms. --- */

static const unsigned char d2_cli_set800_find[] = {
    0xb8, 0x20, 0x03, 0x00, 0x00,                     /* mov eax,800       */
    0xa3, 0x34, 0x70, 0xba, 0x6f,                     /* mov [W],eax       */
    0xc7, 0x05, 0x38, 0x70, 0xba, 0x6f,               /* mov [H],600       */
    0x58, 0x02, 0x00, 0x00
};
static unsigned char d2_cli_set800_repl[] = {
    0xb8, 0x00, 0x00, 0x00, 0x00,
    0xa3, 0x34, 0x70, 0xba, 0x6f,
    0xc7, 0x05, 0x38, 0x70, 0xba, 0x6f,
    0x00, 0x00, 0x00, 0x00
};

static const unsigned char d2_cli_set640_find[] = {
    0xb8, 0x80, 0x02, 0x00, 0x00,                     /* mov eax,640       */
    0xa3, 0x34, 0x70, 0xba, 0x6f,                     /* mov [W],eax       */
    0xc7, 0x05, 0x38, 0x70, 0xba, 0x6f,               /* mov [H],480       */
    0xe0, 0x01, 0x00, 0x00
};
static unsigned char d2_cli_set640_repl[] = {
    0xb8, 0x00, 0x00, 0x00, 0x00,
    0xa3, 0x34, 0x70, 0xba, 0x6f,
    0xc7, 0x05, 0x38, 0x70, 0xba, 0x6f,
    0x00, 0x00, 0x00, 0x00
};

static const unsigned char d2_cli_set_relocs[] = { 6, 12, RELOC_END };
#define D2_CLI_SET_W_AT  1
#define D2_CLI_SET_H_AT 16

/* --- D2Client.dll: the video-options screen, both arms.  These write the
       H-40 viewport height as a literal, so it is patched here too. --- */

static const unsigned char d2_cli_opt640_find[] = {
    0xb8, 0x80, 0x02, 0x00, 0x00,                     /* mov eax,640       */
    0x53,                                             /* push ebx          */
    0xa3, 0x34, 0x70, 0xba, 0x6f,                     /* mov [W],eax       */
    0xc7, 0x05, 0x38, 0x70, 0xba, 0x6f,               /* mov [H],480       */
    0xe0, 0x01, 0x00, 0x00,
    0x89, 0x1d, 0xb4, 0xd2, 0xbc, 0x6f,               /* mov [is800],ebx   */
    0xa3, 0x64, 0x3d, 0xbd, 0x6f,                     /* mov [vpW],eax     */
    0xc7, 0x05, 0x60, 0x3d, 0xbd, 0x6f,               /* mov [vpH],440     */
    0xb8, 0x01, 0x00, 0x00
};
static unsigned char d2_cli_opt640_repl[] = {
    0xb8, 0x00, 0x00, 0x00, 0x00,
    0x53,
    0xa3, 0x34, 0x70, 0xba, 0x6f,
    0xc7, 0x05, 0x38, 0x70, 0xba, 0x6f,
    0x00, 0x00, 0x00, 0x00,
    0x89, 0x1d, 0xb4, 0xd2, 0xbc, 0x6f,
    0xa3, 0x64, 0x3d, 0xbd, 0x6f,
    0xc7, 0x05, 0x60, 0x3d, 0xbd, 0x6f,
    0x00, 0x00, 0x00, 0x00
};
static const unsigned char d2_cli_opt640_relocs[] = { 7, 13, 23, 28, 34, RELOC_END };
#define D2_CLI_OPT640_W_AT    1
#define D2_CLI_OPT640_H_AT   17
#define D2_CLI_OPT640_VPH_AT 38

static const unsigned char d2_cli_opt800_find[] = {
    0xb8, 0x20, 0x03, 0x00, 0x00,                     /* mov eax,800       */
    0x6a, 0x02,                                       /* push 2            */
    0xa3, 0x34, 0x70, 0xba, 0x6f,                     /* mov [W],eax       */
    0xc7, 0x05, 0x38, 0x70, 0xba, 0x6f,               /* mov [H],600       */
    0x58, 0x02, 0x00, 0x00,
    0xc7, 0x05, 0xb4, 0xd2, 0xbc, 0x6f,               /* mov [is800],1     */
    0x01, 0x00, 0x00, 0x00,
    0xa3, 0x64, 0x3d, 0xbd, 0x6f,                     /* mov [vpW],eax     */
    0xc7, 0x05, 0x60, 0x3d, 0xbd, 0x6f,               /* mov [vpH],560     */
    0x30, 0x02, 0x00, 0x00
};
static unsigned char d2_cli_opt800_repl[] = {
    0xb8, 0x00, 0x00, 0x00, 0x00,
    0x6a, 0x02,
    0xa3, 0x34, 0x70, 0xba, 0x6f,
    0xc7, 0x05, 0x38, 0x70, 0xba, 0x6f,
    0x00, 0x00, 0x00, 0x00,
    0xc7, 0x05, 0xb4, 0xd2, 0xbc, 0x6f,
    0x01, 0x00, 0x00, 0x00,
    0xa3, 0x64, 0x3d, 0xbd, 0x6f,
    0xc7, 0x05, 0x60, 0x3d, 0xbd, 0x6f,
    0x00, 0x00, 0x00, 0x00
};
static const unsigned char d2_cli_opt800_relocs[] = { 8, 14, 24, 33, 39, RELOC_END };
#define D2_CLI_OPT800_W_AT    1
#define D2_CLI_OPT800_H_AT   18
#define D2_CLI_OPT800_VPH_AT 43

/*
** --- D2Glide.dll: the open path's mode arm, all three values at once. ---
**
** Extended to start eleven bytes earlier than it used to, so it also covers
** the `mov ecx,<GrScreenResolution_t>` that is about to be handed to
** grSstWinOpen.  That was deliberately left alone at first, on the reasoning
** that the driver's override rewrites it anyway -- which is true, and which
** turned out to be the wrong call: it made the whole fix DEPEND on the
** override being armed.  Patching it means Diablo II asks for the mode
** directly, so the game can run with FX_GLIDE_OVERRIDE_RESOLUTION disabled
** entirely, which is the configuration known to be well behaved here.
**
** With the override armed the patch is a no-op in effect: grSstWinOpen
** replaces the enum with the same value, because both come from the same
** target.  So there is one code path, not two, and it satisfies section 9 --
** the game now asks for what it actually gets.
*/
static const unsigned char d2_gl_open640_find[] = {
    0x8b, 0x15, 0x10, 0x7b, 0x86, 0x6f,                         /* mov edx,[refresh0] */
    0xb9, 0x07, 0x00, 0x00, 0x00,                               /* mov ecx,GR_RES_640x480 */
    0xc7, 0x05, 0x78, 0x5a, 0x86, 0x6f, 0x80, 0x02, 0x00, 0x00, /* [W]=640 */
    0xc7, 0x05, 0x14, 0x5b, 0x86, 0x6f, 0xe0, 0x01, 0x00, 0x00  /* [H]=480 */
};
static unsigned char d2_gl_open640_repl[] = {
    0x8b, 0x15, 0x10, 0x7b, 0x86, 0x6f,
    0xb9, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x05, 0x78, 0x5a, 0x86, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x05, 0x14, 0x5b, 0x86, 0x6f, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char d2_gl_open800_find[] = {
    0x8b, 0x15, 0x14, 0x7b, 0x86, 0x6f,                         /* mov edx,[refresh1] */
    0xb9, 0x08, 0x00, 0x00, 0x00,                               /* mov ecx,GR_RES_800x600 */
    0xc7, 0x05, 0x78, 0x5a, 0x86, 0x6f, 0x20, 0x03, 0x00, 0x00, /* [W]=800 */
    0xc7, 0x05, 0x14, 0x5b, 0x86, 0x6f, 0x58, 0x02, 0x00, 0x00  /* [H]=600 */
};
static unsigned char d2_gl_open800_repl[] = {
    0x8b, 0x15, 0x14, 0x7b, 0x86, 0x6f,
    0xb9, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x05, 0x78, 0x5a, 0x86, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x05, 0x14, 0x5b, 0x86, 0x6f, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char d2_gl_open_relocs[] = { 2, 13, 23, RELOC_END };
#define D2_GL_RES_AT  7
#define D2_GL_W_AT   17
#define D2_GL_H_AT   27

/*
** --- D2Glide.dll: the texture-cache init's "is this 800x600?" gate. ---
**
** THIS IS THE ONE THAT MATTERS.  Without it the game hangs on the main menu at
** every resolution except its own two, and the other patches are irrelevant
** because the game never gets far enough to draw.
**
** InitTextureCaches @0x6f85d180 has two paths.  Path A runs when the mode is 0
** or 2 (the flag at 0x6f867b54) and always builds the pools.  Path B is
** everything else, and it opens like this:
**
**     6f85d405  cmp ds:[W],800 ; jne done     <- SKIPS ALL POOL INIT
**     6f85d415  cmp ds:[H],600 ; jne done     <- SKIPS ALL POOL INIT
**     6f85d425  ...build the pools...
**     6f85d581  done: return 1                <- reports SUCCESS either way
**
** So at any size that is not exactly 800x600 it quietly builds nothing and
** says it worked.  The pools are torn down and zeroed when the context closes,
** so after the first close-and-reopen every pool is elem=0, capacity=0 -- and
** the allocator's eviction loop at 0x6f858640 is
**
**     while (used == capacity) evict_one();
**
** where evict_one() cannot decrement `used` below zero.  capacity==0 with
** used==0 is the one state it can never leave: a three-instruction spin at
** 0x6f858652/86ac/86b2 with the main thread pinned and the sound thread
** running on, which is exactly what the watchdog caught (esi=6f866480,
** elem=0 cap=0, EIP cycling those three addresses).
**
** The fix is to make the gate ask "is this the resolution we configured?"
** rather than "is this 800x600".  Same length, no branch target moves, and the
** two `jne` displacements are carried through untouched.  Deliberately NOT
** done by nop-ing the jumps: that would run the 800x600-tuned block at sizes
** it was never written for, which is a bigger change than the bug warrants.
*/
static const unsigned char d2_gl_gate_find[] = {
    0x81, 0x3d, 0x78, 0x5a, 0x86, 0x6f, 0x20, 0x03, 0x00, 0x00, /* cmp [W],800 */
    0x0f, 0x85, 0x6c, 0x01, 0x00, 0x00,                         /* jne done    */
    0x81, 0x3d, 0x14, 0x5b, 0x86, 0x6f, 0x58, 0x02, 0x00, 0x00, /* cmp [H],600 */
    0x0f, 0x85, 0x5c, 0x01, 0x00, 0x00                          /* jne done    */
};
static unsigned char d2_gl_gate_repl[] = {
    0x81, 0x3d, 0x78, 0x5a, 0x86, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x85, 0x6c, 0x01, 0x00, 0x00,
    0x81, 0x3d, 0x14, 0x5b, 0x86, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x85, 0x5c, 0x01, 0x00, 0x00
};
static const unsigned char d2_gl_gate_relocs[] = { 2, 18, RELOC_END };
#define D2_GL_GATE_W_AT  6
#define D2_GL_GATE_H_AT 22


static const BytePatch d2_gfx_patches[] = {
    { "gfx mode0 -> WxH", d2_gfx_m0_find, d2_gfx_m0_repl,
      sizeof(d2_gfx_m0_find), NULL },
    { "gfx mode1/2 -> WxH", d2_gfx_m1_find, d2_gfx_m1_repl,
      sizeof(d2_gfx_m1_find), NULL },
    { "gfx mode3 -> WxH", d2_gfx_m3_find, d2_gfx_m3_repl,
      sizeof(d2_gfx_m3_find), NULL }
};

static const BytePatch d2_client_patches[] = {
    { "cli setmode 640 -> WxH", d2_cli_set640_find, d2_cli_set640_repl,
      sizeof(d2_cli_set640_find), d2_cli_set_relocs },
    { "cli setmode 800 -> WxH", d2_cli_set800_find, d2_cli_set800_repl,
      sizeof(d2_cli_set800_find), d2_cli_set_relocs },
    { "cli options 640 -> WxH", d2_cli_opt640_find, d2_cli_opt640_repl,
      sizeof(d2_cli_opt640_find), d2_cli_opt640_relocs },
    { "cli options 800 -> WxH", d2_cli_opt800_find, d2_cli_opt800_repl,
      sizeof(d2_cli_opt800_find), d2_cli_opt800_relocs }
};

static const BytePatch d2_glide_patches[] = {
    { "glide open 640 -> WxH", d2_gl_open640_find, d2_gl_open640_repl,
      sizeof(d2_gl_open640_find), d2_gl_open_relocs },
    { "glide open 800 -> WxH", d2_gl_open800_find, d2_gl_open800_repl,
      sizeof(d2_gl_open800_find), d2_gl_open_relocs },
    { "glide texcache gate", d2_gl_gate_find, d2_gl_gate_repl,
      sizeof(d2_gl_gate_find), d2_gl_gate_relocs }
};

/*
** Fill in every immediate from the adopted resolution.  Called once the
** driver's override is known and before anything is applied, so the tables
** above never carry a stale number.
**
** The viewport height keeps the game's own rule, H-40, rather than a constant
** copied from one of the stock modes: 480-440 and 600-560 are both 40, so 40
** is what Diablo II means, and SetResolutionMode computes exactly that at run
** time in the arms where it is not a literal.
*/
static void Diablo2AdoptResolution(void)
{
    unsigned int w  = g_targetW;
    unsigned int h  = g_targetH;
    unsigned int vh = (h > 40u) ? (h - 40u) : h;

    PutU32(d2_gfx_m0_repl + D2_GFX_W_AT, w);
    PutU32(d2_gfx_m0_repl + D2_GFX_H_AT, h);
    PutU32(d2_gfx_m1_repl + D2_GFX_W_AT, w);
    PutU32(d2_gfx_m1_repl + D2_GFX_H_AT, h);
    PutU32(d2_gfx_m3_repl + D2_GFX_W_AT, w);
    PutU32(d2_gfx_m3_repl + D2_GFX_H_AT, h);

    PutU32(d2_cli_set640_repl + D2_CLI_SET_W_AT, w);
    PutU32(d2_cli_set640_repl + D2_CLI_SET_H_AT, h);
    PutU32(d2_cli_set800_repl + D2_CLI_SET_W_AT, w);
    PutU32(d2_cli_set800_repl + D2_CLI_SET_H_AT, h);

    PutU32(d2_cli_opt640_repl + D2_CLI_OPT640_W_AT,   w);
    PutU32(d2_cli_opt640_repl + D2_CLI_OPT640_H_AT,   h);
    PutU32(d2_cli_opt640_repl + D2_CLI_OPT640_VPH_AT, vh);
    PutU32(d2_cli_opt800_repl + D2_CLI_OPT800_W_AT,   w);
    PutU32(d2_cli_opt800_repl + D2_CLI_OPT800_H_AT,   h);
    PutU32(d2_cli_opt800_repl + D2_CLI_OPT800_VPH_AT, vh);

    PutU32(d2_gl_open640_repl + D2_GL_RES_AT, g_targetRes);
    PutU32(d2_gl_open640_repl + D2_GL_W_AT,   w);
    PutU32(d2_gl_open640_repl + D2_GL_H_AT,   h);
    PutU32(d2_gl_open800_repl + D2_GL_RES_AT, g_targetRes);
    PutU32(d2_gl_open800_repl + D2_GL_W_AT,   w);
    PutU32(d2_gl_open800_repl + D2_GL_H_AT,   h);

    PutU32(d2_gl_gate_repl + D2_GL_GATE_W_AT, w);
    PutU32(d2_gl_gate_repl + D2_GL_GATE_H_AT, h);
}

/*
** Sample what Diablo II currently believes, so the log separates "the patch
** never landed" from "the patch landed but its site never executes"
** (GAME-PATCHING.md section 6).  Read straight out of the live globals rather
** than from anything this file computed.
*/
/*
** Read one of a module's globals, given the address it has at the module's
** preferred base.  Bounds-checked against SizeOfImage, because an
** instrumentation read runs in more states than the code it is watching: a
** different build, or a module of the same name belonging to something else,
** would otherwise fault inside the driver.
*/
static BOOL ReadModuleGlobal(HMODULE mod, unsigned int prefVa, unsigned int *out)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)mod;
    const IMAGE_NT_HEADERS *nt;
    unsigned int            rva;

    if (!mod) return FALSE;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    nt = (const IMAGE_NT_HEADERS *)((const unsigned char *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    if (prefVa < (unsigned int)nt->OptionalHeader.ImageBase) return FALSE;
    rva = prefVa - (unsigned int)nt->OptionalHeader.ImageBase;
    if (rva + 4 > (unsigned int)nt->OptionalHeader.SizeOfImage) return FALSE;

    *out = *(const unsigned int *)((const unsigned char *)mod + rva);
    return TRUE;
}

/* Write one of a module's globals, given its address at the preferred base. */
static BOOL WriteModuleGlobal(HMODULE mod, unsigned int prefVa, unsigned int v)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)mod;
    const IMAGE_NT_HEADERS *nt;
    unsigned int            rva;
    unsigned char          *at;
    DWORD                   old = 0;

    if (!mod) return FALSE;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    nt = (const IMAGE_NT_HEADERS *)((const unsigned char *)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    if (prefVa < (unsigned int)nt->OptionalHeader.ImageBase) return FALSE;
    rva = prefVa - (unsigned int)nt->OptionalHeader.ImageBase;
    if (rva + 4 > (unsigned int)nt->OptionalHeader.SizeOfImage) return FALSE;

    at = (unsigned char *)mod + rva;
    if (!VirtualProtect(at, 4, PAGE_READWRITE, &old)) return FALSE;
    PutU32(at, v);
    VirtualProtect(at, 4, old, &old);
    return TRUE;
}

/* ------------------------------------------------------------------------ */
/* 2D placement: one hook, a data table                                       */
/* ------------------------------------------------------------------------ */
/*
** Diablo II lays the control panel out as separate pieces.  Most already
** position themselves against the live width -- the four centre pieces sit at
** W/2-235 and friends, exactly where they belong -- but several do not, and
** each is corrected by rewriting the coordinate on its way to the screen.
**
** Hooked at the CALLER's import slot rather than at the function: no
** trampoline, no instruction-boundary analysis of Blizzard's code, and the
** return address at entry is already the drawer being looked for.  A
** correction is then a write to an argument the caller has already pushed, so
** nothing is relocated and adding an element is a table row.
*/
#define ARG_NONE 0xffu
/*
** Some of Diablo II's drawing entry points are __fastcall, so a coordinate can
** arrive in a REGISTER rather than on the stack.  The belt's hotkey digits
** forced this: D2Win#10076 is DrawText(ecx=string, edx=x, then y/colour/
** centred on the stack), and because the hook only read stack arguments its x
** was invisible -- the trace showed `a0=589 a1=4 a2=0`, which is the y, the
** colour and the centre flag, with no x anywhere in sight.
**
** The stub already preserves every register with pushad, so the saved copy is
** in its own frame; ARG_REG|n addresses that copy instead of the argument
** block, and popad hands the modified value to the real callee.  Order is
** pushfd's word then pushad's, which pushes EAX first and leaves EDI lowest.
*/
#define ARG_REG   0x80u
#define REG_EDX   (ARG_REG | 6u)
#define REG_ECX   (ARG_REG | 7u)
#define REG_EAX   (ARG_REG | 8u)

typedef struct {
    const char   *module;   /* module whose import slot is redirected */
    unsigned int  slot;     /* the slot, at that module's preferred base */
    unsigned int  base;     /* that module's preferred base */
    unsigned char xarg;
    unsigned char yarg;
    const char   *label;
} D2Hook;

static const D2Hook g_d2Hooks[] = {
    { "D2Client.dll", 0x6fb7fc28u, 0x6fab0000u, 1, 2, "cli DrawImage" },
    { "D2Win.dll",    0x6f8fb084u, 0x6f8e0000u, 1, 2, "win DrawImage" },
    /* DrawText: __fastcall, x in edx, y as the first stack argument. */
    { "D2Client.dll", 0x6fb7fbc4u, 0x6fab0000u, REG_EDX, 0, "cli win#10076" },
    /* Clipped image draw -- the orb liquid, with the fill level in arg 4. */
    { "D2Client.dll", 0x6fb7fbecu, 0x6fab0000u, 1, 2, "cli gfx#10082" },
    /* The icon beside each orb; one call site draws BOTH of them. */
    { "D2Client.dll", 0x6fb7fc7cu, 0x6fab0000u, 1, 2, "cli gfx#10067" },
    /* Traced only, to identify drawers.  Nothing is written into an argument
       whose meaning has not been confirmed by a run. */
    /*
    ** The FRONT END's text.
    **
    ** Found by trace, not by reading: at 1432x600 the menu's images all moved
    ** and none of its text did, so the text was reaching D2gfx through a slot
    ** we did not hook.  It is NOT D2Win#10076 (DrawText) -- nothing inside
    ** D2Win calls that, only D2Client does, which is exactly why the in-game
    ** belt digits work and the menu did not.
    **
    ** Ten candidate draw slots were hooked trace-only for one run.  This is
    ** the one that carried glyphs:
    **
    **   draw win gfx#10067 +013629  <ptr> 222 520 ...   the copyright line
    **   draw win gfx#10067 +013629  <ptr> 236 520 ...   x advancing per glyph
    **   draw win gfx#10067 +01344f  <ptr> 340 384 ...   the button labels
    **
    ** x in argument 1 and y in argument 2 -- the same positions D2Client's
    ** hook on this very export already uses for the orb icons.  The other
    ** nine carried no coordinates and were dropped rather than left running
    ** in the draw path for nothing.
    */
    { "D2Win.dll",    0x6f8fb0a0u, 0x6f8e0000u, 1, 2, "win gfx#10067" },

    /*
    ** Candidates for the ABILITY TOOLTIP, trace-only.
    **
    ** Its glyphs come out of D2Win's shared blitter at +013629, so the text is
    ** real but the D2Client call that produced it is not one we hook -- the
    ** watch box saw the glyphs and no matching cli win#10076.
    **
    ** That blitter's function (6f8f34d0) is reached from twelve D2Win exports.
    ** Of those, D2Client imports exactly three: 10076, which is hooked and is
    ** the belt digits, and these two.  So the tooltip is one of them.
    */
    { "D2Client.dll", 0x6fb7fbc8u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10078" },
    { "D2Client.dll", 0x6fb7fb50u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10124" },

    { "D2Client.dll", 0x6fb7fc58u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10013" },
    { "D2Client.dll", 0x6fb7fbc0u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10150" },
    { "D2Client.dll", 0x6fb7fbd0u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10047" },
    { "D2Client.dll", 0x6fb7fbdcu, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10069" },
    /* Framed hover text (the weapon-swap tooltip, among others): __fastcall
       like DrawText, x in edx and y as the first stack argument.  Was
       trace-only, which is why a rule on it could never fire. */
    { "D2Client.dll", 0x6fb7fbbcu, 0x6fab0000u, REG_EDX, 0, "cli win#10137" },
    { "D2Client.dll", 0x6fb7fc98u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10047" },
    { "D2Client.dll", 0x6fb7fcc8u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10041" },
    { "D2Client.dll", 0x6fb7fc74u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10080" },
    { "D2Client.dll", 0x6fb7fc6cu, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10061" },
    { "D2Client.dll", 0x6fb7fc70u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10010" },
    { "D2Client.dll", 0x6fb7fbf0u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10071" },
    { "D2Client.dll", 0x6fb7fc10u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10060" },
    { "D2Client.dll", 0x6fb7fc9cu, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10032" },
    { "D2Client.dll", 0x6fb7fc18u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10081" },
    { "D2Client.dll", 0x6fb7fc14u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10040" },
    { "D2Client.dll", 0x6fb7fca0u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10084" },
    { "D2Client.dll", 0x6fb7fcccu, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10072" },
    { "D2Client.dll", 0x6fb7fc1cu, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10054" },
    { "D2Client.dll", 0x6fb7fca8u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10009" },
    { "D2Client.dll", 0x6fb7fca4u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10006" },
    { "D2Client.dll", 0x6fb7fcb8u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10015" },
    /* World tiles.  ord 10001 is the floor/wall blitter: nine arguments and
       two call sites, both in one region -- what a single tile loop looks
       like.  Kept traced because the visible-world limit turned out to be the
       room adjacency list, not anything these can be told. */
    { "D2Client.dll", 0x6fb7fc38u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10001" },
    { "D2Client.dll", 0x6fb7fc40u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10046" },
    { "D2Client.dll", 0x6fb7fc5cu, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10059" },
    { "D2Client.dll", 0x6fb7fc04u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10016" }
};
#define D2_HOOKS       33
#define D2_TAG_CLIENT  0u
#define D2_TAG_WIN     1u

/*
** How a drawer's coordinates are wrong, and so how to correct them.  cx is
** (W-800)/2 across; down it is H-600 for something anchored to the bottom or
** (H-600)/2 for something centred.
*/
#define ADJ_X_NONE   0
#define ADJ_X_ADD    1    /* x += cx : left-anchored, wants centring  */
#define ADJ_X_SUB    2    /* x -= cx : right-pinned, wants un-pinning */
#define ADJ_X_RIGHT  4    /* x += W-800 : belongs at the RIGHT edge, so it
                           * moves the whole difference, not half of it */
/*
** Pick the direction from which half of the screen the element is in.  Not a
** shortcut -- the only rule that fits: gfx#10067 at +0a7254 draws BOTH the
** left and the right orb icon from one call site (x=117 and x=1755), so a
** fixed direction is wrong for one of them whichever way it is written.  It
** agrees with the explicit modes at every position measured on hardware:
** 0->560, 1803->1243, 29->589, 1809->1249, 117->677, 1755->1195.
*/
#define ADJ_X_AUTO   3
#define ADJ_Y_NONE   0
#define ADJ_Y_BOTTOM 1    /* y += H-600     : raw 800x600, bottom-anchored */
#define ADJ_Y_CENTRE 2    /* y += (H-600)/2 : raw 800x600, centred         */

typedef struct {
    unsigned int  tag;      /* unused in matching; kept for readability */
    unsigned int  rva;      /* caller's return address, as an RVA */
    int           xlo;      /* x qualifier; xlo==xhi==0 means "any x" */
    int           xhi;
    int           ylo;      /* y qualifier; ylo==yhi==0 means "any y" */
    int           yhi;
    unsigned char xmode;
    unsigned char ymode;
    const char   *what;
} D2Fix2D;

static const D2Fix2D g_d2Fix2D[] = {
    /* control panel: frame, inlay, orb liquid and the icon beside each orb */

    /*
    ** The RIGHT-HAND panel: inventory and skill tree.
    **
    ** Its background image is positioned from the live screen width and
    ** lands correctly at the right edge; the frame over it and the
    ** equipped items inside it are not.  The frame's coordinates are
    ** hardcoded immediates -- `push 0x190` is the 400 -- so there is no
    ** global to correct and each site needs a row.
    **
    ** These move by W-800, not by cx: the panel is pinned to the RIGHT
    ** edge, so it travels the full difference rather than half of it.
    ** At 1432 that is 632 against cx's 316 -- getting this wrong leaves
    ** the frame exactly half way to where it belongs.
    */
    /*
    ** The side-panel BACKGROUNDS -- both of them, and the first rules in this
    ** table that move Y.
    **
    ** One function draws both panels, as five sprites each, at contiguous
    ** RVAs: the right-hand set below and the left-hand set after it.  At 600
    ** only the right one needed anything, because the left panel is anchored
    ** at x=0 and was already correct.
    **
    ** ADJ_Y_BOTTOM is new here and is what fixes the "background and
    ** foreground separate" at a height above 600.  Diablo II bottom-anchors
    ** the panel CONTENTS but leaves these backgrounds at stock y, and at 600
    ** those agree, so the whole vertical axis of this table has been a no-op
    ** for every fix until now (by = H-600 = 0).  Measured on the character
    ** screen at 2560x1080: frame at stock y 1..552, contents at 491..971,
    ** which is stock 11..491 plus exactly by=480.
    **
    ** The contents are the ones that are RIGHT.  At 600 the frame's bottom is
    ** 552 = 600-48, sitting exactly on the control panel; +by puts it at
    ** H-48 again, which is the same relationship at any height.  So the
    ** background moves and the contents are left alone.
    */
    { D2_TAG_CLIENT, 0x06d215u, 0, 0, 0, 0, ADJ_X_RIGHT, ADJ_Y_BOTTOM, "panel frame R" }, /* 400,63 */
    { D2_TAG_CLIENT, 0x06d237u, 0, 0, 0, 0, ADJ_X_RIGHT, ADJ_Y_BOTTOM, "panel frame R" }, /* 544,253 */
    { D2_TAG_CLIENT, 0x06d259u, 0, 0, 0, 0, ADJ_X_RIGHT, ADJ_Y_BOTTOM, "panel frame R" }, /* 713,484 */
    { D2_TAG_CLIENT, 0x06d27bu, 0, 0, 0, 0, ADJ_X_RIGHT, ADJ_Y_BOTTOM, "panel frame R" }, /* 544,553 */
    { D2_TAG_CLIENT, 0x06d29du, 0, 0, 0, 0, ADJ_X_RIGHT, ADJ_Y_BOTTOM, "panel frame R" }, /* 400,553 */
    /*
    ** The LEFT panel's five, x untouched: it is anchored at x=0 and stays
    ** there at any width, which is why these have never needed a row before.
    */
    { D2_TAG_CLIENT, 0x06d31cu, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "panel frame L" }, /* 256,63 */
    { D2_TAG_CLIENT, 0x06d2feu, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "panel frame L" }, /* 0,253 */
    { D2_TAG_CLIENT, 0x06d339u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "panel frame L" }, /* 0,484 */
    { D2_TAG_CLIENT, 0x06d356u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "panel frame L" }, /* 0,553 */
    { D2_TAG_CLIENT, 0x06d377u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "panel frame L" }, /* 256,553 */
    /*
    ** The QUEST LOG's contents.
    **
    ** The panel backgrounds above are shared by every side panel, but what
    ** goes inside them is not, and the panels do not agree about their own
    ** anchoring.  The character screen's contents were already bottom-
    ** anchored by the game, so moving its background was the whole fix.  The
    ** quest log's are not: its six icons arrive at stock y 181..283 while its
    ** frame now follows the screen, which left the icons stranded at the top.
    **
    ** X is untouched -- the quest log is anchored at x=0 and its contents come
    ** in at 102..300, already where they belong at any width.
    **
    ** Only the icons.  A third rule was here for +08da8b, the ACT TAB, and it
    ** was wrong: that draw arrives at y=573, which is its stock 93 plus the
    ** game's own 480, so it was already bottom-anchored and the rule shifted
    ** it a second time, off the bottom of the panel.
    **
    ** The mistake was the test used to sort the draws: "incoming y < 600 means
    ** stock".  It does not.  An element whose stock y is small is still under
    ** 600 after the game has bottom-anchored it -- 93 + 480 = 573 -- so the
    ** rule caught something that was already right.  What actually separates
    ** them is whether the value equals its own stock position, and the only
    ** way to know that is the unpatched layout: the tab sits at the TOP of the
    ** quest log at 800x600, so 573 could never have been its stock y.
    */
    { D2_TAG_CLIENT, 0x08dde5u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "quest icons"  },
    { D2_TAG_CLIENT, 0x08de5du, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "quest icons 2" },
    /* The quest TITLE and DESCRIPTION, left behind by the icons.  Both are
       D2Win text draws and both arrive at y 308 and 330..350 with by=480, so
       both are provably stock. */
    { D2_TAG_CLIENT, 0x08dfa7u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "quest title" },
    { D2_TAG_CLIENT, 0x08e00au, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "quest text"  },
    /*
    ** The rolling SPEECH text has NO rule here any more -- see the ybound row
    ** for +075aee.  One scroller (+074920) draws both the quest panel's
    ** speech and every NPC's dialog, from a box position in two globals, and
    ** a rule on its line draw (+074aa5) moved the NPC dialog down off its
    ** box while leaving the partial lines at the box's edges (D2Win#10146,
    ** unhooked) behind.  The box position is now corrected where the quest
    ** panel sets it, so everything drawn from it moves together.
    */
    /*
    ** The WAYPOINT panel's act tab and its "no other waypoints" line.
    **
    ** Its inner tiles (+03fd54..+03fded) and its scroll box (+03fff3, +040215)
    ** already arrive bottom-anchored, so the panel itself is fine; these two
    ** sit above it instead of inside it.
    **
    ** Note the quest log does the OPPOSITE with its own act tab: +08da8b comes
    ** in already anchored and must be left alone -- a rule on it was the bug
    ** that pushed the tab off the bottom.  The two panels are written by
    ** different code and neither can be assumed from the other.
    **
    ** Both of these arrive at y=94 and y=108 with by=120, and a value below by
    ** cannot be stock+by, so they are provably stock and safe to move.  The
    ** rest of the panel's draws are ambiguous by that test and are left alone
    ** until something is actually seen to be wrong.
    */
    { D2_TAG_CLIENT, 0x03ff72u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "waypoint tab"  },
    { D2_TAG_CLIENT, 0x0402a0u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "waypoint note" },
    /*
    ** The rest of the waypoint panel: its list and its close button.
    **
    ** These were ambiguous at 1680x720 -- with by=120 a value like 149 could
    ** have been stock 29 already anchored -- so they were left alone.  At
    ** 2560x1080 by is 480 and the same draws still arrive at 149, 144..249 and
    ** 477, all below by, which cannot be stock+by.  Provably stock, so they
    ** move.
    **
    ** Testing at a TALLER mode is what settled it: the larger by is, the more
    ** of the ambiguous band it resolves.
    */
    { D2_TAG_CLIENT, 0x0400f0u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "waypoint list bg" },
    { D2_TAG_CLIENT, 0x040158u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "waypoint list"    },
    { D2_TAG_CLIENT, 0x03fff3u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "waypoint close"   },
    /*
    ** The close button's CANCEL tooltip, x=347 beside the button at 353.
    **
    ** Read as "already anchored" the first time round and left out, because at
    ** 1680x720 its y of 445 could have been stock 325 plus by=120.  At
    ** 2560x1080 it still arrives at 445, well under by=480, so it was stock all
    ** along.  The ambiguous band shrinks as by grows -- which is the argument
    ** for diagnosing this class of bug at the tallest mode available.
    */
    { D2_TAG_CLIENT, 0x040215u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "waypoint cancel tip" },
    /*
    ** The HIRELING panel's text.
    **
    ** The panel (+09f250) positions everything from two layout globals set
    ** once at start-up -- [6fbcd354]=80 and [6fbcd358]=-60 in the 800x600
    ** layout -- but only its BACKGROUND also uses the screen height:
    **
    **     background   y = [6fbcd358] + H - 0xe0         follows the screen
    **     text         y = table_y - [6fbcd358] (- 2)    stock
    **
    ** so above 600 lines the text stayed where it was while the boxes it
    ** belongs in moved down by H-600.  Four DrawText calls, each in a helper
    ** called from +09f250 and nowhere else.  Rows are keyed on the RETURN
    ** address, the call site + 5:
    **
    **     call +094247  the hireling's name, y = 0xd6 - [6fbcd358]
    **     call +090a6a  the labels, from the table at 6fb83748 (x, x2, y, id)
    **     call +090ad3  the same labels' two-line arm, split at '\n'
    **     call +094121  the values, from the table at 6fb9e808 (x, x2, y, stat)
    **
    ** Its slot rects are stock for the same reason; Diablo2FixupMercPanel
    ** moves those.
    */
    { D2_TAG_CLIENT, 0x09424cu, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "merc name"    },
    { D2_TAG_CLIENT, 0x090a6fu, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "merc label"   },
    { D2_TAG_CLIENT, 0x090ad8u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "merc label 2" },
    { D2_TAG_CLIENT, 0x094126u, 0, 0, 0, 0, ADJ_X_NONE, ADJ_Y_BOTTOM, "merc value"   },
    /*
    ** The Horadric Cube's TRANSMUTE animation -- the flourish over the cube
    ** grid when a quest recipe succeeds (ui\menu\horadric, 30 frames at 70 ms,
    ** started by +094260).  The cube panel draws it at the SCREEN CENTRE:
    **
    **     +09dac7  y = H/2 - 1
    **     +09dadb  x = W/2
    **
    ** and the art's own frame offsets put it over the grid from the 800x600
    ** centre, (400, 299).  But the cube panel is pinned to the left edge in x
    ** and bottom-anchored in y, so the centre is the wrong reference at any
    ** other size: the animation landed cx too far right and only half of H-600
    ** down.  SUB and CENTRE together give back exactly (400, 299 + H-600).
    */
    { D2_TAG_CLIENT, 0x09daf0u, 0, 0, 0, 0, ADJ_X_SUB,  ADJ_Y_CENTRE, "cube horadric anim" },
    /*
    ** The WEAPON-SWAP tooltip ("Swap Weapons: W") over the inventory's I/II
    ** tabs.  Drawn from constants inside the item-tooltip code:
    **
    **     +097dca  x = 0x170 or 0x258, + [6fbcd354]   left / right tab centre
    **     +097dde  y = 0x15 - [6fbcd358]
    **
    ** Stock on both axes, in a panel pinned to the RIGHT edge and moved down
    ** by H-600.  Which of the two x values is chosen is itself a stock test
    ** of the mouse against 500 -- see Diablo2FixupSwapTip.
    */
    { D2_TAG_CLIENT, 0x097df7u, 0, 0, 0, 0, ADJ_X_RIGHT, ADJ_Y_BOTTOM, "weapon swap tip" },

    { D2_TAG_CLIENT, 0x09e0e2u, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 535,217 */
    { D2_TAG_CLIENT, 0x09e127u, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 536,263 */
    { D2_TAG_CLIENT, 0x09e16cu, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 651,290 */
    { D2_TAG_CLIENT, 0x09e1b0u, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 535,118 */
    { D2_TAG_CLIENT, 0x09e1f5u, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 420,292 */
    { D2_TAG_CLIENT, 0x09e23au, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 609,118 */
    { D2_TAG_CLIENT, 0x09e27fu, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 495,263 */
    { D2_TAG_CLIENT, 0x09e2c4u, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 609,263 */
    { D2_TAG_CLIENT, 0x09e393u, 0, 799, 0, 0, ADJ_X_RIGHT, ADJ_Y_NONE, "equip slot" },    /* 651,217 */

    { D2_TAG_CLIENT, 0x06d54eu, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb frame L"  },
    { D2_TAG_CLIENT, 0x06d62bu, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb frame R"  },
    { D2_TAG_CLIENT, 0x06df5au, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb inlay L"  },
    { D2_TAG_CLIENT, 0x06ddd3u, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb inlay R"  },
    { D2_TAG_CLIENT, 0x06df2du, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb liquid L" },
    { D2_TAG_CLIENT, 0x06dda2u, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb liquid R" },
    /*
    ** The POTION FILL: the band that creeps up the orb while a healing or
    ** mana potion is still being absorbed.
    **
    ** A SECOND gfx#10082 draw per orb, from the same pair of functions as the
    ** liquid and with the same argument shape -- x in arg 1, y in arg 2 -- but
    ** it was missed because it is drawn only while a potion is working, so it
    ** is absent from any trace taken while standing still.
    **
    ** The two arms are written differently, which is the same asymmetry the
    ** rest of the control panel shows:
    **
    **   left  6fb1deb3  push 0x1c        x = 28, a constant
    **   right 6fb1dd62  add ecx,-0x70    x = W-112, off the live width
    **
    ** Neither is where the art belongs.  The panel is 800 wide and CENTRED, so
    ** the right orb lives at (W-800)/2 + 688, not hard against the screen's
    ** right edge, and the left one is 300 in from a corner it no longer sits
    ** in.  AUTO reads that off the position itself: 28 moves +cx, W-112 moves
    ** -cx, exactly as the liquid rules above already do.
    **
    ** The right one is included on the strength of the code, not a screenshot.
    ** A mana potion is rarer than a healing one, so it had simply not been
    ** tried -- section 9: the arm nobody exercised is still an arm.
    */
    { D2_TAG_CLIENT, 0x06ded2u, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb potion L" },
    { D2_TAG_CLIENT, 0x06dd75u, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb potion R" },
    { D2_TAG_CLIENT, 0x0a7254u, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE,   "orb icon L+R" },
    /*
    ** +05f597, the SHARED item helper, now has NO rules at all -- and that is
    ** the point, not an omission.
    **
    ** Every family of item that reaches this one call site is corrected at its
    ** own SOURCE, so by the time a draw arrives here it is already right:
    **
    **   inventory grid items    the grid origin, descriptor 6fbb16f0
    **   equipped items          the ten slot rects at 6fbccba0
    **   belt items              Diablo2InstallBeltHook, D2Common ord#10689
    **   stash / cube / vendor   left-hand panels, correct untouched
    **   the item ON THE CURSOR  drawn at the live mouse, already right
    **
    ** Three rules used to live here.  Two were belt rules, replaced by the
    ** belt hook.  The last was `inv equip item` -- x 0..799, y 0..499, plus
    ** (W-800) -- which predates the descriptor fixes and had become redundant
    ** for the items it was written for, while still firing on the item BEING
    ** DRAGGED.  That item is drawn from +014e6c and +014ff7, at the mouse
    ** (x = [6fbcc950] + [6fbcc954] - w/2), through this same helper.  So the
    ** moment a drag crossed x=800 with y<500 the rule matched and threw the
    ** item 600px right, to the screen edge, where it then followed the mouse
    ** at that offset.  It would have done the same to stash and cube items,
    ** which draw at x=100..198.
    **
    ** The lesson this file keeps relearning: a rule keyed on a SHARED call
    ** site plus a coordinate window is a catch-all, and a catch-all fires for
    ** the case nobody thought of.  An element that FOLLOWS THE CURSOR cannot
    ** be qualified by coordinates at all, because it visits all of them.
    ** Correct at the source, or do not correct.
    **
    ** No instrument is left behind for this one: whether the rule was still
    ** doing something is answered by looking at the character panel.  If the
    ** equipped items are in their slots, the descriptors are carrying them and
    ** the rule was dead.  A probe would have been worse than useless here --
    ** the dragged item passes through the equip band too, so it would fire on
    ** exactly the case the rule was wrong about.
    */


    /* The orb tooltip's own x is hardcoded too -- `mov edx,0x41` is the stock
       orb centre, 65 -- so the string needs moving even once its hover region
       has.  AUTO rather than ADD: if the mana orb shares this call site, the
       right-hand one has to travel the other way. */
    { D2_TAG_CLIENT, 0x06d7b8u, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE, "life tooltip" },

    /* The mana tooltip is a SEPARATE call site: its x is W - width/2 - 80,
       computed from the live screen width, so it lands hard against the
       right edge rather than at a stock constant.  AUTO sends it back in
       by cx, matching the orb it belongs to. */
    { D2_TAG_CLIENT, 0x06d877u, 0, 0, 0, 0, ADJ_X_AUTO, ADJ_Y_NONE, "mana tooltip" }

    /*
    ** The skill-selection popup has NO rule here, on purpose.
    **
    ** Moving its draw (+0a7160, one call site drawing both sides) worked
    ** visually and broke picking a skill: the entries stopped being
    ** selectable, because the hit test stayed where the art used to be.
    **
    ** It is corrected at the source instead -- Diablo2FixupSkillPopup moves
    ** the starting x handed to the layout function, which draws, hit-tests
    ** and selects from that one value, so they cannot disagree.  A rule here
    ** as well would move the art a second time.
    */
};
#define D2_FIX2D_N (sizeof(g_d2Fix2D) / sizeof(g_d2Fix2D[0]))

static int            g_d2Trace    = 0;
static int            g_d2Menu     = 1;   /* centre the front end */
static int            g_d2InvGrid  = 1;   /* move the inventory grid origin */
static int            g_d2Belt     = 1;   /* shift the belt slot rects       */
static int            g_d2FrontEnd = 0;   /* front end up -- see GameFix_Tick */
static unsigned int   g_d2Frame     = 0;   /* grBufferSwap count, for the below */
static unsigned int   g_d2CliDrawn  = 0;   /* last frame D2Client drew anything */
static unsigned int   g_d2Real[D2_HOOKS];
static unsigned char *g_d2Stub[D2_HOOKS];

/*
** Trace budget, allocated PER CALL SITE rather than globally.
**
** A single global pool does not work: one caller (a rectangle blitter at
** D2Client+04afaf, which turned out to be the rain) produced 222 of 400
** records on its own and crowded out everything after it -- including the two
** elements being looked for.  That is section 6's "deduplicate, or the buffer
** floods", and the fix is to give every site the same small allowance so
** breadth beats depth.
*/
#define D2_TRACE_SITES   200u
#define D2_TRACE_PERSITE 3u

static unsigned int  g_traceSite[D2_TRACE_SITES];
static unsigned char g_traceHits[D2_TRACE_SITES];
static unsigned int  g_traceSites = 0;
static unsigned int  g_traceEvery = 0;   /* frames between budget re-arms */

/*
** The watch box.
**
** The per-site budget answers "what draws exist", but an element you can SEE
** on screen can still be missing from the log: its call site shares an RVA
** with something that draws constantly, so the three samples are gone before
** the interesting draw happens.  That is how the item tooltip stayed invisible
** to the trace while sitting in plain view in a screenshot.
**
** So: name a rectangle from the screenshot and every draw landing in it is
** logged, budget or no budget.  It is the one instrument that starts from
** where the pixels are rather than from which function drew them.
**
** [Diablo2] watchbox=x0,y0,x1,y1   (empty or 0,0,0,0 = off)
*/
#define D2_BOX_MAX     600u
/*
** Per call site, so one busy site cannot own the budget.
**
** Raised from 4 to 32.  Four is right for a CENSUS -- "which call sites draw
** here" -- but useless for the opposite question, "what range of positions
** does ONE site use".  The quest log's scrolling speech draws two lines from
** +074aa5 and the box logged the same y four times, so whether the other line
** comes from a different y was invisible.  Keep the RECTANGLE tight and let a
** site report properly; that is the trade that answers per-site questions.
*/
#define D2_BOX_PERSITE 32u
static int          g_box[4] = { 0, 0, 0, 0 };
static int          g_boxOn  = 0;
static unsigned int g_boxHits = 0;
static unsigned int g_boxSite[64];
static unsigned char g_boxSiteHits[64];
static unsigned int g_boxSites = 0;

/*
** The box needs its own per-site budget as much as the trace does.
**
** Aimed at the control panel it filled its 400 records with the same dozen
** panel draws -- 65 hits apiece -- and the element actually being looked for
** never got a line.  A global cap answers "what draws here" only until one
** busy site drowns the rest.
*/
static int BoxAllow(unsigned int tag, unsigned int rva)
{
    unsigned int id = (tag << 24) ^ (rva & 0xffffffu);
    unsigned int i;

    for (i = 0; i < g_boxSites; i++) {
        if (g_boxSite[i] != id) continue;
        if (g_boxSiteHits[i] >= (unsigned char)D2_BOX_PERSITE) return 0;
        g_boxSiteHits[i]++;
        return 1;
    }
    if (g_boxSites >= 64u) return 0;
    g_boxSite[g_boxSites] = id;
    g_boxSiteHits[g_boxSites] = 1;
    g_boxSites++;
    return 1;
}

/*
** Hand every site its allowance back.
**
** A per-site budget answers "which call sites exist", but not "what does this
** site do LATER".  A panel opened a minute into the session is drawn from a
** shared helper whose three samples went in the first second on something
** else, so the draw that matters is silent exactly when you need it -- which
** is what hid the inventory frame.
**
** [Diablo2] traceevery=N re-arms every site every N frames, turning the trace
** from a one-shot census into a repeating window: open a panel, wait a window,
** read its draws.  The site LIST is kept, so identity stays stable.
*/
static void TraceRearm(void)
{
    unsigned int i;
    for (i = 0; i < g_traceSites; i++) g_traceHits[i] = 0;
}

/* Returns non-zero while this site still has allowance left. */
static int TraceAllow(unsigned int tag, unsigned int rva)
{
    unsigned int id = (tag << 24) ^ (rva & 0xffffffu);
    unsigned int i;

    for (i = 0; i < g_traceSites; i++) {
        if (g_traceSite[i] != id) continue;
        if (g_traceHits[i] >= (unsigned char)D2_TRACE_PERSITE) return 0;
        g_traceHits[i]++;
        return 1;
    }
    if (g_traceSites >= D2_TRACE_SITES) return 0;
    g_traceSite[g_traceSites] = id;
    g_traceHits[g_traceSites] = 1;
    g_traceSites++;
    return 1;
}

/*
** A poor man's backtrace, for the trace only.
**
** Some elements are positioned by a caller further up than the hook sees: the
** belt potion is drawn from inside an item-draw helper with 78 call sites, so
** the immediate return address says nothing about which one is the belt.
**
** There are no frame pointers to walk, so this scans the stack above the
** argument block for values that point into the module's code AND have a CALL
** immediately before them.  A heuristic: it can report a stale value that
** merely looks like a return address.  Fine for pointing the reading at the
** right function; not something to patch on the strength of alone.
*/
#define D2_WALK_DEPTH  64u
#define D2_WALK_REPORT 3u

static int LooksLikeRet(HMODULE mod, unsigned int base, unsigned int va)
{
    unsigned int probe = 0;

    if (va < base + 0x1000u) return 0;
    if (!ReadLive(mod, va - 8u, &probe)) return 0;
    if (!ReadLive(mod, va - 4u, &probe)) return 0;

    if (*(const unsigned char *)(va - 5u) == 0xe8) return 1;
    if (*(const unsigned char *)(va - 6u) == 0xff) return 1;
    if (*(const unsigned char *)(va - 2u) == 0xff) return 1;
    if (*(const unsigned char *)(va - 3u) == 0xff) return 1;
    return 0;
}

static unsigned int WalkCallers(const D2Hook *h, int *args, unsigned int *out)
{
    HMODULE      mod = GetModuleHandleA(h->module);
    unsigned int base, n = 0, i;

    if (!mod) return 0;
    base = (unsigned int)mod;

    for (i = 0; i < D2_WALK_DEPTH && n < D2_WALK_REPORT; i++) {
        unsigned int v = (unsigned int)args[i];
        if (!LooksLikeRet(mod, base, v)) continue;
        out[n++] = v - base;
    }
    return n;
}

/*
** Called from the stub with pointers to the caller's saved registers and to
** its pushed arguments -- both still live on its stack, so a correction is a
** write to a stack slot and the callee never knows.  cdecl: the stub cleans up.
*/
static void __cdecl D2Dispatch(unsigned int tag, unsigned int ra,
                               int *regs, int *args)
{
    const D2Hook *h;
    unsigned int  rva, i;
    int           cx, by, cy;
    int          *px = NULL, *py = NULL;
    int           x0 = 0, y0 = 0;
    int           applied = 0;
    const char   *what = NULL;
    unsigned int  up[D2_WALK_REPORT];
    unsigned int  nu = 0;

    if (tag >= (unsigned int)D2_HOOKS || !args || !regs) return;
    h   = &g_d2Hooks[tag];
    rva = ra - h->base;

    /*
    ** Note that D2Client drew.  This is what tells the front end apart from a
    ** game in progress -- see GameFix_Tick.  One store, no calls: this runs
    ** hundreds of times a frame.
    */
    if (h->base == 0x6fab0000u) g_d2CliDrawn = g_d2Frame;

    if (h->xarg != ARG_NONE)
        px = (h->xarg & ARG_REG) ? &regs[h->xarg & 0x0fu] : &args[h->xarg];
    if (h->yarg != ARG_NONE)
        py = (h->yarg & ARG_REG) ? &regs[h->yarg & 0x0fu] : &args[h->yarg];
    if (px) x0 = *px;
    if (py) y0 = *py;

    cx = ((int)g_targetW - 800) / 2;
    by =  (int)g_targetH - 600;
    cy = ((int)g_targetH - 600) / 2;

    if (px && py) {
        /*
        ** The front end is a fixed-pixel 800x600 island (section 37), so all
        ** of it moves together rather than element by element.  Gated on
        ** D2Client being absent, which is exactly true while the front end is
        ** up: every D2Win draw in the trace happened before D2Client loaded
        ** and none after.
        */
        if (h->base == 0x6f8e0000u) {
            /* Keyed on the MODULE, not on one tag: the front end reaches the
               renderer through more than one D2Win slot -- DrawImage for the
               art and gfx#10067 for every glyph -- and both have to move by
               the same amount or the labels slide off their buttons. */
            if (g_d2Menu && g_d2FrontEnd) {
                *px += cx; *py += cy; applied = 1; what = "menu";
            }
        } else if (h->base == 0x6fab0000u) {
            /* Matched on the caller's RVA alone: an RVA is unique within the
               module, so keying on the hook index too would only make the
               table fragile against reordering the hook list. */
            for (i = 0; i < D2_FIX2D_N; i++) {
                if (g_d2Fix2D[i].rva != rva) continue;
                if (g_d2Fix2D[i].xhi != 0 &&
                    (*px < g_d2Fix2D[i].xlo || *px > g_d2Fix2D[i].xhi)) continue;
                if (g_d2Fix2D[i].yhi != 0 &&
                    (*py < g_d2Fix2D[i].ylo || *py > g_d2Fix2D[i].yhi)) continue;
                switch (g_d2Fix2D[i].xmode) {
                case ADJ_X_ADD:  *px += cx; break;
                case ADJ_X_SUB:  *px -= cx; break;
                case ADJ_X_RIGHT: *px += (int)g_targetW - 800; break;
                case ADJ_X_AUTO:
                    *px += (*px * 2 < (int)g_targetW) ? cx : -cx; break;
                default: break;
                }
                if (g_d2Fix2D[i].ymode == ADJ_Y_BOTTOM) *py += by;
                if (g_d2Fix2D[i].ymode == ADJ_Y_CENTRE) *py += cy;
                applied = 1;
                what = g_d2Fix2D[i].what;
                break;
            }
        }
    }

    /*
    ** Logged AFTER the correction, reporting both values.
    **
    ** Section 6: verify the instrument reports what the FIX did, not just what
    ** the game asked.  Logging only the incoming arguments made "the rule
    ** never matched", "it matched and moved the wrong argument" and "it moved
    ** the right one and the element is still wrong" look identical, which cost
    ** a round trip.
    */
    /*
    ** The watch box first, and outside the budget: the whole point is to see
    ** draws the budget is hiding.
    **
    ** Reports the incoming position AND the outgoing one.  Incoming is what a
    ** rule has to match on, but incoming alone cannot tell "the rule fired and
    ** moved it" from "the rule fired and the edit did not reach the game" --
    ** and that is exactly the state the quest log's scrolling speech is in: the
    ** box says `(96,427) -> already fixed`, and the text still renders at 427.
    ** Section 6 of GAME-PATCHING.md, which this file has quoted at itself
    ** before: log what the FIX did, not what the game asked.
    */
    if (g_boxOn && g_boxHits < D2_BOX_MAX && px && py &&
        !g_d2FrontEnd &&           /* the FRONT END, for the same reason as the
                                    * rain below.  Raising the per-site cap to
                                    * 32 let nine menu sites take 288 of the
                                    * 400 records before the game had even
                                    * loaded, and the in-game draw being hunted
                                    * never got logged at all.  Nothing in the
                                    * menu is ever the subject of an in-game
                                    * hunt, so it is excluded outright. */
        rva != 0x04afafu &&        /* the rain: hundreds of lines a frame, and
                                    * it once ate 222 of a 400-record budget */
        x0 >= g_box[0] && x0 <= g_box[2] &&
        y0 >= g_box[1] && y0 <= g_box[3] &&
        BoxAllow(tag, rva)) {
        g_boxHits++;
        GameFix_Log("WATCH %-14s +%06x  (%d,%d) -> (%d,%d)%s%s",
                    h->label, rva, x0, y0, *px, *py,
                    applied ? "  fixed: " : "", applied ? what : "");
    }

    if (g_d2Trace && TraceAllow(tag, rva)) {
        nu = WalkCallers(h, args, up);

        if (applied) {
            GameFix_Log("draw %-14s +%06x  (%d,%d) -> (%d,%d)  [%s]",
                        h->label, rva, x0, y0, *px, *py, what);
        } else {
            GameFix_Log("draw %-14s +%06x  %d %d %d %d %d %d %d %d",
                        h->label, rva, args[0], args[1], args[2], args[3],
                        args[4], args[5], args[6], args[7]);
        }

        if (nu)
            GameFix_Log("     via +%06x +%06x +%06x", up[0],
                        (nu > 1) ? up[1] : 0, (nu > 2) ? up[2] : 0);
    }
}

/*
** The stub, hand-assembled so it needs neither naked functions nor inline asm
** -- and so it can be disassembled and checked before shipping (section 5).
**
** After pushad+pushfd the caller's frame sits 36 bytes up: the return address
** at +0x24 and the first argument at +0x28, with the saved registers filling
** the block below.  Each push shifts what remains, which is why the two
** displacements are both 0x28 and mean different things.  Pointers are passed
** rather than values so the dispatcher edits in place; the arguments live
** ABOVE the pushad block, so popad cannot undo an argument edit, and a
** register edit is applied precisely BECAUSE popad restores it.  The
** tail-jump leaves the real callee to clean up, which is right because these
** exports are all stdcall.
*/
static void Diablo2InstallDrawHook(void)
{
    static const unsigned char tmpl[] = {
        0x60,                         /* pushad                      */
        0x9c,                         /* pushfd                      */
        0x8d, 0x44, 0x24, 0x28,       /* lea  eax,[esp+0x28] ; &arg0 */
        0x50,                         /* push eax                    */
        0x8d, 0x44, 0x24, 0x04,       /* lea  eax,[esp+4]    ; &regs */
        0x50,                         /* push eax                    */
        0xff, 0x74, 0x24, 0x2c,       /* push [esp+0x2c]     ; ret   */
        0x68, 0, 0, 0, 0,             /* push tag                    */
        0xb8, 0, 0, 0, 0,             /* mov  eax, D2Dispatch        */
        0xff, 0xd0,                   /* call eax                    */
        0x83, 0xc4, 0x10,             /* add  esp,16                 */
        0x9d,                         /* popfd                       */
        0x61,                         /* popad                       */
        0xff, 0x25, 0, 0, 0, 0        /* jmp  [g_d2Real[tag]]        */
    };
    unsigned int i;

    for (i = 0; i < (unsigned int)D2_HOOKS; i++) {
        HMODULE        mod;
        unsigned int   slotVal = 0;
        unsigned char *stub;

        if (g_d2Stub[i]) continue;

        mod = GetModuleHandleA(g_d2Hooks[i].module);
        if (!mod) continue;
        if (!ReadModuleGlobal(mod, g_d2Hooks[i].slot, &slotVal)) continue;
        if (!slotVal) continue;

        stub = (unsigned char *)VirtualAlloc(NULL, sizeof(tmpl),
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
        if (!stub) {
            GameFix_Log("2dfix: VirtualAlloc failed for %s",
                        g_d2Hooks[i].label);
            continue;
        }

        g_d2Real[i] = slotVal;
        memcpy(stub, tmpl, sizeof(tmpl));
        PutU32(stub + 17, i);
        PutU32(stub + 22, (unsigned int)&D2Dispatch);
        PutU32(stub + 35, (unsigned int)&g_d2Real[i]);

        if (!WriteModuleGlobal(mod, g_d2Hooks[i].slot, (unsigned int)stub)) {
            GameFix_Log("2dfix: could not write slot for %s",
                        g_d2Hooks[i].label);
            VirtualFree(stub, 0, MEM_RELEASE);
            continue;
        }

        g_d2Stub[i] = stub;
        GameFix_Log("2dfix: hooked %-14s real=%08lx stub=%08lx",
                    g_d2Hooks[i].label, (unsigned long)slotVal,
                    (unsigned long)(unsigned int)stub);
    }
}

/*
** Force D2Client's live screen size, once, if it is stale.
**
** The four D2Client patches are correct and land cleanly -- and they are still
** too late.  D2Client.dll is not imported by anything; it is LoadLibrary'd
** part way through startup and calls SetResolutionMode from its own init
** immediately, while our per-frame probe cannot notice the module until the
** next grBufferSwap.  By the time the code is patched the one call that used
** it has already happened, and nothing calls it again unless the player
** changes resolution.  The result on screen is a world drawn at the full size
** -- that comes from the RENDERER's globals via D2gfx ordinal 10023 -- with
** the HUD and the mouse still living on an 800x600 screen in the corner.
**
** So the patch fixes the code and this fixes the state it already produced.
** Both are needed: the patch keeps any later call correct, and this corrects
** the call that got away.
**
** These are exactly the writes SetResolutionMode's own arm performs, with the
** viewport height as the game computes it (H-40, its rule at both stock
** modes).  Its trailing notify call is deliberately not reproduced -- we
** cannot know what it caches -- and that is tolerable because D2Client is
** strongly parametric here: it reads these two globals 389 and 350 times and
** re-derives layout from them per frame.
*/
/*
** Force D2Client's live screen size, once, if it is stale.
**
** The four D2Client patches are correct and still too late: D2Client.dll is
** LoadLibrary'd part way through startup and calls SetResolutionMode from its
** own init, while our per-frame probe cannot notice the module until the next
** grBufferSwap.  By then the one call that used it has happened, and nothing
** calls it again unless the player changes resolution.  So the patch keeps any
** later call correct and this corrects the call that got away.
**
** These are exactly the writes SetResolutionMode's own arm performs, with the
** viewport height as the game computes it (H-40, its rule at both stock
** modes).  Its trailing notify call is deliberately not reproduced -- we
** cannot know what it caches -- and that is tolerable because D2Client is
** strongly parametric here: it reads these globals hundreds of times and
** re-derives layout from them per frame.
**
** DO NOT inflate the viewport pair to try to widen the visible world.  That
** was tried: 25% showed the world ending sooner, 50% lost noticeable chunks,
** and 100% left the floor drawn only in the upper-left with objects -- tents,
** NPCs, the player -- still correctly placed out in the black.  The floor
** layer had come unstuck from everything else, which is the tell that this
** pair is a POSITION input to the floor's screen origin, not a size.  It never
** drew more world; it only slid the floor off-register.
**
** That also explains the apparent win when this fixup first went in.  Measured
** off the screenshots the black went from 45.4% to 5.6%, which looked like a
** bigger draw range; it was the floor snapping back into alignment, plus the
** two shots being taken at different spots.  The real bound on visible world
** is the room adjacency list from D2Common ord 10395 -- four instructions
** returning a room's precomputed neighbours -- and reaching past it means
** touching game state, not presentation.
*/
/*
** Dump D2Client's panel GRID descriptors.
**
** The inventory's art and its clickable cells had parted company: we moved the
** panel to the right edge, but the blue/green overlay the game paints under
** the cursor -- which IS the hit-test grid -- stayed at 800x600 coordinates.
** No draw rule can reconcile that; the game's own idea of where the grid lives
** has to move.
**
** The item draw shows where that idea comes from.  At +099f48:
**
**     mov   edx,[esi+0x04]        ; grid origin X
**     mov   ecx,[esi+0x0c]        ; grid origin Y
**     movzx ecx,BYTE [esi+0x14]   ; cell width
**     movzx eax,BYTE [esi+0x15]   ; cell height
**     x = originX + col*cellW ;  y = originY + row*cellH
**
** and esi is one of seven static descriptors chosen by panel type.  They live
** past the end of D2Client's raw .data, so they are zero in the file and are
** filled at run time -- which is why they can only be read here, and why they
** can be corrected here too.
**
** Dumped before anything is written: which descriptor is the inventory, and
** which belong to the stash, cube and vendor, is a question for the log rather
** than for a guess.  Shifting the wrong one moves a panel that was correct.
*/
/*
** Move the EQUIPMENT slot rectangles.
**
** Same fault as the inventory grid, one level up: the equipped items were
** painted in the right place by draw rules while their click areas stayed at
** 800x600 coordinates, so an item was visible in one place and pickable in
** another.
**
** The slot draw shows where the coordinates come from -- a per-slot base plus
** a small per-slot nudge:
**
**     x = [0x6fb9e730] + [0x6fbccc58]     ; nudge + base
**     y = [0x6fb9e734] + [0x6fbccc64]
**
** The nudges are the -1s and -2s at 0x6fb9e7xx and are not the problem.  The
** bases are ten descriptors at 0x6fbccba0, stride 0x14, laid out exactly like
** the inventory grid's: x at +4, y at +0xc.  Ten is the number of equipment
** slots Diablo II has, which is the check that the stride is right.
**
** Guarded on the x still being in the STOCK RIGHT-PANEL band.  That is what
** makes it both idempotent and self-selecting: a descriptor already moved
** reads >= 800 and is skipped, and anything belonging to a left-hand panel
** sits at 100..200 and is never touched.  Blind-patching a table by index is
** how a panel that was correct gets moved.
*/
#define D2_EQUIP_BASE   0x6fbccba0u
#define D2_EQUIP_STRIDE 0x14u
#define D2_EQUIP_N      10u

/*
** Shift one descriptor PAIR, once, whatever the width happens to be.
**
** The guard used to be a band -- "only if x is still under 800" -- on the
** assumption that one shift always carries the value out of the stock range.
** At 1400 wide it does: 419 + 600 = 1019.  At 960 wide the shift is only 160,
** so 419 -> 579 -> 739 -> 899 and the fixup, which runs every 30 frames, kept
** moving the grid until it happened to clear 800.  On screen the inventory
** items started left of their slots, snapped into place, then slid out to the
** right: three passes, exactly as the log recorded them.
**
** So remember what was WRITTEN instead of guessing from the value.  A field
** holding the value we last wrote is already ours and is left alone; anything
** else is a fresh fill by the game and gets shifted.  That is idempotent for
** any width, and still tracks the descriptors being repopulated.
**
** Both halves move or neither does.  A half-moved box gives "x >= 1051 &&
** x <= 709", which nothing satisfies, and the panel stops responding entirely
** -- this file has paid for that lesson once already.
*/
static int ShiftPair(HMODULE mod, unsigned int vaA, unsigned int vaB,
                     unsigned int delta, unsigned int *lastA, unsigned int *lastB,
                     unsigned int *fromA, unsigned int *fromB)
{
    unsigned int a = 0, b = 0;

    if (!delta) return 0;                       /* 600 lines: nothing to do */
    if (!ReadModuleGlobal(mod, vaA, &a)) return 0;
    if (!ReadModuleGlobal(mod, vaB, &b)) return 0;
    if (a == 0u || b <= a || (b - a) > 1024u) return 0;   /* empty or junk */
    if (a == *lastA && b == *lastB) return 0;            /* already ours */

    *fromA = a; *fromB = b;
    if (!WriteModuleGlobal(mod, vaA, a + delta)) return 0;
    if (!WriteModuleGlobal(mod, vaB, b + delta)) {
        WriteModuleGlobal(mod, vaA, a);         /* never leave it half moved */
        return 0;
    }
    *lastA = a + delta;
    *lastB = b + delta;
    return 1;
}

static void Diablo2FixupEquipSlots(void)
{
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    unsigned int i, base, a, b, moved = 0;
    unsigned int d  = g_targetW - 800u;
    unsigned int dy = (g_targetH > 600u) ? (g_targetH - 600u) : 0u;
    static unsigned int last[D2_EQUIP_N][4];

    if (!cli || !g_d2InvGrid || g_targetW <= 800u) return;

    for (i = 0; i < D2_EQUIP_N; i++) {
        base = D2_EQUIP_BASE + i * D2_EQUIP_STRIDE;

        if (ShiftPair(cli, base + 0x04u, base + 0x08u, d,
                      &last[i][0], &last[i][1], &a, &b)) {
            GameFix_Log("  equip slot %u: x %u..%u -> %u..%u", i, a, b,
                        a + d, b + d);
            moved++;
        }
        /* Y as well above 600 lines: the panel these sit in is bottom
           anchored and they are not, which left the equipped items at the top
           of the screen while their panel moved down. */
        if (ShiftPair(cli, base + 0x0cu, base + 0x10u, dy,
                      &last[i][2], &last[i][3], &a, &b))
            GameFix_Log("  equip slot %u: y %u..%u -> %u..%u", i, a, b,
                        a + dy, b + dy);
    }
    if (moved) GameFix_Log("equipslots: moved %u of %u", moved, D2_EQUIP_N);
}

/*
** The HIRELING panel, Y only.
**
** Its layout comes from the same loader as the player's (+093280, lazy: it
** refills only when the 800-layout flag changes), as inventory record 0x0d:
**
**     6fbb1670   panel rect          L,R,T,B        D2Common#10770
**     6fbb1728   grid info           as kGridDesc   D2Common#10964
**     6fbccc80   ten slot rects      as D2_EQUIP_BASE, one per body location,
**                                    D2Common#10441
**
** The slot rects are what place everything in the top half of the panel: the
** items (+099320 centres each in its rect), the empty-slot silhouettes
** (+08f6c0 draws at the rect's x and bottom), and the hover and click tests
** that walk the same array from 0x6fbccc70.  All are stock 800x600
** positions, while the panel's own background is drawn from the live screen
** height (+09f250: y = H - 0xe0 + [6fbcd358]) -- so above 600 lines the items
** hung at the top of the screen over an empty panel.
**
** X is left alone: the panel is anchored at x=0 at any width.  The slots
** that a hireling does not have come back empty and ShiftPair skips them.
*/
#define D2_MERC_SLOTS   0x6fbccc80u
#define D2_MERC_PANEL_T 0x6fbb1678u
#define D2_MERC_PANEL_B 0x6fbb167cu
#define D2_MERC_GRID    0x6fbb1728u

static void Diablo2FixupMercPanel(void)
{
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    unsigned int i, base, a, b;
    unsigned int dy = (g_targetH > 600u) ? (g_targetH - 600u) : 0u;
    static unsigned int lastS[D2_EQUIP_N][2];
    static unsigned int lastP[2], lastG[2];

    if (!cli || !g_d2InvGrid || !dy) return;

    for (i = 0; i < D2_EQUIP_N; i++) {
        base = D2_MERC_SLOTS + i * D2_EQUIP_STRIDE;
        if (ShiftPair(cli, base + 0x0cu, base + 0x10u, dy,
                      &lastS[i][0], &lastS[i][1], &a, &b))
            GameFix_Log("  merc slot %u: y %u..%u -> %u..%u", i, a, b,
                        a + dy, b + dy);
    }

    if (ShiftPair(cli, D2_MERC_PANEL_T, D2_MERC_PANEL_B, dy,
                  &lastP[0], &lastP[1], &a, &b))
        GameFix_Log("merc: panel rect y %u..%u -> %u..%u", a, b, a + dy, b + dy);

    if (ShiftPair(cli, D2_MERC_GRID + 0x0cu, D2_MERC_GRID + 0x10u, dy,
                  &lastG[0], &lastG[1], &a, &b))
        GameFix_Log("merc: grid y %u..%u -> %u..%u", a, b, a + dy, b + dy);
}

/*
** Move the INVENTORY grid, origin and all.
**
** This is the one correction so far that is not a draw hook, and it has to be:
** the blue/green overlay Diablo II paints under the cursor is not decoration,
** it is the hit-test grid.  Shifting only the art left the clickable cells at
** 800x600 coordinates -- the item was drawn in one place and could be picked
** up in another.  No number of draw rules reconciles that; the game's own idea
** of where the grid lives is what has to move.
**
** The dump identified it beyond doubt.  Of the seven panel descriptors,
** 6fbb16f0 holds originX=419, originY=315, 29x29 cells, and every traced item
** lands exactly on that lattice:
**
**     (680,401) -> col 9 row 3      (651,404) -> col 8 row 3
**     (680,430) -> col 9 row 4
**
** The other six sit at x=100..198 -- the LEFT-hand panels, stash and cube and
** vendor, which are already correct and must not be touched.  That is why the
** descriptor is named rather than searched for.
**
** 419 is 19 inside the stock panel's left edge of 400; our panel starts at
** 1032, so the origin belongs at 1051 -- which is also 419 + (W-800).  The two
** derivations agreeing is the check that this is the right constant.
**
** Guarded on the value still being the stock one, so it is idempotent: the
** descriptors are filled lazily and may be repopulated, and adding the shift
** twice would put the grid off the right of the screen.
*/
#define D2_INV_GRID   0x6fbb16f0u
/*
** The PANEL gate, which sits in front of everything else.
**
**     6fb40660:  cmp x,[6fbb1608] jl reject   ; panel left
**                cmp x,[6fbb160c] jge reject  ; panel right
**                cmp y,[6fbb1610] jl reject   ; panel top
**                cmp y,[6fbb1614] jg reject   ; panel bottom
**
** No inner rectangle is consulted unless this passes.  Moving the grid and the
** slot rects while leaving this behind is what made the inventory stop
** responding ANYWHERE: over the panel the gate rejected, and over the old
** position the gate passed but the inner rects had moved out from under it.
** A gate that fails closed hides every correction behind it.
*/
#define D2_INV_PANEL_L 0x6fbb1608u
#define D2_INV_PANEL_R 0x6fbb160cu

#define D2_INV_LEFT   (D2_INV_GRID + 0x04u)
#define D2_INV_RIGHT  (D2_INV_GRID + 0x08u)
/*
** The same descriptors carry Y, at +0c and +10, and it matters above 600.
**
** Only the two X fields were ever written, because at 600 lines the vertical
** correction is zero and nothing could show.  The gate's Y pair lives at
** 6fbb1610/6fbb1614, the two compares that follow the X ones at 6fb40660.
*/
#define D2_INV_TOP     (D2_INV_GRID + 0x0cu)
#define D2_INV_BOT     (D2_INV_GRID + 0x10u)
#define D2_INV_PANEL_T 0x6fbb1610u
#define D2_INV_PANEL_B 0x6fbb1614u

/*
** ALL SEVEN panel grids, for the vertical correction.
**
** Only the inventory's is moved horizontally: the other six are the stash, the
** cube and the vendor's, which are LEFT-hand panels and are already correct in
** x at any width.  That is why they were left alone entirely -- and at 600
** lines "entirely" was indistinguishable from "in x", because the vertical
** correction is zero there.
**
** Above 600 they come apart exactly as the inventory did.  The vendor's panel
** background follows the screen (it is drawn by the shared side-panel code)
** and its grid does not, so the goods hang in the air above the panel and
** nothing in the grid can be clicked.
**
** Same descriptor layout throughout: x at +04, right at +08, y at +0c,
** bottom at +10, cell size at +14.
*/
/*
** The TRADER panel's outer gate, and the same lesson a third time.
**
** Moving all seven grids put the vendor's goods in the right place and left
** nothing on the panel clickable -- not the items, not the buttons.  That is
** the signature of a gate, not of a coordinate: a gate rejects before any
** inner rect is consulted, so every correction behind it is invisible.
**
** 6fb496fd tests 6fbb1718/171c/1720/1724 and only then falls through to the
** vendor grid's own rect at 6fbb16c4.., which we do move:
**
**     cmp eax,ebx            ; ebx = [6fbb1718], the left bound
**     cmp eax,[6fbb171c] jg  ; right
**     cmp edi,[6fbb1720] jl  ; top
**     cmp edi,[6fbb1724] jg  ; bottom
**
** Y only: the trade panel is anchored at x=0, so its horizontal bounds are
** already right at any width -- which is exactly why this never showed until a
** mode taller than 600.  The left/right pair is logged anyway, so a run says
** whether that assumption holds rather than leaving it assumed.
*/
#define D2_TRADE_GATE_L 0x6fbb1718u
#define D2_TRADE_GATE_R 0x6fbb171cu
#define D2_TRADE_GATE_T 0x6fbb1720u
#define D2_TRADE_GATE_B 0x6fbb1724u

#define D2_GRID_N 7
static const unsigned int kGridDesc[D2_GRID_N] = {
    0x6fbb1598u, 0x6fbb15e0u, 0x6fbb1680u, 0x6fbb16a8u,
    0x6fbb16c0u, 0x6fbb16d8u, 0x6fbb16f0u
};

/*
** Move a hardcoded HOVER REGION.
**
** The orbs and the ability icons are the one part of the UI that Diablo II
** pins to the screen CORNERS, so their hover tests read like this (the health
** orb, at +06d6f3):
**
**     mov edx,[esp+0x10]      ; mouse X
**     cmp edx,0x1e            ; 30       <- hardcoded
**     jl  reject
**     cmp edx,0x6e            ; 110      <- hardcoded
**     jg  reject
**     mov eax,ds:0x6fba7038   ; screen H -- LIVE, so Y already follows
**     lea esi,[eax-0x4b] ...  ; H-75 .. H-15
**
** Note the asymmetry: vertical is computed from the live screen height and has
** been right all along; only horizontal is frozen at 800x600.  That is why the
** orbs' Y behaviour never needed touching.
**
** 30+316 does not fit in the imm8 those compares use, so the values cannot
** simply be rewritten.  Instead the seven bytes of `mov` + first `cmp` are
** replaced by a call to a stub that normalises the mouse INTO stock space:
**
**     mov edx,[esp+N+4]       ; the mouse X the original read (+4 for the
**                             ; return address the call just pushed)
**     sub edx,cx              ; back into 800x600 coordinates
**     cmp edx,<imm8>          ; the compare that was displaced
**     ret                     ; ret does not touch flags, so the jl still works
**
** and every later compare in the sequence then works unmodified, because edx
** is left holding the normalised value.  One stub covers a whole region test
** rather than one compare.
*/
/*
** Two shapes, because the two orbs are anchored to opposite corners.
**
** LEFT-anchored (health): `mov edx,[esp+N] ; cmp edx,imm8`, 7 bytes.  The art
** moved +cx, so the mouse is normalised back by SUBTRACTING cx.
**
** RIGHT-anchored (mana): `mov ecx,ds:<screen width>`, 6 bytes, and the bounds
** that follow are W-relative rather than immediates.  The art moved -cx, so
** the mouse is normalised by ADDING cx.  The displaced instruction is simply
** re-issued inside the stub.
**
** Both leave the register holding a stock-space X, so every remaining compare
** in the sequence works untouched.
*/
#define HITFIX_LEFT   0   /* mov edx,[esp+N] ; cmp edx,imm8   -> sub */
#define HITFIX_RIGHT  1   /* mov ecx,ds:width                 -> add */
#define HITFIX_AUTO   2   /* mov ecx,ds:mouseX -- shift the ICON, by eax */

typedef struct {
    unsigned int  rva;      /* the instruction being replaced */
    unsigned char kind;
    unsigned char espOff;   /* N in [esp+N] holding the mouse X;
                            ** AUTO: the left icon's own stock X */
    unsigned char cmpImm;   /* LEFT: imm8 of the cmp that follows;
                            ** AUTO: the right icon's inset from W */
    unsigned int  global;   /* RIGHT/AUTO: the global the mov reads */
    const char   *what;
} D2HitFix;

static const D2HitFix g_d2HitFix[] = {
    { 0x06d6f3u, HITFIX_LEFT,  0x10u, 0x1eu, 0u,          "health orb hover" },
    { 0x06d7cbu, HITFIX_RIGHT, 0x10u, 0u,    0x6fba7034u, "mana orb hover"   },
    { 0x0a7350u, HITFIX_AUTO,  117u,  165u,  0x6fbcc950u,
      "ability tooltip" }
};
#define D2_HITFIX_N (sizeof(g_d2HitFix) / sizeof(g_d2HitFix[0]))

/*
** Replace a whole REGION TEST, rather than normalising a register.
**
** The ability icons cannot use the stub-and-reload trick the orbs do.  Their
** tests live in a chain that shares one register, and after the chain falls
** through the mouse X is handed on:
**
**     6fb1e29c:  mov ecx,edi
**     6fb1e29e:  call 0x6fb1c680
**
** so shifting the register would corrupt whatever that handles.  Instead the
** two compares and their two branches are replaced outright by a call that
** sets the flags and one branch that consumes them:
**
**     push edx                    ; the game's edx is not ours to spend
**     lea  edx,[reg - low]        ; low = where the icon actually IS now
**     cmp  edx, span              ; unsigned: below-or-equal means inside
**     pop  edx                    ; pop does not disturb flags
**     ret                         ; nor does ret
**
**   ... call stub ; ja <the original reject target> ; nop padding
**
** One `ja` replaces a `jl`/`jg` pair because the subtraction turns a range
** test into a single unsigned comparison -- anything below the region wraps to
** a huge value and fails the same test as anything above it.
**
** The displacement is where the icon sits AFTER our draw rules moved it, so
** left and right differ only in that constant:
**
**     left   x - (0x75 + cx)      ; art moved +cx
**     right  x - ((W - 0xa5) - cx); art moved -cx
*/
typedef struct {
    unsigned int  rva;        /* first byte replaced */
    unsigned char len;        /* how many bytes, >= 7 */
    unsigned char modrm;      /* 0x97 = lea edx,[edi+d]; 0x96 = [esi+d] */
    unsigned char span;       /* inclusive width of the region */
    unsigned char jaRel;      /* rel8 of the ja we emit at rva+5 */
    unsigned char sig[3];     /* first three original bytes, checked */
    unsigned int  bound;      /* stock low bound */
    unsigned char fromRight;  /* bound is measured from the screen width */
    const char   *what;
} D2RegionFix;

static const D2RegionFix g_d2Region[] = {
    /* +06e100 -- reached first, but patching it changed nothing on screen, so
       it is not the handler that acts on a click.  Left in place: it tests the
       same regions and should agree with the others. */
    { 0x06e16eu, 13, 0x97, 0x30, 0x31, { 0x83, 0xff, 0x75 }, 0x75u, 0,
      "ability L (06e100)" },
    { 0x06e1acu, 17, 0x97, 0x30, 0x35, { 0x8d, 0x91, 0x5b }, 0xa5u, 1,
      "ability R (06e100)" },

    /* +06f3b0 IS the handler that acts: on a match it calls 0x6facc190 with
       the skill selectors in ecx/edx.  Note the registers are the other way
       round here -- esi is the mouse X (movzx esi,[ebp+0xc]), where +06e100
       used edi -- which is why the modrm differs. */
    { 0x06f618u, 13, 0x96, 0x30, 0x4bu, { 0x83, 0xfe, 0x75 }, 0x75u, 0,
      "ability L click" },
    { 0x06f78fu, 13, 0x96, 0x30, 0x69u, { 0x83, 0xfe, 0x75 }, 0x75u, 0,
      "ability L click 2" },

    /*
    ** The ORB click regions, which toggle the permanent value display.
    **
    ** Their hover regions were corrected long before these were, so the
    ** tooltips followed the orbs while the toggle still lived out at the
    ** screen corner -- clicking there pinned the mana readout on, which looked
    ** like a bug in the tooltip and was in fact the game's own feature being
    ** triggered from the old position.  0x6fbcd00c is written in exactly one
    ** place, +06e275, on this region's success path.
    **
    ** Span 0x50 rather than 0x30: the orbs are wider than the ability icons.
    */
    { 0x06e1e8u, 10, 0x97, 0x50, 0x51u, { 0x83, 0xff, 0x1e }, 0x1eu, 0,
      "health orb click" },
    { 0x06e240u, 14, 0x97, 0x50, 0x55u, { 0x8d, 0x51, 0x91 }, 0x6fu, 1,
      "mana orb click" },

    /*
    ** The "QUEST LOG" notification button of the 640-wide layout, which sits
    ** above the health orb.  Its click test (+020b00, left arm) is the stock
    ** 0x29..0x49 from the screen's left edge:
    **
    **     +020b2c  cmp ecx,0x28 ; jle +020b52
    **     +020b31  cmp ecx,0x4a ; jge +020b52
    **
    ** The art is moved with it -- see Diablo2FixupQuestBtn.  Mouse x is in
    ** ecx here, hence lea edx,[ecx+d], modrm 0x91.
    */
    { 0x020b2cu, 10, 0x91, 0x20, 0x1fu, { 0x83, 0xf9, 0x28 }, 0x29u, 0,
      "quest log button click" }
};
#define D2_REGION_N (sizeof(g_d2Region) / sizeof(g_d2Region[0]))

/*
** The RIGHT-hand twins are edited in place instead of being replaced.
**
** They compute their bounds from a base register and, crucially, MODIFY it as
** part of the test:
**
**     lea edx,[ebx-0xa5] ; cmp esi,edx ; jl reject
**     add ebx,-0x75      ; cmp esi,ebx ; jg reject
**
** Replacing the block wholesale would drop that `add`, so instead the lea's
** disp32 is rewritten to the icon's real position and the second bound is
** taken from edx rather than the base:
**
**     lea edx,[ebx-(0xa5+cx)] ; cmp esi,edx ; jl reject
**     add edx,0x30            ; cmp esi,edx ; jg reject
**
** Same length, same branches, same targets -- only two constants and one
** register field change, and the base register is left untouched rather than
** half-updated.
*/
typedef struct {
    unsigned int  rva;
    unsigned char modrm;      /* 0x93 = [ebx+d], 0x95 = [ebp+d] */
    unsigned char addReg;     /* the `add <base>,imm8` byte we replace */
    unsigned char cmpReg;     /* the `cmp esi,<base>` second byte */
    unsigned int  bound;
    const char   *what;
} D2RegionInPlace;

static const D2RegionInPlace g_d2RegionIP[] = {
    { 0x06f66au, 0x93, 0xc3, 0xf3, 0xa5u, "ability R click" },
    { 0x06f7ffu, 0x95, 0xc5, 0xf5, 0xa5u, "ability R click 2" }
};
#define D2_REGIONIP_N (sizeof(g_d2RegionIP) / sizeof(g_d2RegionIP[0]))

static void Diablo2FixupRegionsInPlace(unsigned int cx)
{
    HMODULE        cli = GetModuleHandleA("D2Client.dll");
    unsigned int   i;
    unsigned char *at;
    unsigned char  code[17];
    int            disp;

    if (!cli) return;
    for (i = 0; i < D2_REGIONIP_N; i++) {
        const D2RegionInPlace *r = &g_d2RegionIP[i];

        at = (unsigned char *)((unsigned int)cli + r->rva);
        if (IsBadReadPtr(at, 17) ||
            at[0] != 0x8d || at[1] != r->modrm ||
            at[10] != 0x83 || at[11] != r->addReg || at[12] != 0x8b ||
            at[13] != 0x3b || at[14] != r->cmpReg) {
            GameFix_Log("region: %s -- bytes at +%06lx unexpected, skipped",
                        r->what, (unsigned long)r->rva);
            continue;
        }

        memcpy(code, at, 17);
        disp = -((int)r->bound + (int)cx);
        PutU32(code + 2, (unsigned int)disp);
        code[10] = 0x83; code[11] = 0xc2; code[12] = 0x30;  /* add edx,0x30 */
        code[13] = 0x3b; code[14] = 0xf2;                   /* cmp esi,edx  */
        if (WriteCode(at, code, 17))
            GameFix_Log("region: %s +%06lx in place (base%d .. base%d)",
                        r->what, (unsigned long)r->rva, disp, disp + 0x30);
        else
            GameFix_Log("region: %s -- could not write the code", r->what);
    }
}

static void Diablo2FixupRegions(unsigned int cx)
{
    HMODULE        cli = GetModuleHandleA("D2Client.dll");
    unsigned int   i;
    unsigned char *at, *stub;
    unsigned char  code[24];
    int            disp;

    if (!cli) return;
    for (i = 0; i < D2_REGION_N; i++) {
        const D2RegionFix *r = &g_d2Region[i];

        at = (unsigned char *)((unsigned int)cli + r->rva);
        if (IsBadReadPtr(at, r->len) || memcmp(at, r->sig, 3) != 0) {
            GameFix_Log("region: %s -- bytes at +%06lx unexpected, skipped",
                        r->what, (unsigned long)r->rva);
            continue;
        }

        disp = r->fromRight
             ? -((int)(g_targetW - r->bound) - (int)cx)
             : -((int)r->bound + (int)cx);

        stub = (unsigned char *)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
        if (!stub) { GameFix_Log("region: %s -- no memory", r->what); continue; }
        stub[0] = 0x52;                             /* push edx */
        stub[1] = 0x8d; stub[2] = r->modrm;         /* lea edx,[reg+disp32] */
        PutU32(stub + 3, (unsigned int)disp);
        stub[7] = 0x83; stub[8] = 0xfa; stub[9] = r->span;   /* cmp edx,span */
        stub[10] = 0x5a;                            /* pop edx (flags intact) */
        stub[11] = 0xc3;                            /* ret     (flags intact) */

        code[0] = 0xe8;
        PutU32(code + 1, (unsigned int)stub - ((unsigned int)at + 5u));
        code[5] = 0x77; code[6] = r->jaRel;         /* ja <reject> */
        memset(code + 7, 0x90, (unsigned int)r->len - 7u);
        if (WriteCode(at, code, r->len))
            GameFix_Log("region: %s +%06lx -> stub %08lx (inside = x-%d <= %u)",
                        r->what, (unsigned long)r->rva,
                        (unsigned long)(unsigned int)stub, -disp, r->span);
        else
            GameFix_Log("region: %s -- could not write the code", r->what);
    }
}

static int g_hitDone = 0;

static void Diablo2FixupHitRegions(void)
{
    HMODULE        cli = GetModuleHandleA("D2Client.dll");
    unsigned int   i, cx;
    unsigned char *at, *stub;
    unsigned char  want[7], code[7];

    if (!cli || g_hitDone || !g_d2InvGrid || g_targetW <= 800u) return;
    g_hitDone = 1;                       /* one attempt, reported either way */
    cx = (g_targetW - 800u) / 2u;

    for (i = 0; i < D2_HITFIX_N; i++) {
        const D2HitFix *h = &g_d2HitFix[i];

        unsigned int nWant = (h->kind == HITFIX_LEFT) ? 7u : 6u;

        at = (unsigned char *)((unsigned int)cli + h->rva);

        if (h->kind == HITFIX_LEFT) {
            want[0] = 0x8b; want[1] = 0x54; want[2] = 0x24; want[3] = h->espOff;
            want[4] = 0x83; want[5] = 0xfa; want[6] = h->cmpImm;
        } else {
            want[0] = 0x8b; want[1] = 0x0d;           /* mov ecx,ds:imm32 */
            PutU32(want + 2, h->global);
        }
        if (IsBadReadPtr(at, nWant) || memcmp(at, want, nWant) != 0) {
            GameFix_Log("hitfix: %s -- bytes at +%06lx are not what was"
                        " expected, skipped", h->what, (unsigned long)h->rva);
            continue;
        }

        stub = (unsigned char *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
        if (!stub) { GameFix_Log("hitfix: %s -- no memory", h->what); continue; }

        if (h->kind == HITFIX_LEFT) {
            stub[0] = 0x8b; stub[1] = 0x54; stub[2] = 0x24;
            stub[3] = (unsigned char)(h->espOff + 4u); /* call pushed a return */
            stub[4] = 0x81; stub[5] = 0xea;            /* sub edx,imm32 */
            PutU32(stub + 6, cx);
            stub[10] = 0x83; stub[11] = 0xfa; stub[12] = h->cmpImm;
            stub[13] = 0xc3;                           /* ret preserves flags */
        } else if (h->kind == HITFIX_AUTO) {
            /*
            ** The ABILITY TOOLTIP -- hover region AND text, in one stub.
            **
            ** 6fb57350 is a helper: "is the mouse over the icon at (eax,esi)?
            ** if so draw its tooltip", with the icon's own position passed in
            ** eax.  Every use of eax inside it is that position -- the two
            ** region compares, the two `lea <r>,[eax+0x30]` upper bounds, and
            ** the `push eax` that hands the tooltip box its draw X.  Nothing
            ** returns in eax (the helper ends `ret 0x10`, and eax is reloaded
            ** on the draw path anyway).
            **
            ** So shift the ICON rather than normalise the mouse.  One add moves
            ** the region and the text together; normalising the mouse could
            ** only ever fix the region, and left the text at stock -- which is
            ** exactly how it looked.
            **
            ** The gate is the icon's own X, not a half-screen test.  The same
            ** helper draws the tooltips for entries inside the ability-select
            ** POPUP, and that popup is deliberately left at its stock position
            ** (moving its art breaks selection -- see g_d2Fix2D).  A half-screen
            ** test caught those entries too and pushed their tests off target,
            ** which is why their tooltips stopped appearing.  Matching the two
            ** control-panel icons exactly leaves every other caller alone.
            **
            **     mov ecx,ds:<mouse x>     ; the displaced instruction
            **     cmp eax,<left icon x>    ; the left ability icon?
            **     je  left
            **     cmp eax,<W - inset>      ; the right one?
            **     je  right
            **     ret                      ; anything else: untouched
            **   left:   add eax,cx  ; ret  ; art moved +cx
            **   right:  sub eax,cx  ; ret  ; art moved -cx
            */
            stub[0] = 0x8b; stub[1] = 0x0d;            /* the displaced mov */
            PutU32(stub + 2, h->global);
            stub[6] = 0x3d;                            /* cmp eax,imm32 */
            PutU32(stub + 7, (unsigned int)h->espOff);
            stub[11] = 0x74; stub[12] = 0x08;          /* je left  (-> 21) */
            stub[13] = 0x3d;                           /* cmp eax,imm32 */
            PutU32(stub + 14, g_targetW - (unsigned int)h->cmpImm);
            stub[18] = 0x74; stub[19] = 0x09;          /* je right (-> 29) */
            stub[20] = 0xc3;
            stub[21] = 0x05;                           /* add eax,imm32 */
            PutU32(stub + 22, cx);
            stub[26] = 0xc3;
            stub[27] = 0x90; stub[28] = 0x90;
            stub[29] = 0x2d;                           /* sub eax,imm32 */
            PutU32(stub + 30, cx);
            stub[34] = 0xc3;
        } else {
            /*
            ** RELOAD the mouse rather than adjust edx in place.
            **
            ** edx is NOT reloaded between the two orb tests: the health test's
            ** reject path jumps past the `mov edx,[esp+0x10]` that the pass
            ** path executes, so edx still holds whatever the health stub left
            ** -- mouseX - cx.  Adding cx to that restored the original value
            ** and the region never moved, while the tooltip did, which is
            ** exactly how it looked on screen.
            **
            ** Reading the slot again makes each stub independent of whether
            ** any earlier one ran.
            */
            stub[0] = 0x8b; stub[1] = 0x54; stub[2] = 0x24;
            stub[3] = (unsigned char)(h->espOff + 4u);
            stub[4] = 0x81; stub[5] = 0xc2;            /* add edx,imm32 */
            PutU32(stub + 6, cx);
            stub[10] = 0x8b; stub[11] = 0x0d;          /* the displaced mov */
            PutU32(stub + 12, h->global);
            stub[16] = 0xc3;
        }

        code[0] = 0xe8;                                /* call rel32 */
        PutU32(code + 1, (unsigned int)stub - ((unsigned int)at + 5u));
        code[5] = 0x90; code[6] = 0x90;                /* pad to the old length */
        if (WriteCode(at, code, nWant))
            GameFix_Log("hitfix: %s +%06lx -> stub %08lx (%s)",
                        h->what, (unsigned long)h->rva,
                        (unsigned long)(unsigned int)stub,
                        (h->kind == HITFIX_AUTO) ? "icon x +/- cx at 117/W-165"
                      : (h->kind == HITFIX_LEFT) ? "mouse x -= cx"
                      :                            "mouse x += cx");
        else
            GameFix_Log("hitfix: %s -- could not write the code", h->what);
    }

    Diablo2FixupRegions(cx);
    Diablo2FixupRegionsInPlace(cx);
}

/*
** Move the BELT slot rects, at their source.
**
** The four quick-item slots looked right and did not work: the potions sat in
** the middle of the control panel where they belong, but nothing highlighted
** under the cursor and nothing could be picked up or dropped.  That split is
** the signature of a draw rule with no matching hit rule -- the inventory grid
** all over again -- except here it goes further, because even the highlight
** was missing.
**
** All four consumers read ONE rect, from D2Common ordinal 10689, reached
** through D2Client's import slot 6fb7fa50:
**
**   6fb1c510  the SLOT PICKER: for each slot, fetch its rect and compare the
**             mouse against {left,right,top,bottom}; return the index.
**             Reached from 6fb1c7e0, which is what the strip test calls once
**             a click lands inside the quick slots.
**   6fb1f160  the GREEN SQUARE: D2gfx#10028 fills rect.left..left+0x1d,
**             rect.top..top+0x1d.  A rectangle FILL, not a sprite, so no draw
**             hook of ours was ever going to see it.
**   6fb1f18a  the ITEM ART: the shared item helper, at rect.left/rect.top.
**   6fb1f2a3  the HOTKEY DIGITS: at rect.left+2, rect.bottom-2.
**
** Blizzard's own gate was already correct -- the strip test at 6fb1d13e reads
** x in [W/2+23, W/2+145] off the live width -- which is why the click reached
** the picker at all and then died there, on rects that are still 800x600.
** Gate right, contents wrong: the mirror image of the inventory, where it was
** the gate that got left behind.
**
** So hook the slot, call through, and shift the rect that comes back.  One
** correction, applied where all four consumers read from, which is why they
** cannot drift apart again.
**
** Scoped by inspection, not by hope: ordinal 10689 has six call sites in
** D2Client and every one is belt code (6fb1c564, 6fb1c880, 6fb1c934,
** 6fb1f0b2, 6fb1f13f, 6fb1f179).  Nothing else asks for these rects, so the
** shift cannot reach the inventory, the stash or the cube.
**
** Y is carried too.  It is a no-op while the game runs at 600 lines, which is
** every mode this was built for, but the belt is bottom-anchored and the rects
** are raw 800x600, so H-600 is the correction if a taller mode appears.
*/
/*
** ...and the GATE in front of it, which is a SECOND rect source.
**
** Shifting ord#10689 made the slots work and left one thing wrong: moving the
** mouse across a slot turned the highlight on, off, on, off -- one flip per
** mouse-move message.  Not a pixel-parity effect; a two-state machine.
**
** 6fb1d0c8, the belt's mouse-move handler, asks 6fbccfc4 "is the belt already
** engaged?" and takes a DIFFERENT test depending on the answer:
**
**   not engaged -> 6fb1d13e, the strip test, x in [W/2+23, W/2+145] read off
**                  the live width.  Correct already.  A hit ENGAGES the belt
**                  (6fbccfc4 = 1) and the highlight comes on.
**   engaged     -> 6fb1c3d0, whose first arm tests the rect ARRAY from
**                  D2Common ord#10370.  Those rects are raw 800x600, so it
**                  missed -- and a miss DISENGAGES (6fb1d125 clears 6fbccfc4
**                  and 6fbccfc0), turning the highlight off.
**
** So every move alternated between the two arms and the belt flickered at the
** rate the mouse produced messages.  Section 9, again: patch every arm.  The
** first version of this hook did one of the two rect sources, which is why the
** symptom moved instead of going away.
**
** The array starts at buffer+8, sixteen bytes per rect, the same
** {left,right,top,bottom} order as ord#10689, with the count as a BYTE at
** buffer+4.  The stack block the game hands over is 0x108 bytes, which is
** exactly 8 + 16*16, so sixteen is the real capacity and the clamp is not a
** guess.  Only 6fb1c3d0 reads these rects; the other three callers of
** ord#10370 take the count and nothing else, so the shift cannot reach them.
*/
#define D2_BELT_RECT_SLOT 0x6fb7fa50u   /* D2Client IAT: D2Common ord#10689 */
#define D2_BELT_LIST_SLOT 0x6fb7fa38u   /* D2Client IAT: D2Common ord#10370 */
#define D2_BELT_RECTS_MAX 16u           /* (0x108 - 8) / 16                 */

static unsigned int   g_beltReal     = 0;
static unsigned char *g_beltStub     = 0;
static unsigned int   g_beltListReal = 0;
static unsigned char *g_beltListStub = 0;
static int            g_beltCx       = 0;
static int            g_beltBy       = 0;

/*
** Called by the list stub, after the real ordinal has filled the buffer.
**
** C rather than more hand-assembly, because it is a loop over a count only
** known at run time.  The stub saves and restores eax around the call, so the
** ordinal's own return value reaches its caller untouched.
*/
static void D2BeltFixList(unsigned char *buf)
{
    unsigned int n, i;
    int *r;

    if (!buf) return;
    n = (unsigned int)buf[4];
    if (n > D2_BELT_RECTS_MAX) n = D2_BELT_RECTS_MAX;

    r = (int *)(buf + 8);
    for (i = 0; i < n; i++) {
        r[0] += g_beltCx;   /* left   */
        r[1] += g_beltCx;   /* right  */
        r[2] += g_beltBy;   /* top    */
        r[3] += g_beltBy;   /* bottom */
        r += 4;
    }
}

/*
** The gate's rect array: call through, then shift every rect it filled in.
**
**     push ebp / mov ebp,esp
**     mov  edx,[ebp+8] ; mov ecx,[ebp+0xc]    the caller's registers, as they
**                                             were at the original call
**     push [ebp+0x10] .. [ebp+8]              three arguments, buffer last
**     call [g_beltListReal]                   callee pops its own 12
**     push eax                                keep the ordinal's result
**     push [ebp+0x10] ; call D2BeltFixList    shift the rects (cdecl)
**     add  esp,4 / pop eax
**     pop  ebp / ret 0x0c
*/
static void Diablo2InstallBeltList(unsigned int cx, unsigned int by)
{
    static const unsigned char tmpl[] = {
        0x55,                         /* push ebp                      */
        0x8b, 0xec,                   /* mov  ebp,esp                  */
        0x8b, 0x55, 0x08,             /* mov  edx,[ebp+8]              */
        0x8b, 0x4d, 0x0c,             /* mov  ecx,[ebp+0xc]            */
        0xff, 0x75, 0x10,             /* push [ebp+0x10]  ; buffer     */
        0xff, 0x75, 0x0c,             /* push [ebp+0xc]                */
        0xff, 0x75, 0x08,             /* push [ebp+8]                  */
        0xff, 0x15, 0, 0, 0, 0,       /* call [g_beltListReal]         */
        0x50,                         /* push eax         ; keep it    */
        0xff, 0x75, 0x10,             /* push [ebp+0x10]  ; buffer     */
        0xb8, 0, 0, 0, 0,             /* mov  eax,D2BeltFixList        */
        0xff, 0xd0,                   /* call eax                      */
        0x83, 0xc4, 0x04,             /* add  esp,4       ; cdecl      */
        0x58,                         /* pop  eax                      */
        0x5d,                         /* pop  ebp                      */
        0xc2, 0x0c, 0x00              /* ret  0x0c                     */
    };
    HMODULE        cli = GetModuleHandleA("D2Client.dll");
    unsigned int   slotVal = 0;
    unsigned char *stub;

    if (!cli || g_beltListStub) return;

    if (!ReadModuleGlobal(cli, D2_BELT_LIST_SLOT, &slotVal) || !slotVal) {
        GameFix_Log("belt: gate slot %08lx unreadable, gate not hooked"
                    " -- expect the highlight to flicker as the mouse moves",
                    (unsigned long)D2_BELT_LIST_SLOT);
        g_beltListStub = (unsigned char *)1;
        return;
    }

    stub = (unsigned char *)VirtualAlloc(NULL, sizeof(tmpl),
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!stub) { GameFix_Log("belt: no memory for the gate stub"); return; }

    g_beltListReal = slotVal;
    memcpy(stub, tmpl, sizeof(tmpl));
    PutU32(stub + 20, (unsigned int)&g_beltListReal);
    PutU32(stub + 29, (unsigned int)&D2BeltFixList);

    if (!WriteModuleGlobal(cli, D2_BELT_LIST_SLOT, (unsigned int)stub)) {
        GameFix_Log("belt: could not write the gate slot");
        VirtualFree(stub, 0, MEM_RELEASE);
        return;
    }

    g_beltListStub = stub;
    GameFix_Log("belt: gate rects hooked  real=%08lx stub=%08lx"
                " (x += %u, y += %u, up to %u rects)",
                (unsigned long)slotVal, (unsigned long)(unsigned int)stub,
                cx, by, D2_BELT_RECTS_MAX);
}

static void Diablo2InstallBeltHook(void)
{
    /*
    ** stdcall, four arguments, an out-pointer at +0x0c:
    **
    **     push ebp / mov ebp,esp
    **     mov  edx,[ebp+8] ; mov ecx,[ebp+0xc]   reproduce the caller's
    **                                            registers, so the shape of
    **                                            the convention cannot matter
    **     push [ebp+0x14] .. [ebp+8]             hand the four along
    **     call [g_beltReal]                      callee pops its own 16
    **     mov  ecx,[ebp+0x10]                    &rect (eax is the result and
    **                                            is left alone)
    **     add  [ecx+0],cx / [ecx+4],cx           left, right
    **     add  [ecx+8],by / [ecx+0xc],by         top, bottom
    **     pop  ebp / ret 0x10
    */
    static const unsigned char tmpl[] = {
        0x55,                         /* push ebp                     */
        0x8b, 0xec,                   /* mov  ebp,esp                 */
        0x8b, 0x55, 0x08,             /* mov  edx,[ebp+8]             */
        0x8b, 0x4d, 0x0c,             /* mov  ecx,[ebp+0xc]           */
        0xff, 0x75, 0x14,             /* push [ebp+0x14]  ; slot      */
        0xff, 0x75, 0x10,             /* push [ebp+0x10]  ; &rect     */
        0xff, 0x75, 0x0c,             /* push [ebp+0xc]               */
        0xff, 0x75, 0x08,             /* push [ebp+8]                 */
        0xff, 0x15, 0, 0, 0, 0,       /* call [g_beltReal]            */
        0x8b, 0x4d, 0x10,             /* mov  ecx,[ebp+0x10]          */
        0x81, 0x01, 0, 0, 0, 0,       /* add  [ecx],cx      ; left    */
        0x81, 0x41, 0x04, 0, 0, 0, 0, /* add  [ecx+4],cx    ; right   */
        0x81, 0x41, 0x08, 0, 0, 0, 0, /* add  [ecx+8],by    ; top     */
        0x81, 0x41, 0x0c, 0, 0, 0, 0, /* add  [ecx+0xc],by  ; bottom  */
        0x5d,                         /* pop  ebp                     */
        0xc2, 0x10, 0x00              /* ret  0x10                    */
    };
    HMODULE        cli = GetModuleHandleA("D2Client.dll");
    unsigned int   slotVal = 0;
    unsigned int   cx, by;
    unsigned char *stub;

    if (!cli || g_beltStub || !g_d2Belt || g_targetW <= 800u) return;

    if (!ReadModuleGlobal(cli, D2_BELT_RECT_SLOT, &slotVal) || !slotVal) {
        GameFix_Log("belt: import slot %08lx unreadable, not hooked",
                    (unsigned long)D2_BELT_RECT_SLOT);
        g_beltStub = (unsigned char *)1;   /* reported once, not every frame */
        return;
    }

    stub = (unsigned char *)VirtualAlloc(NULL, sizeof(tmpl),
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!stub) { GameFix_Log("belt: no memory for the stub"); return; }

    cx = (g_targetW - 800u) / 2u;
    by = (g_targetH > 600u) ? (g_targetH - 600u) : 0u;
    g_beltCx = (int)cx;          /* the list helper reads these */
    g_beltBy = (int)by;

    g_beltReal = slotVal;
    memcpy(stub, tmpl, sizeof(tmpl));
    PutU32(stub + 23, (unsigned int)&g_beltReal);
    PutU32(stub + 32, cx);
    PutU32(stub + 39, cx);
    PutU32(stub + 46, by);
    PutU32(stub + 53, by);

    if (!WriteModuleGlobal(cli, D2_BELT_RECT_SLOT, (unsigned int)stub)) {
        GameFix_Log("belt: could not write the import slot");
        VirtualFree(stub, 0, MEM_RELEASE);
        return;
    }

    g_beltStub = stub;
    GameFix_Log("belt: slot rects hooked  real=%08lx stub=%08lx"
                " (x += %u, y += %u)",
                (unsigned long)slotVal, (unsigned long)(unsigned int)stub,
                cx, by);

    Diablo2InstallBeltList(cx, by);
}

/*
** Y BOUNDS that never learned about the screen height.
**
** The quest log's buttons draw themselves against the LIVE height and then
** hit-test themselves against CONSTANTS:
**
**   6fb3e086  mov eax,ds:0x6fba7038          ; H
**   6fb3e096  lea edx,[ecx+eax*1-0x3a]       ; art y = C + H - 58
**   6fb3e0ab  call DrawImage
**   6fb3e0bc  mov edx,ds:0x6fbcc94c          ; mouse y
**   6fb3e0cf  lea edi,[edx+eax*1]            ; test y = mouseY + C
**   6fb3e0dc  cmp edi,0x188  jl reject       ; ...against 392 and 425,
**   6fb3e0e4  cmp edi,0x1a9  jg reject       ;    with no H anywhere
**
** so above 600 lines the button is drawn where it belongs and can only be
** clicked where it used to be.  That is why the quest log could be opened and
** not closed.
**
** The art moves by (H-58) - (600-58) = H-600 = by, whatever C holds, and the
** bounds move by nothing.  So adding by to the bounds restores agreement at
** any height, and the value of C -- an unidentified global at 6fbcd358 --
** never has to be worked out.
**
** A plain immediate rewrite: `cmp edi,imm32` is 81 ff id, and the new value
** fits, so there is no stub and no relocation.  Guarded on the shipped
** immediate still being there, which makes it idempotent for free: once
** rewritten the bytes no longer match and a second pass does nothing.
*/
typedef struct {
    unsigned int  rva;     /* the cmp instruction */
    unsigned char modrm;   /* 0xff cmp edi / 0xf9 cmp ecx / 0x00 cmp eax */
    unsigned int  stock;   /* the immediate as Blizzard shipped it */
    const char   *what;
} D2YBound;

/*
** cmp eax,imm32 has its own one-byte opcode, 3d id, five bytes rather than
** the six of 81 /7 id.  modrm 0x00 in the table means that form.
*/
#define YB_EAX 0x00u
/*
** Not a bound at all but a POSITION: `mov eax,imm32`, b8 id, also five bytes.
** Same treatment -- the shipped immediate gets +by -- for a y that a panel
** computes from a constant rather than from the screen height.
*/
#define YB_MOV_EAX 0x01u
/* And `push imm32`, 68 id, five bytes: a position handed to a constructor. */
#define YB_PUSH    0x02u

/*
** THREE copies of the same two bounds, and patching one is not enough.
**
** The first version fixed only the draw-and-hover function, which is why the
** close button grew a tooltip and still would not close: the tooltip comes
** from that function, and the CLICK comes from somewhere else entirely.
** Searching D2Client for the shipped immediates found all of them:
**
**   +08e0dc  cmp edi  draw + hover      6fb3e0cf  lea edi,[edx+eax]
**   +08b16e  cmp ecx  a predicate, "is the mouse over button A/B",
**                     called from 6fb3c8b6 with ecx = the same y
**   +08d6ea  cmp ecx  the CLICK handler -- 6fb3d6d6 add ecx,esi, then
**                     call 6fb3d240 on a hit
**
** All three take y as mouseY plus the same panel offset and compare it to the
** same constants, so all three move together.  Two register forms, hence the
** modrm byte: 81 ff id for edi, 81 f9 id for ecx.
**
** Lesson worth keeping: a hit region can be implemented more than once in a
** binary, and fixing the one the trace shows you leaves the others.  The
** immediates themselves are the search key that finds the rest.
*/
static const D2YBound g_d2YBound[] = {
    { 0x08e0dcu, 0xffu, 0x188u, "quest btn A top  (draw)"  },
    { 0x08e0e4u, 0xffu, 0x1a9u, "quest btn A bot  (draw)"  },
    { 0x08e182u, 0xffu, 0x186u, "quest btn B top  (draw)"  },
    { 0x08e18au, 0xffu, 0x1a8u, "quest btn B bot  (draw)"  },
    { 0x08b16eu, 0xf9u, 0x188u, "quest btn A top  (test)"  },
    { 0x08b176u, 0xf9u, 0x1a9u, "quest btn A bot  (test)"  },
    { 0x08b1feu, 0xf9u, 0x186u, "quest btn B top  (test)"  },
    { 0x08b206u, 0xf9u, 0x1a8u, "quest btn B bot  (test)"  },
    { 0x08d6eau, 0xf9u, 0x188u, "quest btn A top  (click)" },
    { 0x08d6f2u, 0xf9u, 0x1a9u, "quest btn A bot  (click)" },
    /*
    ** The WAYPOINT panel's close button, and the same story a second time.
    **
    ** It draws at `mov ecx,0x1a1 ; sub ecx,[6fbcd358]` -- panel y 417, a
    ** constant, so it does not follow the height and the draw rule above
    ** moves it.  Its bounds are 387..420, which brackets that 417 exactly,
    ** and they appear THREE times just as the quest log's did, in all three
    ** register forms:
    **
    **   +03ecde  cmp ecx   81 f9 id
    **   +03f2d3  cmp edi   81 ff id
    **   +040192  cmp eax   3d id      <- five bytes, hence YB_EAX
    **
    ** Found by searching the region for immediates in the button's band
    ** rather than by reading outward from the draw, which is the technique
    ** that found the quest log's three and is now the standard move.
    */
    { 0x03ecdeu, 0xf9u,   0x183u, "wp close top (ecx)" },
    { 0x03ece6u, 0xf9u,   0x1a4u, "wp close bot (ecx)" },
    { 0x03f2d3u, 0xffu,   0x183u, "wp close top (edi)" },
    { 0x03f2dbu, 0xffu,   0x1a4u, "wp close bot (edi)" },
    { 0x040192u, YB_EAX,  0x183u, "wp close top (eax)" },
    { 0x040199u, YB_EAX,  0x1a4u, "wp close bot (eax)" },
    /*
    ** The QUEST PANEL's speech box.  +075ab0 sets the scroller's box position
    ** (x in 6fbd18e8, y in 6fba21f8) for two callers:
    **
    **     NPC dialog   x = (W - 0x145)/2   y = 0x0c                 correct
    **     quest panel  x = [6fbcd354]      y = 0x105 - [6fbcd358]   stock
    **
    ** The NPC box is centred and at the top, which is right at any size.
    ** The quest one is a constant inside a panel that has moved down by H-600,
    ** so its speech scrolled in the empty space above the panel.  Moving the
    ** constant moves everything drawn from the box together: full lines,
    ** the part-lines clipped at its edges, and the hit test that reads it.
    */
    { 0x075aeeu, YB_MOV_EAX, 0x105u, "quest speech box y" },
    /*
    ** The GOLD dialog (withdraw from the stash, and its siblings from the same
    ** constructor call in +01cae0).  It is a dialog.cpp object: the origin is
    ** handed to the constructor (+015ec0) and stored at +0x2c/+0x30, and its
    ** text, number field and buttons are all placed relative to that.  So one
    ** constant moves the whole dialog, clicks included:
    **
    **     +01cc1b  68 8c 00 00 00   push 0x8c   ; y = 140   <- this one
    **     +01cc20  68 d7 00 00 00   push 0xd7   ; x = 215
    **
    ** x stays: the stash is pinned to the left edge.  y follows the stash
    ** down by H-600, which puts the dialog back over it the way it sits at
    ** 800x600 instead of hanging above the panel's top edge.
    */
    { 0x01cc1bu, YB_PUSH, 0x8cu, "gold dialog y" },
    /*
    ** ...and its four CONTROLS, which are not dialog-relative at all.  Each
    ** is its own object, built in the same function after the dialog with an
    ** absolute stock position, and each keeps that position for both its
    ** drawing and its click test -- so moving the dialog alone left the
    ** arrows, the cursor and the two button faces hanging where it used to
    ** be.  Same form, same +by:
    **
    **     +01cd5c  push 0xdb    arrows      6fac0d20(obj, 223, 219, ...)
    **     +01cdbc  push 0xe4    amount box  6fac4330(obj, 258, 228, ...)
    **     +01ce22  push 0x11f   OK          6fac35e0(obj, 250, 287, 0, ...)
    **     +01ce84  push 0x11f   cancel      6fac35e0(obj, 355, 287, 1, ...)
    */
    { 0x01cd5cu, YB_PUSH, 0xdbu,  "gold dialog arrows y" },
    { 0x01cdbcu, YB_PUSH, 0xe4u,  "gold dialog amount y" },
    { 0x01ce22u, YB_PUSH, 0x11fu, "gold dialog ok y"     },
    { 0x01ce84u, YB_PUSH, 0x11fu, "gold dialog cancel y" }
};
#define D2_YBOUND_N (sizeof(g_d2YBound) / sizeof(g_d2YBound[0]))

/*
** The weapon-swap tooltip's LEFT/RIGHT choice.
**
**     +097dc2  8d 91 f4 01 00 00   lea edx,[ecx+0x1f4]   ; [6fbcd354] + 500
**     +097dc8  3b f2               cmp esi,edx           ; mouse x
**              jle -> left tab text, else right
**
** 500 is the stock split between the inventory's two I/II tabs.  The panel is
** pinned to the right edge, so the split has moved by W-800 with it; left
** alone, every mouse position on a wide screen is "right of 500" and hovering
** the LEFT tabs put the tooltip over the right ones.  One displacement, x
** only, so it applies at 600 lines too.  Verified against the shipped bytes.
*/
static int g_swapTipDone = 0;

static void Diablo2FixupSwapTip(void)
{
    static const unsigned char want[6] = { 0x8d, 0x91, 0xf4, 0x01, 0x00, 0x00 };
    HMODULE        cli = GetModuleHandleA("D2Client.dll");
    unsigned char *at;
    unsigned char  repl[6];
    unsigned int   split;

    if (!cli || g_swapTipDone || g_targetW <= 800u) return;
    g_swapTipDone = 1;                     /* one attempt, reported either way */

    at = (unsigned char *)((unsigned int)cli + 0x097dc2u);
    if (IsBadReadPtr(at, 6) || memcmp(at, want, 6) != 0) {
        GameFix_Log("swaptip: +097dc2 -- not the shipped bytes, skipped");
        return;
    }
    split = 0x1f4u + (g_targetW - 800u);
    memcpy(repl, want, 6);
    PutU32(repl + 2, split);
    if (WriteCode(at, repl, 6))
        GameFix_Log("swaptip: tab split 500 -> %u", split);
    else
        GameFix_Log("swaptip: could not write the code");
}

/*
** The SKILL-SELECTION popups -- the icon grids that open above the two skill
** buttons on the control panel.
**
** Everything a popup does -- drawing, hover highlight, tooltip, hotkey
** labels, the click that picks a skill -- is done by one layout function,
** +0a73d0, from the starting x it is handed as its second argument.  Eight
** calls in five small wrappers supply that x, and nothing else does:
**
**     right popup   x = W - 0x80     add e?x,0xffffff80  (imm8)
**     left  popup   x = 0x50         push 0x50           (imm8)
**
** Both are measured from the SCREEN edges, but the skill buttons they belong
** to sit on the centred control panel, so on a wide screen each popup opened
** at the far edge.  They belong cx further in.  (Moving only the draw, which
** was tried first, broke picking a skill -- see the note in g_d2Fix2D.)
**
** Those immediates are imm8 and cannot hold cx, so each call is aimed at a
** stub instead, which adjusts the x argument where the callee will read it
** and continues into the real function with the stack otherwise untouched:
**
**     add  dword [esp+8], +/-cx     ; [esp+4] is the unit, [esp+8] the x
**     push <D2Client+0a73d0>
**     ret
**
** y is already taken from the screen height (+0a73d6: H - 0x56).
*/
typedef struct {
    unsigned int  rva;       /* the `call 0x6fb573d0` */
    unsigned char right;     /* 1 = right popup (-cx), 0 = left (+cx) */
} D2PopupCall;

static const D2PopupCall g_d2PopupCall[] = {
    { 0x0a772fu, 1 }, { 0x0a7757u, 0 }, { 0x0a778au, 1 }, { 0x0a77beu, 0 },
    { 0x0a780eu, 0 }, { 0x0a783au, 1 }, { 0x0a7856u, 0 }, { 0x0a787bu, 1 }
};
#define D2_POPUP_CALLS  (sizeof(g_d2PopupCall) / sizeof(g_d2PopupCall[0]))
#define D2_POPUP_LAYOUT 0x0a73d0u

static int g_popupDone = 0;

static void Diablo2FixupSkillPopup(void)
{
    HMODULE        cli = GetModuleHandleA("D2Client.dll");
    unsigned char *stub, *at;
    unsigned char  code[5];
    unsigned int   i, cx, target, moved = 0;
    int            rel;

    if (!cli || g_popupDone || g_targetW <= 800u) return;
    g_popupDone = 1;                       /* one attempt, reported either way */

    cx     = (g_targetW - 800u) / 2u;
    target = (unsigned int)cli + D2_POPUP_LAYOUT;

    stub = (unsigned char *)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!stub) { GameFix_Log("popup: no memory"); return; }

    for (i = 0; i < 2u; i++) {             /* +0 left (+cx), +16 right (-cx) */
        unsigned char *s = stub + 16u * i;
        s[0] = 0x81; s[1] = 0x44; s[2] = 0x24; s[3] = 0x08;   /* add [esp+8],id */
        PutU32(s + 4, i ? (unsigned int)(-(int)cx) : cx);
        s[8] = 0x68;                                          /* push target    */
        PutU32(s + 9, target);
        s[13] = 0xc3;                                         /* ret            */
    }

    for (i = 0; i < D2_POPUP_CALLS; i++) {
        const D2PopupCall *c = &g_d2PopupCall[i];

        at = (unsigned char *)((unsigned int)cli + c->rva);
        if (IsBadReadPtr(at, 5) || at[0] != 0xe8) {
            GameFix_Log("popup: +%06lx -- not a call, skipped",
                        (unsigned long)c->rva);
            continue;
        }
        memcpy(&rel, at + 1, 4);
        if ((unsigned int)at + 5u + (unsigned int)rel != target) {
            GameFix_Log("popup: +%06lx -- calls elsewhere, skipped",
                        (unsigned long)c->rva);
            continue;
        }
        code[0] = 0xe8;
        PutU32(code + 1, (unsigned int)(stub + (c->right ? 16u : 0u)) -
                         ((unsigned int)at + 5u));
        if (WriteCode(at, code, 5)) moved++;
        else GameFix_Log("popup: +%06lx -- could not write the code",
                         (unsigned long)c->rva);
    }

    if (moved) {
        GameFix_Log("popup: %u of %u calls moved (left +%u, right -%u)",
                    moved, (unsigned int)D2_POPUP_CALLS, cx, cx);
    } else {
        VirtualFree(stub, 0, MEM_RELEASE);
    }
}

/*
** The "QUEST LOG" notification button's ART (640-wide layout, above the
** health orb).  +020eae picks its x once, into ebx, and the button face (x),
** its icon (x+3) and the "Quest Log" caption (centred on x) are all drawn
** from that:
**
**     +020ec4  bb 28 00 00 00   mov ebx,0x28      ; 40 from the left edge
**
** The health orb it sits over has moved in by cx with the centred control
** panel, so the button follows it.  Its click test is corrected alongside it
** in g_d2Region.  The other arm (+020eb3, x = W/2 + 0x28) is left alone.
*/
static int g_questBtnDone = 0;

static void Diablo2FixupQuestBtn(void)
{
    static const unsigned char want[5] = { 0xbb, 0x28, 0x00, 0x00, 0x00 };
    HMODULE        cli = GetModuleHandleA("D2Client.dll");
    unsigned char *at;
    unsigned char  repl[5];
    unsigned int   x;

    if (!cli || g_questBtnDone || g_targetW <= 800u) return;
    g_questBtnDone = 1;                    /* one attempt, reported either way */

    at = (unsigned char *)((unsigned int)cli + 0x020ec4u);
    if (IsBadReadPtr(at, 5) || memcmp(at, want, 5) != 0) {
        GameFix_Log("questbtn: +020ec4 -- not the shipped bytes, skipped");
        return;
    }
    x = 0x28u + (g_targetW - 800u) / 2u;
    memcpy(repl, want, 5);
    PutU32(repl + 1, x);
    if (WriteCode(at, repl, 5))
        GameFix_Log("questbtn: x 40 -> %u", x);
    else
        GameFix_Log("questbtn: could not write the code");
}

/*
** The "QUEST LOG" button as the 800-wide layout draws it.
**
** Diablo2FixupQuestBtn above covers the 640-layout copy (+020e50).  The
** layout the game normally runs uses a second copy, found with the watch box
** (+08d045 caption at x 18, +08d088 face at 40, +08d0d3 icon at 43), and that
** one reads its position from a TABLE rather than a constant:
**
**     6fbaae38 + row*0x14:  x-left, x-right, y-top, y-face, y-caption
**
** Both its draw (+08cf7c) and its click test (+08b3d0) index the same row,
** so moving the data moves the art and the click together.  y is already
** H-relative (table y + H - 480).  The row comes from +08b040:
**
**     rows 0, 2   no view shift          x = 40..75       stock   -> +cx
**     rows 1, 3   [6fbcd070] == 2        x + (W-640)/2    already centred
**
** (W-640)/2 is 80 + cx, so rows 1 and 3 are right as they are and only 0 and
** 2 move.  Row 0 is shipped in the file; row 2 is filled in at start-up by
** +0cdf00, so this is ShiftPair every tick like the other descriptors.
*/
#define D2_QBTN_ROWS    0x6fbaae38u
#define D2_QBTN_STRIDE  0x14u

static void Diablo2FixupQuestBtnRows(void)
{
    static const unsigned int rows[2] = { 0u, 2u };
    static unsigned int last[2][2];
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    unsigned int i, base, a, b, cx;

    if (!cli || g_targetW <= 800u) return;
    cx = (g_targetW - 800u) / 2u;

    for (i = 0; i < 2u; i++) {
        base = D2_QBTN_ROWS + rows[i] * D2_QBTN_STRIDE;
        if (ShiftPair(cli, base, base + 4u, cx, &last[i][0], &last[i][1],
                      &a, &b))
            GameFix_Log("questbtn: row %u x %u..%u -> %u..%u", rows[i], a, b,
                        a + cx, b + cx);
    }
}

static int g_yboundDone = 0;

static void Diablo2FixupYBounds(void)
{
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    unsigned int i, by, done = 0;

    if (!cli || g_yboundDone || g_targetH <= 600u) return;
    by = g_targetH - 600u;
    g_yboundDone = 1;                    /* one attempt, reported either way */

    for (i = 0; i < D2_YBOUND_N; i++) {
        const D2YBound *y = &g_d2YBound[i];
        unsigned char  *at = (unsigned char *)((unsigned int)cli + y->rva);
        unsigned char   want[6], repl[6];
        unsigned int    len, immAt;

        if (y->modrm == YB_EAX) {                    /* cmp eax,imm32 */
            want[0] = 0x3d; len = 5u; immAt = 1u;
        } else if (y->modrm == YB_MOV_EAX) {         /* mov eax,imm32 */
            want[0] = 0xb8; len = 5u; immAt = 1u;
        } else if (y->modrm == YB_PUSH) {            /* push imm32 */
            want[0] = 0x68; len = 5u; immAt = 1u;
        } else {                                     /* cmp edi/ecx,imm32 */
            want[0] = 0x81; want[1] = y->modrm; len = 6u; immAt = 2u;
        }
        PutU32(want + immAt, y->stock);
        if (IsBadReadPtr(at, len) || memcmp(at, want, len) != 0) {
            GameFix_Log("ybound: %s +%06lx -- not the shipped bytes, skipped",
                        y->what, (unsigned long)y->rva);
            continue;
        }

        memcpy(repl, want, len);
        PutU32(repl + immAt, y->stock + by);
        if (WriteCode(at, repl, len)) {
            GameFix_Log("ybound: %s +%06lx  %u -> %u", y->what,
                        (unsigned long)y->rva, y->stock, y->stock + by);
            done++;
        } else {
            GameFix_Log("ybound: %s -- could not write the code", y->what);
        }
    }
    if (done) GameFix_Log("ybound: moved %u of %u", done, (unsigned int)D2_YBOUND_N);
}

/*
** The six QUEST ICONS' hit boxes.
**
** Their art is moved by the two draw rules above, and their hit test is a
** static table -- 6fb9f180, sixteen bytes an entry, x at +0 and y at +4, box
** 0x38 by 0x34 -- walked at 6fb3b1c1 with the count from 6fbd08b0:
**
**     mov ecx,0x6fb9f184
**     mov edx,[ecx-4] ; cmp ebx,edx jl next ; add edx,0x38 ; cmp ebx,edx jge next
**     mov edx,[ecx]   ; cmp edi,edx jl next ; add edx,0x34 ; cmp edi,edx jl HIT
**
** The coordinates are PANEL-RELATIVE and in the same space as the close
** button's constants: the icons occupy y 65..215 and the button y 392..425,
** both inside a panel that is 63..553 tall.  One space, so one correction --
** the button's immediates get +by in Diablo2FixupYBounds and this column gets
** the same.
**
** Guarded on the shipped y, which makes it idempotent: after the write the
** value is no longer 65 or 163 and a second pass does nothing.  x is left
** alone; the quest log is anchored at x=0 at any width.
*/
#define D2_QICON_BASE   0x6fb9f180u
#define D2_QICON_STRIDE 0x10u
#define D2_QICON_N      6u

static int g_qiconDone = 0;

static void Diablo2FixupQuestIcons(void)
{
    /* Rows of three, twice: the 3x2 grid the panel shows. */
    static const unsigned int stockY[D2_QICON_N] = { 65u, 65u, 65u,
                                                     163u, 163u, 163u };
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    unsigned int i, by, y, moved = 0;

    if (!cli || g_qiconDone || g_targetH <= 600u) return;
    by = g_targetH - 600u;

    for (i = 0; i < D2_QICON_N; i++) {
        unsigned int va = D2_QICON_BASE + i * D2_QICON_STRIDE + 0x04u;

        if (!ReadModuleGlobal(cli, va, &y)) continue;
        if (y != stockY[i]) continue;              /* already ours, or not it */
        if (WriteModuleGlobal(cli, va, y + by)) {
            GameFix_Log("  quest icon %u: y %u -> %u", i, y, y + by);
            moved++;
        }
    }
    if (moved == D2_QICON_N) g_qiconDone = 1;      /* only stop when all six */
    if (moved) GameFix_Log("questicons: moved %u of %u", moved, D2_QICON_N);
}

static void Diablo2FixupInvGrid(void)
{
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    unsigned int a, b;
    unsigned int d  = g_targetW - 800u;
    unsigned int dy = (g_targetH > 600u) ? (g_targetH - 600u) : 0u;
    static unsigned int last[8];   /* grid L,R,T,B then gate L,R,T,B */

    if (!cli || !g_d2InvGrid || g_targetW <= 800u) return;

    /*
    ** The grid, then the GATE in front of it.  Moving the inner rects and not
    ** the gate made the whole inventory dead: over the panel the gate
    ** rejected, over the old position it passed but the rects had moved out
    ** from under it.  A gate that fails closed hides every correction behind
    ** it.
    */
    if (ShiftPair(cli, D2_INV_LEFT, D2_INV_RIGHT, d,
                  &last[0], &last[1], &a, &b))
        GameFix_Log("invgrid: grid x %u..%u -> %u..%u", a, b, a + d, b + d);

    /* Y on every grid, not just the inventory's: the stash, cube and vendor
       sit in panels that follow the screen height and their own descriptors do
       not.  ShiftPair skips an empty one (the game fills them lazily) and
       remembers what it wrote, so this is safe to run every tick. */
    {
        static unsigned int lastY[D2_GRID_N][2];
        unsigned int g;
        for (g = 0; g < D2_GRID_N; g++) {
            if (ShiftPair(cli, kGridDesc[g] + 0x0cu, kGridDesc[g] + 0x10u, dy,
                          &lastY[g][0], &lastY[g][1], &a, &b))
                GameFix_Log("invgrid: grid %u (%08lx) y %u..%u -> %u..%u",
                            g, (unsigned long)kGridDesc[g], a, b,
                            a + dy, b + dy);
        }
    }

    if (ShiftPair(cli, D2_INV_PANEL_L, D2_INV_PANEL_R, d,
                  &last[4], &last[5], &a, &b))
        GameFix_Log("invgrid: panel gate x %u..%u -> %u..%u", a, b, a + d, b + d);

    if (ShiftPair(cli, D2_INV_PANEL_T, D2_INV_PANEL_B, dy,
                  &last[6], &last[7], &a, &b))
        GameFix_Log("invgrid: panel gate y %u..%u -> %u..%u", a, b, a + dy, b + dy);

    /* The trade panel's gate.  Y only -- see the note by D2_TRADE_GATE_L. */
    {
        static unsigned int lastT[2];
        unsigned int l = 0, r = 0;
        if (ShiftPair(cli, D2_TRADE_GATE_T, D2_TRADE_GATE_B, dy,
                      &lastT[0], &lastT[1], &a, &b)) {
            GameFix_Log("invgrid: trade gate y %u..%u -> %u..%u",
                        a, b, a + dy, b + dy);
            /* Reported, not corrected: if these are not already screen-correct
               the panel is not left-anchored after all and needs an x rule. */
            if (ReadModuleGlobal(cli, D2_TRADE_GATE_L, &l) &&
                ReadModuleGlobal(cli, D2_TRADE_GATE_R, &r))
                GameFix_Log("invgrid: trade gate x %u..%u (left alone)", l, r);
        }
    }
}

/*
** Dump an arbitrary run of dwords out of D2Client, once and then on change.
**
** This keeps coming up: an element is visibly wrong, the draw is found, and
** the coordinates turn out to come from a table in memory that is empty in the
** file because the game fills it at run time.  Reading it is the only way to
** know what is in it, and guessing which entry is which has already been shown
** to be how you move a panel that was correct.
**
** [Diablo2] dumpwords=6fb9e700,40   (hex address, decimal count; empty = off)
*/
#define D2_DUMP_MAX 64u
static unsigned int g_dumpAt = 0;
static unsigned int g_dumpN  = 0;

static void Diablo2DumpWords(void)
{
    static unsigned int last[D2_DUMP_MAX];
    static int          ever = 0;
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    unsigned int cur[D2_DUMP_MAX];
    unsigned int i;
    int          changed = 0;

    if (!cli || !g_dumpAt || !g_dumpN) return;
    for (i = 0; i < g_dumpN; i++) {
        cur[i] = 0;
        ReadModuleGlobal(cli, g_dumpAt + i * 4u, &cur[i]);
        if (cur[i] != last[i]) changed = 1;
    }
    if (ever && !changed) return;
    for (i = 0; i < g_dumpN; i++) last[i] = cur[i];
    ever = 1;

    GameFix_Log("dump: %u dwords at %08lx", g_dumpN, (unsigned long)g_dumpAt);
    for (i = 0; i < g_dumpN; i += 4u) {
        GameFix_Log("  %08lx  %6d %6d %6d %6d",
                    (unsigned long)(g_dumpAt + i * 4u),
                    (int)cur[i],
                    (int)((i + 1u < g_dumpN) ? cur[i + 1u] : 0u),
                    (int)((i + 2u < g_dumpN) ? cur[i + 2u] : 0u),
                    (int)((i + 3u < g_dumpN) ? cur[i + 3u] : 0u));
    }
}

static void Diablo2DumpGrids(void)
{
    static const unsigned int kDesc[] = {
        0x6fbb1598u, 0x6fbb15e0u, 0x6fbb1680u, 0x6fbb16a8u,
        0x6fbb16c0u, 0x6fbb16d8u, 0x6fbb16f0u
    };
    static unsigned int last[7 * 3];
    static int          everLogged = 0;
    HMODULE cli = GetModuleHandleA("D2Client.dll");
    unsigned int i, x, y, cell, ctrl = 0;
    unsigned int cur[7 * 3];
    int changed = 0;

    if (!cli) return;

    /*
    ** A control read, so "all zero" can be told from "the read is broken".
    ** 0x6fba7034 is D2Client's live screen width, which Diablo2FixupClient
    ** has already forced -- if this comes back as the target width the
    ** accessor works and the descriptors really are empty.
    */
    ReadModuleGlobal(cli, 0x6fba7034u, &ctrl);

    for (i = 0; i < 7u; i++) {
        cur[i * 3 + 0] = cur[i * 3 + 1] = cur[i * 3 + 2] = 0;
    }
    for (i = 0; i < 7u; i++) {
        unsigned int base = 0;
        switch (i) {
        case 0: base = 0x6fbb1598u; break;  case 1: base = 0x6fbb15e0u; break;
        case 2: base = 0x6fbb1680u; break;  case 3: base = 0x6fbb16a8u; break;
        case 4: base = 0x6fbb16c0u; break;  case 5: base = 0x6fbb16d8u; break;
        default: base = 0x6fbb16f0u; break;
        }
        if (ReadModuleGlobal(cli, base + 0x04u, &x) &&
            ReadModuleGlobal(cli, base + 0x0cu, &y) &&
            ReadModuleGlobal(cli, base + 0x14u, &cell)) {
            cur[i * 3 + 0] = x; cur[i * 3 + 1] = y; cur[i * 3 + 2] = cell;
        }
    }
    for (i = 0; i < 7u * 3u; i++)
        if (cur[i] != last[i]) changed = 1;
    if (everLogged && !changed) return;   /* only speak when something moved */
    for (i = 0; i < 7u * 3u; i++) last[i] = cur[i];
    everLogged = 1;

    GameFix_Log("grids: panel descriptors (control: D2Client width reads %u,"
                " expected %u)", ctrl, g_targetW);
    for (i = 0; i < 7u; i++) {
        GameFix_Log("  %08lx  x=%-5d y=%-5d cell=%ux%u",
                    (unsigned long)kDesc[i], (int)cur[i * 3 + 0],
                    (int)cur[i * 3 + 1], cur[i * 3 + 2] & 0xffu,
                    (cur[i * 3 + 2] >> 8) & 0xffu);
    }
}

static void Diablo2FixupClient(void)
{
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    unsigned int w = 0;

    if (!cli || !g_targetRes) return;
    if (!ReadModuleGlobal(cli, 0x6fba7034u, &w)) return;
    if (w == g_targetW) return;                  /* already right */

    WriteModuleGlobal(cli, 0x6fba7034u, g_targetW);   /* screen w */
    WriteModuleGlobal(cli, 0x6fba7038u, g_targetH);   /* screen h */
    WriteModuleGlobal(cli, 0x6fba703cu, g_targetW);   /* screen w copy */
    WriteModuleGlobal(cli, 0x6fbd3d64u, g_targetW);   /* viewport w */
    WriteModuleGlobal(cli, 0x6fbd3d60u,
                      (g_targetH > 40u) ? (g_targetH - 40u) : g_targetH);

    GameFix_Log("  client was stale at %u wide -- forced to %ux%u",
                w, g_targetW, g_targetH);
}

static void Diablo2Report(void)
{
    HMODULE      cli = GetModuleHandleA("D2Client.dll");
    HMODULE      gl  = GetModuleHandleA("D2Glide.dll");
    unsigned int w = 0, h = 0, vw = 0, vh = 0, is800 = 0;

    if (cli &&
        ReadModuleGlobal(cli, 0x6fba7034u, &w)  &&
        ReadModuleGlobal(cli, 0x6fba7038u, &h)  &&
        ReadModuleGlobal(cli, 0x6fbd3d64u, &vw) &&
        ReadModuleGlobal(cli, 0x6fbd3d60u, &vh) &&
        ReadModuleGlobal(cli, 0x6fbcd2b4u, &is800))
        GameFix_Log("  live client: W=%u H=%u vpW=%u vpH=%u is800=%u",
                    w, h, vw, vh, is800);
    else
        GameFix_Log("  live client: %s", cli ? "unreadable" : "not loaded");

    if (gl &&
        ReadModuleGlobal(gl, 0x6f865a78u, &w) &&
        ReadModuleGlobal(gl, 0x6f865b14u, &h))
        GameFix_Log("  live glide:  W=%u H=%u", w, h);
    else
        GameFix_Log("  live glide:  %s", gl ? "unreadable" : "not loaded");
}

/* ------------------------------------------------------------------------ */
/* Cinematics: scaled to the screen                                           */
/* ------------------------------------------------------------------------ */
/*
** Diablo II plays its Bink movies in D2Glide, writing every decoded frame
** straight into the FRONT buffer through the LFB, 1:1, centred on its own idea
** of the screen size (0x6f865a78 W, 0x6f865b14 H):
**
**     6f85dabd  grLfbLock(WRITE_ONLY, FRONT, 8888, UPPER_LEFT, FALSE, &info)
**     6f85dc00  dstX = (W - bink.Width)  / 2, rounded up to 4
**     6f85dc22  dstY = (H - bink.Height) / 2
**     6f85daee  BinkCopyToBuffer(bink, info.lfbPtr, info.strideInBytes,
**                                bink.Height, dstX, dstY, 2)
**
** Stock, a movie gets a 640x480 context of its own and the monitor stretches
** it.  With the override every context is the full mode, so a 640x292 frame
** sits small in the middle of the screen.
**
** The fix takes over that one import.  The frame is decoded into a buffer of
** our own at its native size, then written into the LFB magnified -- as large
** as fits with its aspect kept, centred.  A 640x292 cinematic fills the height
** of a 1920x800 screen (1753x800); the 640x480 logos fill it at 1066x800.  The
** bars stay black: PlayMovie clears the screen before the first frame, and
** nothing here writes outside the picture.
**
** It is done at the Bink boundary and not with the Voodoo's overlay scaler.
** The scaler would cost nothing per frame, but it needs a context rendered at
** a different size from its video mode -- driver plumbing, not a game patch --
** and it cannot run alongside SLI or AA.  This costs CPU and bus bandwidth
** instead and leaves the context exactly as it was.
**
** The cost is bus bandwidth -- 1920x876 at four bytes a pixel is 6.7 MB a
** frame, 25 frames a second, which stutters -- so two things keep it down:
**
**   - 16 bits.  D2Glide's lock asks for 8888.  Its grLfbLock import is
**     wrapped so that this one lock asks for 565 instead, and the frame is
**     converted while it is expanded: half the bytes.  If the driver refuses
**     565 the original request goes through and the frame is written at 32.
**   - Only what changed.  Each source row is compared with the one written
**     last frame -- in system memory, where that costs nothing -- and the
**     screen lines it maps to are rewritten only if it differs.  Dark and slow
**     shots then cost almost nothing.  The first frame of a movie and any
**     change of size write everything.  This relies on nothing else touching
**     the front buffer mid-movie, and nothing does: PlayMovie clears it once,
**     before the first frame, and the loop never swaps.
**
** Nearest-neighbour both ways.  Each distinct source row is expanded once into
** a system-memory row, which is then copied to every screen line that maps to
** it: whole-row copies are what a write-combined LFB is good at, and the LFB
** is never READ -- reads cross the bus uncached.
**
** Every movie goes through here -- the startup logos and intro (D2Launch),
** the Cinematics menu, the in-game act movies (D2Client) -- because they all
** end in this one D2Glide routine, 0x6f85da50.
*/
#define D2_GL_IAT_BINKCOPY  0x6f8611b0u   /* D2Glide's _BinkCopyToBuffer@28 */
#define D2_GL_IAT_LFBLOCK   0x6f8611e0u   /* D2Glide's _grLfbLock@24 */
#define D2_GL_SCREEN_W      0x6f865a78u
#define D2_GL_SCREEN_H      0x6f865b14u
#define D2_MOVIE_MAX        2048u         /* sanity bound on a frame's size */
#define D2_SCREEN_MAX       4096u

typedef int (WINAPI *D2BinkCopyFn)(void *bink, void *dest, int pitch,
                                   unsigned int destH, unsigned int x,
                                   unsigned int y, unsigned int flags);

typedef struct {                          /* GrLfbInfo_t, glide3.h */
    int           size;
    void         *lfbPtr;
    unsigned int  strideInBytes;
    int           writeMode;
    int           origin;
} D2LfbInfo;

typedef int (WINAPI *D2LfbLockFn)(int type, int buffer, int writeMode,
                                  int origin, int pixelPipeline,
                                  D2LfbInfo *info);

static int           g_d2Movies     = 1;      /* [Diablo2] movies= */
static int           g_d2MovieTried = 0;
static HMODULE       g_d2MovieGl    = NULL;
static D2BinkCopyFn  g_d2BinkCopy   = NULL;   /* binkw32's own */
static D2LfbLockFn   g_d2LfbLock    = NULL;   /* the driver's own */
static unsigned int  g_d2MovieBpp   = 4;      /* of the lock just taken */

/* Scratch, grown on demand and kept: a movie is 25 frames a second.  The
   decoded frame must also PERSIST between frames of one movie, in case Bink
   only rewrites the blocks that changed. */
static unsigned int *g_d2MovieSrc   = NULL;   /* decoded frame, native size */
static unsigned int *g_d2MoviePrev  = NULL;   /* the frame last written */
static unsigned int  g_d2MovieSrcN  = 0;      /* pixels, both of the above */
static unsigned int *g_d2MovieRow   = NULL;   /* one expanded screen row */
static unsigned int *g_d2MovieXMap  = NULL;   /* screen x -> source x */
static unsigned int  g_d2MovieRowN  = 0;      /* pixels, both of the above */
static const void   *g_d2MovieBink  = NULL;   /* movie g_d2MoviePrev is of */
static unsigned int  g_d2MovieKey[5];         /* bw,bh,outW,outH,bpp */

static BOOL D2MovieGrow(unsigned int srcN, unsigned int rowN)
{
    HANDLE heap = GetProcessHeap();

    if (srcN > g_d2MovieSrcN) {
        if (g_d2MovieSrc)  HeapFree(heap, 0, g_d2MovieSrc);
        if (g_d2MoviePrev) HeapFree(heap, 0, g_d2MoviePrev);
        g_d2MovieSrc  = (unsigned int *)HeapAlloc(heap, HEAP_ZERO_MEMORY,
                                                  srcN * 4u);
        g_d2MoviePrev = (unsigned int *)HeapAlloc(heap, 0, srcN * 4u);
        g_d2MovieSrcN = srcN;
        g_d2MovieBink = NULL;                 /* Prev holds nothing yet */
        if (!g_d2MovieSrc || !g_d2MoviePrev) {
            if (g_d2MovieSrc)  HeapFree(heap, 0, g_d2MovieSrc);
            if (g_d2MoviePrev) HeapFree(heap, 0, g_d2MoviePrev);
            g_d2MovieSrc  = NULL;
            g_d2MoviePrev = NULL;
            g_d2MovieSrcN = 0;
            return FALSE;
        }
    }

    if (rowN > g_d2MovieRowN) {
        if (g_d2MovieRow)  HeapFree(heap, 0, g_d2MovieRow);
        if (g_d2MovieXMap) HeapFree(heap, 0, g_d2MovieXMap);
        g_d2MovieRow  = (unsigned int *)HeapAlloc(heap, 0, rowN * 4u);
        g_d2MovieXMap = (unsigned int *)HeapAlloc(heap, 0, rowN * 4u);
        g_d2MovieRowN = rowN;
        g_d2MovieKey[0] = 0;                  /* the x map must be rebuilt */
        if (!g_d2MovieRow || !g_d2MovieXMap) {
            if (g_d2MovieRow)  HeapFree(heap, 0, g_d2MovieRow);
            if (g_d2MovieXMap) HeapFree(heap, 0, g_d2MovieXMap);
            g_d2MovieRow  = NULL;
            g_d2MovieXMap = NULL;
            g_d2MovieRowN = 0;
            return FALSE;
        }
    }
    return TRUE;
}

/*
** Bilinear filtering, for the 565 path (the one normally taken).
**
** Worked in "spread" 565: the three fields pulled apart with gaps between
** them, green at 21..26, red at 11..15, blue at 0..4 --
**
**     0000 0GGG GGG0 0000 RRRR R000 000B BBBB        mask 0x07e0f81f
**
** -- so one multiply per pixel blends all three fields at once.  A 5-bit
** weight grows each field by at most 5 bits, and every gap above a field is
** at least that wide, so nothing carries into its neighbour.  Packing back to
** 565 is one OR and a shift.
**
** Two passes.  Each SOURCE row is widened once, blending along x, into one of
** two cached rows; each SCREEN row is then a blend of the two cached rows it
** falls between.  The x work is per source row (292 of them) and only the
** cheaper y blend is per screen row.  Rows whose sources did not change are
** still skipped, now judged on both source rows a screen row reads.
**
** Sampling is centre-aligned, in 1/32ths of a source pixel:
**     s32 = (2i+1) * n * 16 / out - 16
** which stays inside 32 bits for any frame and screen this file accepts.
*/
#define D2_SPREAD_MASK 0x07e0f81fu

static int           g_d2MovieFilter = 1;                  /* [Diablo2] moviefilter= */
static unsigned int  g_d2MovieSpread[D2_MOVIE_MAX + 1u];   /* a source row, spread */
static unsigned int  g_d2MovieWide[2][D2_SCREEN_MAX];      /* widened source rows */
static int           g_d2MovieWideY[2];                    /* which row each holds */
static unsigned char g_d2MovieXW[D2_SCREEN_MAX];           /* x weight, 0..31 */
static unsigned char g_d2MovieDirty[D2_MOVIE_MAX];         /* per source row */

static unsigned int D2Spread(unsigned int p)               /* 8888 -> spread 565 */
{
    return ((p >> 3) & 0x0000001fu) | ((p >> 8) & 0x0000f800u) |
           ((p << 11) & 0x07e00000u);
}

static unsigned int D2Blend(unsigned int a, unsigned int b, unsigned int w)
{
    return ((a * (32u - w) + b * w) >> 5) & D2_SPREAD_MASK;   /* w 0..31 */
}

/* Source row `sy`, widened to outW and blended along x.  Rows are asked for
   in ascending order within a frame, so the slot holding the LOWER row is the
   one that will not be wanted again. */
static const unsigned int *D2MovieWiden(unsigned int sy, unsigned int bw,
                                        unsigned int outW)
{
    const unsigned int *s = g_d2MovieSrc + sy * bw;
    unsigned int       *w;
    unsigned int        i, k;

    if (g_d2MovieWideY[0] == (int)sy) return g_d2MovieWide[0];
    if (g_d2MovieWideY[1] == (int)sy) return g_d2MovieWide[1];

    k = (g_d2MovieWideY[0] < g_d2MovieWideY[1]) ? 0u : 1u;
    for (i = 0; i < bw; i++) g_d2MovieSpread[i] = D2Spread(s[i]);
    g_d2MovieSpread[bw] = g_d2MovieSpread[bw - 1u];   /* for the last column */

    w = g_d2MovieWide[k];
    for (i = 0; i < outW; i++) {
        unsigned int x0 = g_d2MovieXMap[i];
        w[i] = D2Blend(g_d2MovieSpread[x0], g_d2MovieSpread[x0 + 1u],
                       g_d2MovieXW[i]);
    }
    g_d2MovieWideY[k] = (int)sy;
    return w;
}

/*
** Stands in for BinkCopyToBuffer in D2Glide's import table.
**
** `dest` is whatever the lock just before produced: 565 when the wrapper below
** got its way (g_d2MovieBpp 2), otherwise the 8888 D2Glide asked for.  At 8888
** anything this does not understand goes to the real BinkCopyToBuffer with the
** caller's own arguments, exactly as stock.  At 565 there is no such fallback
** -- Bink is asked for 32 bits and cannot write them into a 16-bit lock -- so
** every frame is drawn here, at native size and at the caller's own position
** when it cannot be magnified.
*/
static int WINAPI D2BinkCopyScaled(void *bink, void *dest, int pitch,
                                   unsigned int destH, unsigned int x,
                                   unsigned int y, unsigned int flags)
{
    const unsigned int *b   = (const unsigned int *)bink;
    unsigned int        bpp = g_d2MovieBpp;
    unsigned int  W = 0, H = 0, bw, bh, lfbW, maxW, fw, fh;
    unsigned int  outW, outH, x0, y0, row, sy, lastSy, i;
    unsigned char *line;
    int            r, full, dirty = 0;

    g_d2MovieBpp = 4u;                        /* one lock, one copy */

    bw = b ? b[0] : 0u;                       /* BINK.Width, BINK.Height */
    bh = b ? b[1] : 0u;
    if (!dest || pitch <= 0 || bw == 0u || bh == 0u ||
        bw > D2_MOVIE_MAX || bh > D2_MOVIE_MAX)
        return (bpp == 4u)
               ? g_d2BinkCopy(bink, dest, pitch, destH, x, y, flags) : 0;

    /* The stock placement, unless it can be magnified. */
    outW = bw;  outH = bh;  x0 = x;  y0 = y;

    if (ReadModuleGlobal(g_d2MovieGl, D2_GL_SCREEN_W, &W) &&
        ReadModuleGlobal(g_d2MovieGl, D2_GL_SCREEN_H, &H) &&
        W != 0u && H != 0u && W <= D2_SCREEN_MAX && H <= D2_SCREEN_MAX) {
        /* How wide the lock is, from its own stride.  The 565 lock is the
           raw buffer (glfb.c: write-only in the framebuffer's own format)
           and is as wide as the screen.  The 8888 one is the 3D LFB, which
           is 2048 pixels wide whatever the screen, so on a wider screen only
           its left 2048 columns can be reached: the picture is centred on
           the SCREEN, so its right edge, (W + outW) / 2, has to stay inside,
           i.e. outW <= 2*lfbW - W. */
        lfbW = (unsigned int)pitch / bpp;
        if (W <= lfbW)          maxW = W;
        else if (2u * lfbW > W) maxW = 2u * lfbW - W;
        else                    maxW = 0u;

        /* As large as fits with the aspect kept: whichever of maxW/bw and
           H/bh is smaller limits, compared by cross-multiplying. */
        if (maxW * bh <= H * bw) { fw = maxW; fh = (bh * maxW) / bw; }
        else                     { fh = H;    fw = (bw * H) / bh; }

        if (fw > bw && fh > bh) {             /* magnification only */
            outW = fw;
            outH = fh;
            x0   = ((W - fw) / 2u) & ~1u;     /* even: dword-aligned rows */
            y0   = (H - fh) / 2u;
        }
    }

    if (bpp == 4u && outW == bw)              /* nothing to scale or convert */
        return g_d2BinkCopy(bink, dest, pitch, destH, x, y, flags);

    if (!D2MovieGrow(bw * bh, outW))
        return (bpp == 4u)
               ? g_d2BinkCopy(bink, dest, pitch, destH, x, y, flags) : 0;

    r = g_d2BinkCopy(bink, g_d2MovieSrc, (int)(bw * 4u), bh, 0u, 0u, flags);

    /* BINK.FrameNum is 1 on a movie's first frame. */
    full = (bink != g_d2MovieBink) || (b[3] <= 1u);
    g_d2MovieBink = bink;

    /* The x map, rebuilt when anything it depends on changes.  Bilinear is
       only for a magnified frame going into the 565 lock: native size has
       nothing to filter, and the 32-bit fallback stays nearest.  The choice
       rides in the key (bit 8 of [4]) so the paths below can read it. */
    {
        unsigned int filt = (g_d2MovieFilter && bpp == 2u &&
                             outW > bw && outH > bh) ? 1u : 0u;

        if (g_d2MovieKey[0] != bw   || g_d2MovieKey[1] != bh ||
            g_d2MovieKey[2] != outW || g_d2MovieKey[3] != outH ||
            g_d2MovieKey[4] != (bpp | (filt << 8))) {
            for (i = 0; i < outW; i++) {
                if (filt) {
                    int          s32 = (int)(((2u * i + 1u) * bw * 16u) / outW)
                                       - 16;
                    unsigned int sx;
                    if (s32 < 0) s32 = 0;
                    sx = (unsigned int)s32 >> 5;
                    g_d2MovieXW[i] = (unsigned char)(s32 & 31);
                    if (sx >= bw - 1u) { sx = bw - 1u; g_d2MovieXW[i] = 0; }
                    g_d2MovieXMap[i] = sx;
                } else {
                    /* Nearest, sampled at pixel centres, so the picture is
                       not pulled half a source pixel towards the top left. */
                    g_d2MovieXMap[i] = ((2u * i + 1u) * bw) / (2u * outW);
                }
            }
            g_d2MovieKey[0] = bw;
            g_d2MovieKey[1] = bh;
            g_d2MovieKey[2] = outW;
            g_d2MovieKey[3] = outH;
            g_d2MovieKey[4] = bpp | (filt << 8);
            full = 1;
            GameFix_Log("movie: %ux%u frame drawn %ux%u at %u,%u of %ux%u,"
                        " %u-bit %s", bw, bh, outW, outH, x0, y0, W, H,
                        bpp * 8u, filt ? "bilinear" : "nearest");
        }
    }

    line   = (unsigned char *)dest + y0 * (unsigned int)pitch + x0 * bpp;

    if (g_d2MovieKey[4] & 0x100u) {
        unsigned short *o = (unsigned short *)g_d2MovieRow;

        /* Which source rows changed, judged once for the frame: a screen
           row reads two of them. */
        for (row = 0; row < bh; row++) {
            const unsigned int *s = g_d2MovieSrc  + row * bw;
            unsigned int       *p = g_d2MoviePrev + row * bw;

            g_d2MovieDirty[row] =
                (unsigned char)(full || memcmp(s, p, bw * 4u) != 0);
            if (g_d2MovieDirty[row]) memcpy(p, s, bw * 4u);
        }
        g_d2MovieWideY[0] = -1;
        g_d2MovieWideY[1] = -1;

        for (row = 0; row < outH; row++, line += pitch) {
            const unsigned int *wa, *wb;
            int          s32 = (int)(((2u * row + 1u) * bh * 16u) / outH) - 16;
            unsigned int fy, sy1;

            if (s32 < 0) s32 = 0;
            sy = (unsigned int)s32 >> 5;
            fy = (unsigned int)s32 & 31u;
            if (sy >= bh - 1u) { sy = bh - 1u; fy = 0u; }
            sy1 = fy ? sy + 1u : sy;
            if (!g_d2MovieDirty[sy] && !g_d2MovieDirty[sy1]) continue;

            /* wa stays valid across the second call: the slot it would
               replace always holds a row below sy. */
            wa = D2MovieWiden(sy, bw, outW);
            if (fy == 0u) {
                for (i = 0; i < outW; i++)
                    o[i] = (unsigned short)(wa[i] | (wa[i] >> 16));
            } else {
                wb = D2MovieWiden(sy1, bw, outW);
                for (i = 0; i < outW; i++) {
                    unsigned int s = D2Blend(wa[i], wb[i], fy);
                    o[i] = (unsigned short)(s | (s >> 16));
                }
            }
            memcpy(line, o, outW * 2u);
        }
        return r;
    }
    lastSy = 0xffffffffu;
    for (row = 0; row < outH; row++) {
        sy = ((2u * row + 1u) * bh) / (2u * outH);
        if (sy != lastSy) {
            const unsigned int *src  = g_d2MovieSrc  + sy * bw;
            unsigned int       *prev = g_d2MoviePrev + sy * bw;

            dirty = full || memcmp(src, prev, bw * 4u) != 0;
            if (dirty) {
                memcpy(prev, src, bw * 4u);
                if (bpp == 2u) {
                    unsigned short *o = (unsigned short *)g_d2MovieRow;
                    for (i = 0; i < outW; i++) {
                        unsigned int p = src[g_d2MovieXMap[i]];
                        o[i] = (unsigned short)(((p >> 8) & 0xf800u) |
                                                ((p >> 5) & 0x07e0u) |
                                                ((p >> 3) & 0x001fu));
                    }
                } else {
                    for (i = 0; i < outW; i++)
                        g_d2MovieRow[i] = src[g_d2MovieXMap[i]];
                }
            }
            lastSy = sy;
        }
        if (dirty) memcpy(line, g_d2MovieRow, outW * bpp);
        line += pitch;
    }
    return r;
}

/*
** Stands in for grLfbLock in D2Glide's import table.  D2Glide takes two
** locks: the movie's (write-only, front, 8888, upper left, no pipeline) at
** 0x6f85dabd, and a screenshot's (read-only, back, any) at 0x6f85caa0.  Only
** the first matches, and it is asked for 565 instead; D2BinkCopyScaled, which
** always follows it, is told through g_d2MovieBpp.  If the driver refuses,
** the original request goes through untouched.
*/
static int WINAPI D2LfbLockMovie(int type, int buffer, int writeMode,
                                 int origin, int pixelPipeline,
                                 D2LfbInfo *info)
{
    g_d2MovieBpp = 4u;
    if (type == 1 && buffer == 0 && writeMode == 5 && origin == 0 &&
        !pixelPipeline && info &&
        g_d2LfbLock(type, buffer, 0 /* 565 */, origin, pixelPipeline, info)) {
        g_d2MovieBpp = 2u;
        return 1;
    }
    return g_d2LfbLock(type, buffer, writeMode, origin, pixelPipeline, info);
}

/*
** Once.  Each slot must still hold the export it was built against: a
** different build, or some other tool that hooked it first, is left alone.
** Without the BinkCopyToBuffer hook the movies play at native size as before;
** without the grLfbLock one they are scaled but written at 32 bits.
*/
static void Diablo2InstallMovieHook(void)
{
    HMODULE      gl, bink, gx;
    FARPROC      real, lock;
    unsigned int cur = 0;

    if (g_d2MovieTried || !g_d2Movies) return;
    gl = GetModuleHandleA("D2Glide.dll");
    if (!gl) return;                          /* not yet: try again later */
    g_d2MovieTried = 1;

    bink = GetModuleHandleA("binkw32.dll");
    real = bink ? GetProcAddress(bink, "_BinkCopyToBuffer@28") : NULL;
    if (!real || !ReadModuleGlobal(gl, D2_GL_IAT_BINKCOPY, &cur) ||
        cur != (unsigned int)real) {
        GameFix_Log("movie: BinkCopyToBuffer slot is %08lx, expected %08lx"
                    " -- movies left at native size",
                    (unsigned long)cur, (unsigned long)(unsigned int)real);
        return;
    }

    g_d2MovieGl  = gl;
    g_d2BinkCopy = (D2BinkCopyFn)real;
    if (!WriteModuleGlobal(gl, D2_GL_IAT_BINKCOPY,
                           (unsigned int)&D2BinkCopyScaled)) {
        GameFix_Log("movie: could not write the BinkCopyToBuffer slot");
        return;
    }
    GameFix_Log("movie: BinkCopyToBuffer hooked, real=%08lx",
                (unsigned long)cur);

    /* 16-bit writes.  Optional: the scaling works without them. */
    gx   = GetModuleHandleA("glide3x.dll");
    lock = gx ? GetProcAddress(gx, "_grLfbLock@24") : NULL;
    cur  = 0;
    if (!lock || !ReadModuleGlobal(gl, D2_GL_IAT_LFBLOCK, &cur) ||
        cur != (unsigned int)lock) {
        GameFix_Log("movie: grLfbLock slot is %08lx, expected %08lx"
                    " -- frames written at 32 bits",
                    (unsigned long)cur, (unsigned long)(unsigned int)lock);
        return;
    }

    g_d2LfbLock = (D2LfbLockFn)lock;
    if (!WriteModuleGlobal(gl, D2_GL_IAT_LFBLOCK,
                           (unsigned int)&D2LfbLockMovie)) {
        GameFix_Log("movie: could not write the grLfbLock slot"
                    " -- frames written at 32 bits");
        return;
    }
    GameFix_Log("movie: grLfbLock hooked -- frames written at 16 bits");
}

/*
** Per-module gates, from wideDriver.ini beside the exe:
**
**   [Diablo2]
**   gfx=1        D2gfx.dll    GetResolutionSize
**   client=1     D2Client.dll live screen size
**   glide=1      D2Glide.dll  renderer size globals
**   movies=1     D2Glide.dll  cinematics scaled to the screen
**
** All default to 1.  They exist because the three groups fail differently and
** a hardware trip per guess is the expensive currency here: setting all three
** to 0 is a control run that leaves only the driver's own resolution override
** in play, which separates "our patch broke it" from "this game and this
** override do not get along" without a rebuild.
*/
static int g_d2Gfx    = 1;
static int g_d2Client = 1;
static int g_d2Glide  = 1;

static void Diablo2ReadIni(const char *ini)
{
    if (!ini) return;
    g_d2Gfx    = (int)GetPrivateProfileIntA("Diablo2", "gfx",    1, ini);
    g_d2Client = (int)GetPrivateProfileIntA("Diablo2", "client", 1, ini);
    g_d2Glide  = (int)GetPrivateProfileIntA("Diablo2", "glide",  1, ini);
    g_d2Movies = (int)GetPrivateProfileIntA("Diablo2", "movies", 1, ini);
    g_d2MovieFilter = (int)GetPrivateProfileIntA("Diablo2", "moviefilter", 1, ini);
    g_d2Trace  = (int)GetPrivateProfileIntA("Diablo2", "traceui", 0, ini);
    g_d2Menu   = (int)GetPrivateProfileIntA("Diablo2", "menu",    1, ini);
    g_d2InvGrid = (int)GetPrivateProfileIntA("Diablo2", "invgrid", 1, ini);
    g_d2Belt    = (int)GetPrivateProfileIntA("Diablo2", "belt",    1, ini);
    {
        char w[48];
        w[0] = 0;
        GetPrivateProfileStringA("Diablo2", "dumpwords", "", w, sizeof(w), ini);
        if (w[0]) {
            const char *p = w;
            unsigned int v = 0;
            while (*p && *p != ',') {          /* hex address */
                char c = *p++;
                if      (c >= '0' && c <= '9') v = v * 16u + (unsigned int)(c - '0');
                else if (c >= 'a' && c <= 'f') v = v * 16u + (unsigned int)(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') v = v * 16u + (unsigned int)(c - 'A' + 10);
                else break;
            }
            g_dumpAt = v;
            if (*p == ',') p++;
            v = 0;
            while (*p >= '0' && *p <= '9') v = v * 10u + (unsigned int)(*p++ - '0');
            g_dumpN = (v > D2_DUMP_MAX) ? D2_DUMP_MAX : v;
        }
    }
    g_traceEvery = (unsigned int)GetPrivateProfileIntA("Diablo2", "traceevery",
                                                       0, ini);
    {
        char box[64];
        box[0] = 0;
        GetPrivateProfileStringA("Diablo2", "watchbox", "", box, sizeof(box), ini);
        if (box[0]) {
            const char *p = box;
            int i, v, neg;
            for (i = 0; i < 4 && *p; i++) {
                while (*p == ' ' || *p == ',') p++;
                neg = (*p == '-'); if (neg) p++;
                v = 0;
                while (*p >= '0' && *p <= '9') v = v * 10 + (*p++ - '0');
                g_box[i] = neg ? -v : v;
            }
            g_boxOn = (g_box[2] > g_box[0] && g_box[3] > g_box[1]);
        }
    }
}

/*
** Adopting the resolution is unconditional on purpose.  An earlier version
** guarded it on the host being Game.exe with D2gfx.dll already mapped, which
** is wrong in a way that is easy to miss: the three profiles are applied
** independently, so a guard that declined would leave the tables full of
** placeholder ZEROES and the other two profiles would then happily write a 0x0
** screen size.
**
** Filling them costs nothing and cannot misfire: only the Diablo II profiles
** read these bytes, and those are keyed on Game.exe and on patterns that exist
** in no other program.
*/
static void Diablo2Apply(const char *exePath, const char *ini)
{
    (void)exePath;
    Diablo2ReadIni(ini);
    Diablo2AdoptResolution();
}


/* ======================================================================== */
/* Profile table                                                            */
/* ======================================================================== */

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const GameProfile g_profiles[] = {
    /*
    ** Diablo II.  The host is Game.exe -- "Diablo II.exe" is a 36 KB launcher
    ** that CreateProcess()es it -- but it is listed too so the log records
    ** that the launcher ran and matched nothing to patch.
    **
    ** The three modules arrive at different times, so a profile whose module
    ** is not mapped yet returns "try again later" and GameFix_Tick retries.
    */
    { "Game.exe", "D2gfx.dll",    d2_gfx_patches,    COUNT(d2_gfx_patches),
      &g_d2Gfx },
    { "Game.exe", "D2Client.dll", d2_client_patches, COUNT(d2_client_patches),
      &g_d2Client },
    { "Game.exe", "D2Glide.dll",  d2_glide_patches,  COUNT(d2_glide_patches),
      &g_d2Glide }
};

static const unsigned int g_profileCount = COUNT(g_profiles);

/*
** The gate itself.  Cached: called from per-frame paths through the log.
**
** A profile's exeName is matched with PathEndsWith, exactly as GameFix_Apply
** matches it, so the two cannot disagree about whose process this is.
*/
static int GameFix_ExeIsOurs(void)
{
    static int   ours = -1;
    unsigned int i;

    if (ours >= 0) return ours;

    if (!g_exeKnown) {
        DWORD len = GetModuleFileNameA(NULL, g_exePath, MAX_PATH);
        if (len == 0 || len >= (DWORD)MAX_PATH) return 0;   /* retry later */
        g_exeKnown = 1;
    }

    ours = 0;
    for (i = 0; i < g_profileCount; i++) {
        if (PathEndsWith(g_exePath, g_profiles[i].exeName)) { ours = 1; break; }
    }
    return ours;
}


/* ======================================================================== */
/* Public entry points                                                      */
/* ======================================================================== */

/*
** A Glide resolution enum from `[GameFix] resolution=` in wideDriver.ini
** beside the exe, or 0.
**
** This is how a game runs wide WITHOUT arming FX_GLIDE_OVERRIDE_RESOLUTION.
** The override forces the mode behind the application's back and applies to
** every Glide app on the machine; naming the resolution here instead patches
** the game to ASK for it, which is both narrower in blast radius and, for
** Diablo II, the configuration that behaves.
**
** The caller turns this into pixels via the driver's own _resTable -- this
** file deliberately has no second copy of that table.  Decimal or 0x hex.
*/
int GameFix_IniResolution(void)
{
    char ini[MAX_PATH];
    char buf[32];

    if (!GameFix_ExeIsOurs()) return 0;
    if (!PathBesideExe(GAMEFIX_INI, ini)) return 0;

    buf[0] = '\0';
    GetPrivateProfileStringA("GameFix", "resolution", "", buf, sizeof(buf), ini);
    if (!buf[0]) return 0;

    if (buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X')) {
        int v = 0;
        const char *p = buf + 2;
        while (*p) {
            char c = *p++;
            if      (c >= '0' && c <= '9') v = v * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v = v * 16 + (c - 'A' + 10);
            else break;
        }
        return v;
    }

    return (int)GetPrivateProfileIntA("GameFix", "resolution", 0, ini);
}

int GameFix_SetTargetResolution(unsigned int glideEnum,
                                unsigned int w, unsigned int h)
{
    /* The driver ignores anything <= 1 (gsst.c tests `> 1`), which is how
       "Disabled" is expressed, so we must treat those the same way or we would
       patch the game for a resolution the driver is not going to set. */
    if (glideEnum <= 1) return 0;
    if (!w || !h) return 0;

    g_targetRes = glideEnum;
    g_targetW   = w;
    g_targetH   = h;
    return 1;
}

/*
** Read the master switch once.  Env first, then the ini, matching how the log
** switch is decided.
*/
static int GameFix_Enabled(const char *ini)
{
    char env[32];

    if (g_enabled >= 0) return g_enabled;

    g_enabled = 1;

    if (GetEnvironmentVariableA("FX_GLIDE_GAMEFIX", env, sizeof(env)) != 0 &&
        env[0] == '0')
        g_enabled = 0;

    if (g_enabled && ini &&
        GetPrivateProfileIntA("GameFix", "enable", 1, ini) == 0)
        g_enabled = 0;

    return g_enabled;
}

void GameFix_Apply(void)
{
    const char  *exePath;
    char         ini[MAX_PATH];
    BOOL         haveIni;
    unsigned int i;

    /* Before anything, including the crash filter and the watchdog: those
       install per process and write files beside the exe, and this DLL is
       loaded by every Glide app on the machine. */
    if (!GameFix_ExeIsOurs()) return;

    if (!g_exeKnown) {
        DWORD len = GetModuleFileNameA(NULL, g_exePath, MAX_PATH);
        if (len == 0 || len >= (DWORD)MAX_PATH) return;
        g_exeKnown = 1;
    }
    exePath = g_exePath;

    g_applyRuns++;

    /* Logged BEFORE the guard below, so "ran with no override" and "never ran
       at all" do not both look like an absent log file. */
    if (g_applyRuns == 1) {
        GameFix_InstallCrashFilter();
        GameFix_StartWatchdog();
        GameFix_Log("gamefix: exe=%s", exePath);
        GameFix_Log("gamefix: res=%u (%ux%u)", g_targetRes, g_targetW, g_targetH);
    }

    /*
    ** Nothing is patched until the target resolution is known.
    **
    ** With the override disabled there is nothing to fix -- the game runs at a
    ** mode it was designed for and should be left completely alone rather than
    ** patched with values that merely happen to be inert.
    **
    ** It also protects against the ordering hazard: an early call that baked
    ** 640x480-derived constants into the image would ALSO consume the find
    ** patterns, so the later, correct call would find nothing left to patch
    ** and would silently leave the wrong values in place.  Idempotency guards
    ** against applying a patch twice; it cannot guard against applying the
    ** wrong one first.
    */
    if (!g_targetRes) return;

    haveIni = PathBesideExe(GAMEFIX_INI, ini);
    if (g_applyRuns == 1)
        GameFix_Log("gamefix: ini=%s", haveIni ? ini : "(none)");

    if (!GameFix_Enabled(haveIni ? ini : NULL)) {
        if (g_applyRuns == 1) {
            GameFix_Log("gamefix: DISABLED -- driver override only");
            GameFix_LogFlush();
        }
        return;
    }

    /*
    ** Per-game setup FIRST.  Every resolution-dependent immediate has to be
    ** built before the profile loop runs, or the loop would burn each
    ** pattern's find bytes writing placeholder zeroes -- and then the correct
    ** values would have nothing left to match.  Idempotency protects against
    ** applying a patch twice; it cannot protect against applying the wrong one
    ** first.
    */
    Diablo2Apply(exePath, haveIni ? ini : NULL);

    g_pending = 0;
    for (i = 0; i < g_profileCount; i++) {
        if (!PathEndsWith(exePath, g_profiles[i].exeName)) continue;
        g_matched = 1;
        if (g_profileDone & (1u << i)) continue;

        /* An off profile is marked done, not left pending: it is a decision,
           not a module that has yet to arrive. */
        if (g_profiles[i].enable && *g_profiles[i].enable == 0) {
            GameFix_Log("profile %s / %s: DISABLED by ini",
                        g_profiles[i].exeName,
                        g_profiles[i].moduleName ? g_profiles[i].moduleName
                                                 : "(exe)");
            g_profileDone |= (1u << i);
            continue;
        }

        if (ApplyProfile(&g_profiles[i]))
            g_profileDone |= (1u << i);
        else
            g_pending = 1;
    }

    Diablo2FixupClient();
    Diablo2InstallDrawHook();
    Diablo2InstallMovieHook();     /* D2Glide is mapped: it called grGlideInit */
    Diablo2Report();

    GameFix_LogFlush();
}

/*
** Is any matched-but-unpatched profile's module mapped now?
**
** Uses the cached exe path: an earlier version called GetModuleFileNameA here,
** which meant a loader call on EVERY grBufferSwap for as long as a profile
** stayed outstanding -- and for Diablo II that is the whole main menu, because
** D2Client.dll is not loaded until a game starts.  A loader call per swap from
** inside a fullscreen Glide context on Win9x is not something to do casually.
** What is left is one GetModuleHandleA per outstanding profile, and the caller
** throttles even that.
*/
static BOOL GameFix_ModuleArrived(void)
{
    unsigned int i;

    if (!g_exeKnown) return FALSE;

    for (i = 0; i < g_profileCount; i++) {
        if (g_profileDone & (1u << i)) continue;
        if (!PathEndsWith(g_exePath, g_profiles[i].exeName)) continue;
        if (GetModuleHandleA(g_profiles[i].moduleName)) return TRUE;
    }
    return FALSE;
}

/*
** Called once per grBufferSwap.
**
** This runs inside the render loop of a fullscreen Glide app, so the rule here
** is absolute: NO file I/O, and no Win32 call at all in the common case.  An
** earlier version wrote the diagnostic log from here and froze the machine --
** see g_inSwap.  What is left is an integer test per swap, plus one
** GetModuleHandleA every 15 swaps while a module is still outstanding.
*/
void GameFix_Tick(void)
{
    static unsigned int frame = 0;

    if (g_enabled == 0) return;
    if (!g_matched) return;

    frame++;
    g_d2Frame = frame;

    g_inSwap = 1;

    /* Throttled: a module that has just appeared can wait a quarter of a
       second to be patched -- D2Client's own resolution call comes later than
       that -- and this keeps the common case, where nothing is outstanding,
       down to a single integer test per swap.  Any logging GameFix_Apply does
       is buffered, not written; g_inSwap sees to that. */
    if (g_pending && (frame % 15u) == 0 && GameFix_ModuleArrived())
        GameFix_Apply();

    /* D2Client can finish loading and stamp its stale 800x600 at any point,
       so keep checking -- once a second, and it early-outs on one read as
       soon as the value is right. */
    if (g_targetRes && (frame % 60u) == 0) {
        Diablo2FixupClient();
        Diablo2InstallDrawHook();      /* D2Client arrives after the menu */
    }

    /* Once, and late enough that the panels have been populated from the
       game's data files. */
    /* Every couple of seconds, but it only logs when a value CHANGES -- the
       descriptors may well not be filled until a panel is first opened. */
    if (g_targetRes && (frame % 120u) == 0) Diablo2DumpGrids();
    if (g_targetRes && (frame % 120u) == 0) Diablo2DumpWords();

    /* Often, and cheap: one read that early-outs once the value is right.
       The descriptor is filled lazily, so there is no single moment to do
       this at -- it has to be watched for. */
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupInvGrid();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupEquipSlots();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupMercPanel();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupHitRegions();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupYBounds();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupSwapTip();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupSkillPopup();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupQuestBtn();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupQuestBtnRows();
    if (g_targetRes && (frame % 30u) == 0) Diablo2FixupQuestIcons();
    if (g_targetRes && (frame % 30u) == 0) Diablo2InstallBeltHook();

    /* Re-arm the trace, so a panel opened later than the first second still
       shows up.  Cheap: a clear over the sites actually seen. */
    if (g_d2Trace && g_traceEvery && (frame % g_traceEvery) == 0) {
        TraceRearm();
        g_boxHits = 0;             /* the watch box re-arms with the trace */
        {
            unsigned int b;
            for (b = 0; b < g_boxSites; b++) g_boxSiteHits[b] = 0;
        }
        GameFix_Log("trace: re-armed %u sites at frame %u", g_traceSites, frame);
    }

    /*
    ** Whether the front end is up, evaluated once a frame rather than once per
    ** sprite: the draw hook fires hundreds of times a frame and must not be
    ** making loader calls.
    **
    ** "D2Client is not loaded" is true before the first game and never again --
    ** the module stays mapped once loaded, so quitting a game back to the menu
    ** left the front end uncentred.  What actually distinguishes the two is who
    ** is DRAWING: D2Client paints the world every frame during a game and not
    ** one sprite while the menu is up, where D2Launch drives D2Win instead.
    **
    ** So: not loaded, or loaded but silent for a few frames.  The margin is
    ** there because a frame in which the client happens to draw nothing should
    ** not flick the menu sideways; it costs a few frames of stale answer on the
    ** way back to the menu, which nothing is watching.
    */
    if (g_matched) {
        g_d2FrontEnd = (GetModuleHandleA("D2Client.dll") == NULL) ||
                       ((g_d2Frame - g_d2CliDrawn) > 3u);
    }

    /* Sample what the game believes, into memory only.  Sparse, because a
       freeze loses the buffer anyway and the setup-time record is the part
       that has earned its keep. */
    if (g_targetRes && (frame % 600u) == 0) {
        GameFix_Log("tick %u:", frame);
        Diablo2Report();
    }

    g_inSwap = 0;
}

/*
** Write out whatever is buffered.  Call from grGlideShutdown / process detach:
** the display is being torn down there, so file I/O is safe again, and it is
** the only thing that gets the render-loop samples onto disk.
*/
void GameFix_Shutdown(void)
{
    g_inSwap = 0;
    GameFix_LogFlush();
}
