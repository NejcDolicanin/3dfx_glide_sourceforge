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

#define GAMEFIX_LOG_CAP  (32u * 1024u)

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
** Enabled by [GameFix] log=1 in wideDriver.ini beside the exe, or by the
** FX_GLIDE_GAMEFIX_LOG environment variable.  Decided once and cached: this is
** called from per-frame paths.
*/
static int GameFix_LogEnabled(void)
{
    char ini[MAX_PATH];
    char env[32];

    if (g_logOn >= 0) return g_logOn;

    g_logOn = 0;

    if (GetEnvironmentVariableA("FX_GLIDE_GAMEFIX_LOG", env, sizeof(env)) != 0 &&
        env[0] != '0')
        g_logOn = 1;

    if (!g_logOn && PathBesideExe(GAMEFIX_INI, ini) &&
        GetPrivateProfileIntA("GameFix", "log", 0, ini) != 0)
        g_logOn = 1;

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
    if (g_logLen + (unsigned int)n + 2 >= GAMEFIX_LOG_CAP) {
        /* Say so rather than falling silent.  A diagnostic that stops
           recording looks exactly like an event that never happened. */
        g_logFull = 1;
        if (g_logLen + 24 < GAMEFIX_LOG_CAP) {
            memcpy(g_logBuf + g_logLen, "-- LOG FULL --\r\n", 16);
            g_logLen += 16;
        }
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
    { "D2Client.dll", 0x6fb7fc58u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli gfx#10013" },
    { "D2Client.dll", 0x6fb7fbc0u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10150" },
    { "D2Client.dll", 0x6fb7fbd0u, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10047" },
    { "D2Client.dll", 0x6fb7fbdcu, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10069" },
    { "D2Client.dll", 0x6fb7fbbcu, 0x6fab0000u, ARG_NONE, ARG_NONE, "cli win#10137" },
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
#define D2_HOOKS       30
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
    unsigned char xmode;
    unsigned char ymode;
    const char   *what;
} D2Fix2D;

static const D2Fix2D g_d2Fix2D[] = {
    /* control panel: frame, inlay, orb liquid and the icon beside each orb */
    { D2_TAG_CLIENT, 0x06d54eu, ADJ_X_AUTO, ADJ_Y_NONE,   "orb frame L"  },
    { D2_TAG_CLIENT, 0x06d62bu, ADJ_X_AUTO, ADJ_Y_NONE,   "orb frame R"  },
    { D2_TAG_CLIENT, 0x06df5au, ADJ_X_AUTO, ADJ_Y_NONE,   "orb inlay L"  },
    { D2_TAG_CLIENT, 0x06ddd3u, ADJ_X_AUTO, ADJ_Y_NONE,   "orb inlay R"  },
    { D2_TAG_CLIENT, 0x06df2du, ADJ_X_AUTO, ADJ_Y_NONE,   "orb liquid L" },
    { D2_TAG_CLIENT, 0x06dda2u, ADJ_X_AUTO, ADJ_Y_NONE,   "orb liquid R" },
    { D2_TAG_CLIENT, 0x0a7254u, ADJ_X_AUTO, ADJ_Y_NONE,   "orb icon L+R" },
    /* belt: raw 800x600, so it needs the vertical offset as well */
    { D2_TAG_CLIENT, 0x05f597u, ADJ_X_AUTO, ADJ_Y_BOTTOM, "belt items"   },
    { D2_TAG_CLIENT, 0x06f2a8u, ADJ_X_AUTO, ADJ_Y_BOTTOM, "belt digits"  }
};
#define D2_FIX2D_N (sizeof(g_d2Fix2D) / sizeof(g_d2Fix2D[0]))

static int            g_d2Trace    = 0;
static int            g_d2Menu     = 1;   /* centre the front end */
static int            g_d2FrontEnd = 0;   /* front end up (D2Client absent) */
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
        if (tag == D2_TAG_WIN) {
            if (g_d2Menu && g_d2FrontEnd) {
                *px += cx; *py += cy; applied = 1; what = "menu";
            }
        } else if (h->base == 0x6fab0000u) {
            /* Matched on the caller's RVA alone: an RVA is unique within the
               module, so keying on the hook index too would only make the
               table fragile against reordering the hook list. */
            for (i = 0; i < D2_FIX2D_N; i++) {
                if (g_d2Fix2D[i].rva != rva) continue;
                switch (g_d2Fix2D[i].xmode) {
                case ADJ_X_ADD:  *px += cx; break;
                case ADJ_X_SUB:  *px -= cx; break;
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

/*
** Per-module gates, from wideDriver.ini beside the exe:
**
**   [Diablo2]
**   gfx=1        D2gfx.dll    GetResolutionSize
**   client=1     D2Client.dll live screen size
**   glide=1      D2Glide.dll  renderer size globals
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
    g_d2Trace  = (int)GetPrivateProfileIntA("Diablo2", "traceui", 0, ini);
    g_d2Menu   = (int)GetPrivateProfileIntA("Diablo2", "menu",    1, ini);
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

    /* Whether the front end is up, evaluated once a frame rather than once
       per sprite: the draw hook fires hundreds of times a frame and must not
       be making loader calls. */
    if (g_matched)
        g_d2FrontEnd = (GetModuleHandleA("D2Client.dll") == NULL);

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
