/*
** gamefix.h -- per-game runtime binary patches, driver-side.
**
** Ported from the Glide2->Glide3 wrapper (GlideXp/GLIDE2X/gamefix.cpp), where
** the same machinery carries the widescreen fixes for GTA2, Turok, Ignition,
** MDK and Driver.  Those are Glide2 games, so the wrapper is in their call
** path and is the right place for them.  A game that talks Glide3 directly --
** Diablo II is the first -- never loads the wrapper at all, so its fixes have
** to live here.
**
** The method is written down in GlideXp/GLIDE2X/GAME-PATCHING.md.  Read it
** before adding a game.  Per-game addresses and reasoning live in gamefix.c
** next to the code that uses them; this header is only the boundary.
**
** Deliberately free of any Glide internals: gamefix.c includes <windows.h> and
** the C runtime and nothing else, so the pair stays interchangeable with the
** wrapper's copy.  Everything that needs to know about _GlideRoot or _resTable
** is done by the CALLER and handed in through the two functions below.
*/

#ifndef GAMEFIX_H
#define GAMEFIX_H

#ifdef __cplusplus
extern "C" {
#endif

/*
** Tell gamefix what the screen is actually going to be.
**
** The driver's "Glide Override Resolution" setting is the single source of
** truth: whatever it names is what grSstWinOpen will force, so it is what the
** game's projection, HUD layout and mode list all have to agree with.  The
** caller reads _GlideRoot.environment.glideResOverride and looks the pixels up
** in _resTable, so there is exactly one resolution table in the build and this
** file does not carry a second, drifting copy of it.
**
** `glideEnum` <= 1 means "Disabled" and is rejected, matching the driver's own
** test (glideResOverride > 1, gsst.c).  Call BEFORE GameFix_Apply; without it
** the target stays 640x480 and GameFix_Apply does nothing at all, which leaves
** the game running exactly as it would unpatched.
**
** Returns non-zero if the resolution was adopted.
*/
int GameFix_SetTargetResolution(unsigned int glideEnum,
                                unsigned int w, unsigned int h);

/*
** A Glide resolution enum from `[GameFix] resolution=` in wideDriver.ini
** beside the exe, or 0 if unset.
**
** This is the route that does NOT need FX_GLIDE_OVERRIDE_RESOLUTION.  The
** override forces the mode behind the application's back and affects every
** Glide app on the machine; naming a resolution here instead patches the game
** to ask for that mode itself.  Narrower blast radius, and for Diablo II it is
** the configuration that behaves.
**
** The caller resolves it to pixels through the driver's own _resTable, so this
** unit still carries no resolution table of its own.
*/
int GameFix_IniResolution(void);

/*
** Write out the buffered status log.  Call from grGlideShutdown or process
** detach -- NOT from anywhere inside a frame.  See the g_inSwap note in
** gamefix.c: file I/O from inside grBufferSwap freezes Win98 hard.
*/
void GameFix_Shutdown(void);

/*
** Identify the host process and apply whatever patches its profile lists.
**
** Idempotent and safe to call repeatedly: a patch whose "find" bytes are no
** longer present is simply skipped.  That matters because no single call site
** is early enough for every game AND late enough for every module -- Diablo II
** pulls D2Client.dll, D2Win.dll and D2gfx.dll in over the course of startup,
** and a profile whose module is not mapped yet is left for the next call.
**
** Never fails loudly.  A game running unpatched at its stock resolution is a
** far better outcome than one that refuses to start.
*/
void GameFix_Apply(void);

/*
** Called once per grBufferSwap.  Two jobs: retry any profile whose module was
** not mapped at the last attempt, and flush the status log.  Both stop costing
** anything once there is nothing left to do.
*/
void GameFix_Tick(void);

/*
** Status log, written beside the game exe as g3fix.txt.  Enabled by
**   [GameFix] log=1   in wideDriver.ini beside the exe,
** or by setting the FX_GLIDE_GAMEFIX_LOG environment variable.
**
** GAME-PATCHING.md section 6: write a status log before you write a theory.
** "Nothing happens" on hardware is consistent with three unrelated failures --
** gamefix never ran, ran and matched nothing, or patched correctly and the
** screen size comes from somewhere else -- and each guess costs a full round
** trip.  wvsprintf formatting: no floats.
*/
void GameFix_Log(const char *fmt, ...);

/*
** Called at the top of grDrawVertexArrayContiguous.
**
** Diablo II's cinematics are drawn through this entry point, from a STATIC
** vertex array inside D2Glide, so a pointer compare identifies them exactly --
** no return-address walking and no code patch in the game.  Everything else
** costs one test and returns.
**
** For now it only measures (see [Diablo2] videolog in gamefix.c); it takes the
** array by pointer because the transform that resizes the movie will rewrite
** those vertices in place.
*/
void GameFix_VertexArray(unsigned int mode, unsigned int count,
                         void *pointers, unsigned int stride);

#ifdef __cplusplus
}
#endif

#endif /* GAMEFIX_H */
