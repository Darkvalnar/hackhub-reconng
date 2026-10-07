# Local privilege escalation targets

A content mod registers a host through `SharedStorage` under `reconng.localPrivilege.targets`:

```ts
type LocalPrivilegeTarget = {
    target: string; // Host IP or domain
    seed?: string;   // Stable across save and reload; defaults to the host IP
    families?: Array<"search-path" | "fixed-buffer">;
};
```

ReconNg derives two local routines from the seed when the player uses `linpeas` in a limited shell session. One routine has a usable weakness; the other has a relevant guard. `linpeas` lists routine names, `linpeas inspect <routine>` reports each routine's input, privileged action, and guard, and the optional `linpeas probe <routine> <input>` tests a hypothesis. The player uses `privesc build <routine> <input>` to prepare an attempt and `privesc run` to execute it. Wrong attempts leave the session unprivileged. A successful attempt promotes only that session to root and emits `ReconNg.Breach.PrivilegeEscalated`.

Search path profiles require selecting the routine that accepts the session environment and supplying the command it invokes. Fixed buffer profiles require selecting the routine whose length check follows the copy and supplying the return offset derived from the reported buffer and saved frame sizes. The profile is generated on demand; neither helper binaries nor puzzle files are added to the host filesystem. The save holds the small target registration and, while a session is open, only its prepared routine and input.

ReconNg emits `ReconNg.Breach.LocalActivity` with `scan`, `inspect`, `probe`, `build`, or `run` for each action. Content mods can use that event for detection or other consequences. Hacklink charges trace noise for every phase, including a failed run.
