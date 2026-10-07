export type LocalPrivilegeFamily = "search-path" | "fixed-buffer";

export interface LocalPrivilegeTarget {
    target: string;
    seed?: string;
    os?: "linux" | "windows";
    families?: LocalPrivilegeFamily[];
}

export interface LocalPrivilegeRoutine {
    id: string;
    process: string;
    input: string;
    action: string;
    guard: string;
}

export interface LocalPrivilegeProfile {
    os: "linux" | "windows";
    family: LocalPrivilegeFamily;
    routines: LocalPrivilegeRoutine[];
    solution: { routineId: string; value: string };
}

function hash(value: string): number {
    let result = 2166136261;
    for (const character of value) {
        result ^= character.charCodeAt(0);
        result = Math.imul(result, 16777619);
    }
    return result >>> 0;
}

export function buildLocalPrivilegeProfile(target: LocalPrivilegeTarget, ip: string, _host: string): LocalPrivilegeProfile {
    const os = target.os === "windows" ? "windows" : "linux";
    const families = target.families?.length ? target.families : ["search-path", "fixed-buffer"] as LocalPrivilegeFamily[];
    const chosen = hash(`${target.seed ?? ip}|local-privilege-v2`);
    const family = families[chosen % families.length];
    if (os === "windows") {
        if (family === "search-path") {
            const jobs = [
                { id: "vault-backup", command: "robocopy.exe", work: "a backup job" },
                { id: "ledger-export", command: "powershell.exe", work: "an export job" },
                { id: "snapshot-check", command: "certutil.exe", work: "an integrity check" },
                { id: "mirror-sync", command: "xcopy.exe", work: "a mirror job" },
            ] as const;
            const index = (chosen >>> 12) % jobs.length;
            const vulnerable = jobs[index];
            const guarded = jobs[(index + 1) % jobs.length];
            const routine = (job: typeof vulnerable, unsafe: boolean): LocalPrivilegeRoutine => ({
                id: job.id,
                process: `C:\\Program Files\\VaultOps\\${job.id}.exe`,
                input: unsafe ? "session environment" : "administrator configuration",
                action: `invokes ${job.command} by name for ${job.work}`,
                guard: unsafe ? "no fixed system path before command lookup" : "system command path pinned before environment entries",
            });
            return {
                os, family,
                routines: chosen & 2 ? [routine(guarded, false), routine(vulnerable, true)] : [routine(vulnerable, true), routine(guarded, false)],
                solution: { routineId: vulnerable.id, value: vulnerable.command },
            };
        }
        const jobs = ["vault-index-check", "archive-verify", "queue-decode", "record-parse"];
        const index = (chosen >>> 12) % jobs.length;
        const buffer = [32, 48, 64, 80][(chosen >>> 5) % 4];
        const frame = [8, 16][(chosen >>> 9) % 2];
        const routine = (id: string, unsafe: boolean): LocalPrivilegeRoutine => ({
            id,
            process: `C:\\Program Files\\VaultOps\\${id}.exe`,
            input: "label argument",
            action: `copies label into a ${buffer}-byte buffer; saved frame is ${frame} bytes`,
            guard: unsafe ? "length checked after copy" : "length checked before copy",
        });
        const vulnerable = jobs[index];
        const guarded = jobs[(index + 1) % jobs.length];
        return {
            os, family,
            routines: chosen & 2 ? [routine(guarded, false), routine(vulnerable, true)] : [routine(vulnerable, true), routine(guarded, false)],
            solution: { routineId: vulnerable, value: String(buffer + frame) },
        };
    }
    if (family === "search-path") {
        const jobs = [
            { id: "archive-sync", command: "tar", work: "an archive job" },
            { id: "snapshot-run", command: "cpio", work: "an archive job" },
            { id: "export-bundle", command: "zip", work: "an export job" },
            { id: "backup-mirror", command: "rsync", work: "a backup job" },
            { id: "log-pack", command: "gzip", work: "a log rotation job" },
            { id: "log-compress", command: "xz", work: "a log compression job" },
            { id: "cert-renew", command: "openssl", work: "a certificate renewal job" },
            { id: "checksum-audit", command: "sha256sum", work: "an integrity check" },
        ] as const;
        const jobIndex = (chosen >>> 12) % jobs.length;
        const job = jobs[jobIndex];
        const otherJob = jobs[(jobIndex + 1 + ((chosen >>> 5) % (jobs.length - 1))) % jobs.length];
        const vulnerable: LocalPrivilegeRoutine = {
            id: job.id,
            process: `/usr/local/sbin/${job.id}`,
            input: "session environment",
            action: `invokes ${job.command} by name for ${job.work}`,
            guard: "no fixed system path before command lookup",
        };
        const guarded: LocalPrivilegeRoutine = {
            id: otherJob.id,
            process: `/usr/local/sbin/${otherJob.id}`,
            input: "administrator configuration",
            action: `invokes ${otherJob.command} by name for ${otherJob.work}`,
            guard: "system command path pinned before environment entries",
        };
        return {
            os,
            family,
            routines: chosen & 2 ? [guarded, vulnerable] : [vulnerable, guarded],
            solution: { routineId: vulnerable.id, value: job.command },
        };
    }

    const functions = ["archive-sync-check", "manifest-verify", "record-parse", "queue-decode", "index-check", "job-audit"];
    const functionIndex = (chosen >>> 12) % functions.length;
    const service = functions[functionIndex];
    const otherService = functions[(functionIndex + 1 + ((chosen >>> 5) % (functions.length - 1))) % functions.length];
    const buffer = [32, 48, 64, 80, 96][(chosen >>> 5) % 5];
    const frame = [8, 16, 24][(chosen >>> 9) % 3];
    const vulnerable: LocalPrivilegeRoutine = {
        id: service,
        process: `/usr/local/sbin/${service}`,
        input: "label argument",
        action: `copies label into a ${buffer}-byte buffer; saved frame is ${frame} bytes`,
        guard: "length checked after copy",
    };
    const guarded: LocalPrivilegeRoutine = {
        id: otherService,
        process: `/usr/local/sbin/${otherService}`,
        input: "label argument",
        action: `copies label into a ${buffer}-byte buffer; saved frame is ${frame} bytes`,
        guard: "length checked before copy",
    };
    return {
        os,
        family,
        routines: chosen & 2 ? [guarded, vulnerable] : [vulnerable, guarded],
        solution: { routineId: vulnerable.id, value: String(buffer + frame) },
    };
}
