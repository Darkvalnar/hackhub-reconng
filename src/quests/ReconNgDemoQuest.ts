import { Quest, RegisterQuest, UI } from "@hotbunny/hackhub-content-sdk";
import { ReconNgEvents } from "../world/ReconNgEvents";
import { registerReconNgDemoWorld } from "../world/ReconNgDemoWorld";
import { readDemoContentSetting } from "../world/DemoContent";

const AVATAR_BASE = "https://api.dicebear.com/7.x/identicon/svg-seed=";

const DEMO_HOST = "breach-demo.io";

interface ReconNgDemoState {
    opened: boolean;
    read: boolean;
    looted: boolean;
}

function isDemoHost(host: string | undefined): boolean {
    if (!DEMO_HOST) return true;
    return String(host ?? "").toLowerCase().includes(DEMO_HOST);
}

@RegisterQuest
export class ReconNgDemoQuest extends Quest<ReconNgDemoState> {
    private readonly demoContentEnabled = readDemoContentSetting();

    Name = this.demoContentEnabled ? "ReconNgDemo" : "ReconNgDemo.Disabled";
    Title = "Proof of Foothold";
    Description = "A broker wants proof of access on breach-demo.io. Use recon-ng to open a session, read a file, and pull one out as evidence.";

    Rewards = {
        xp: 200,
        money: 500,
    };

    HackhubPost = this.demoContentEnabled ? {
        content: "Inherited a staging box from a client offboarding: breach-demo.io. Old service stack, never decommissioned. Need someone to prove a foothold: open a session and pull one config file as evidence. Quick job, fast payout.",
        author: {
            name: "gh0st_broker",
            avatar: `${AVATAR_BASE}gh0st_broker`,
        },
        likes: 3,
        comments: [
            {
                author: { name: "n0va", avatar: `${AVATAR_BASE}n0va` },
                content: "old stack- recon-ng will walk right through that",
            },
            {
                author: { name: "gh0st_broker", avatar: `${AVATAR_BASE}gh0st_broker` },
                content: "that's the idea. clean proof, no noise.",
            },
        ],
    } : undefined;

    Objectives = [
        {
            name: "open_session",
            description: "Open a session on breach-demo.io with recon-ng.",
        },
        {
            name: "read_file",
            description: "Read a file inside the session.",
            unlocksAfter: ["open_session"],
        },
        {
            name: "loot_file",
            description: "Download a file from the session as proof.",
            unlocksAfter: ["read_file"],
        },
    ];

    CreateData(): ReconNgDemoState {
        return { opened: false, read: false, looted: false };
    }

    OnStart() {
        UI.toast("New contract: Proof of Foothold", "info");
    }

    OnObjectivesStart() {
        registerReconNgDemoWorld();

        ReconNgEvents.questOn(this.Events, "ReconNg.Breach.SessionOpened", (event) => {
            if (!isDemoHost(event.host)) return;
            this.SetData("opened", true);
            this.completeObjective("open_session");
            UI.toast("Session opened.", "success");
        });

        ReconNgEvents.questOn(this.Events, "ReconNg.Breach.FileRead", (event) => {
            if (!isDemoHost(event.host)) return;
            this.SetData("read", true);
            this.completeObjective("read_file");
            UI.toast("File read.", "success");
        });

        ReconNgEvents.questOn(this.Events, "ReconNg.Breach.FileDownloaded", (event) => {
            if (!isDemoHost(event.host)) return;
            this.SetData("looted", true);
            this.completeObjective("loot_file");
            UI.toast("Evidence secured. Contract complete.", "success");
        });
    }
}
