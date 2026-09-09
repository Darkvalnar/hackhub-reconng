import {
    Command,
    RegisterCommand,
    type CommandAutoComplete,
    type CommandTools,
} from "@hotbunny/hackhub-content-sdk";
import { resetReconNgDemoWorld } from "../world/ReconNgDemoWorld";
import { registerLabWordlists, registerReconNgTestLab, resetReconNgTestLab } from "../world/ReconNgTestLab";
import { registerExploitShop } from "../world/ExampleExploitShop";
import { registerExampleTarget } from "../world/ExampleTarget";
import { BreachBackend } from "../world/BreachBackend";
import { isDemoContentEnabled } from "../world/DemoContent";

/** Rebuilds the practice hosts. Recreating one over a damaged address is a no op without this. */
async function runReset(tools: CommandTools): Promise<void> {
    if (!isDemoContentEnabled()) {
        tools.printError("Practice targets are off. Enable them in the recon-ng mod settings and restart.");
        return;
    }

    tools.println("[*] tearing down practice hosts ...");
    const demoIp = await resetReconNgDemoWorld();
    if (demoIp) tools.println(`[+] released breach-demo.io (${demoIp})`);
    const labIps = await resetReconNgTestLab();
    tools.println(`[+] released ${labIps.length} lab hosts`);

    tools.println("[*] rebuilding ...");
    registerReconNgTestLab();
    registerExampleTarget();
    registerExploitShop();
    registerLabWordlists();

    const wordlists = BreachBackend.getWordlists().map((list) => `${list.name} (tier ${list.tier})`);
    tools.println("");
    tools.println(`modules ............ ${BreachBackend.getModules().length}`);
    tools.println(`wordlists .......... ${wordlists.length ? wordlists.join(", ") : "none"}`);
    tools.printSuccess("Practice hosts rebuilt. breach-demo.io returns with the quest.");
}

@RegisterCommand
export class ReconNgResetCommand extends Command {
    CommandName = "recon-ng-reset";
    Description = "Rebuild the recon-ng practice hosts and report breach state.";
    PackageName = "recon-ng";

    Autocomplete: CommandAutoComplete[] = [
        { label: "recon-ng-reset", type: "STRING" },
    ];

    Run(tools: CommandTools): Promise<void> {
        return runReset(tools);
    }
}
