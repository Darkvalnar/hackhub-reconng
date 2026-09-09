import { isDemoContentEnabled } from "./DemoContent";
import {
    Network,
    NetworkDeviceType,
    type NetworkVulnerability,
} from "@hotbunny/hackhub-content-sdk";
import { registerServiceBinary, unregisterServiceBinary, type VulnType } from "./ServiceBinary";
import { BreachBackend } from "./BreachBackend";

interface LabPort {
    external: number;
    service: string;
    version: string;
    exploitable?: boolean;
    vulns?: VulnType[];
}

interface LabHost {
    ip: string;
    domain: string;
    name: string;
    vulnerabilities: NetworkVulnerability[];
    ports: LabPort[];
}

const LAB_HOSTS: LabHost[] = [
    { ip: "198.51.100.10", domain: "webnode.lab", name: "Webnode", vulnerabilities: [{ type: "RCE" }], ports: [{ external: 8080, service: "http", version: "LiteHTTP 2.0" }] },
    { ip: "198.51.100.11", domain: "archive.lab", name: "Archive", vulnerabilities: [{ type: "LFI" }], ports: [{ external: 21, service: "ftp", version: "QuillFTP 3.1" }] },
    { ip: "198.51.100.12", domain: "portal.lab", name: "Portal", vulnerabilities: [{ type: "XSS" }, { type: "CORS" }], ports: [{ external: 8080, service: "http", version: "VaultPortal 3.4" }] },
    { ip: "198.51.100.13", domain: "relay.lab", name: "Relay", vulnerabilities: [{ type: "SSRF" }, { type: "RFI" }], ports: [{ external: 8080, service: "http", version: "RelayProxy 2.0" }] },
    { ip: "198.51.100.14", domain: "shopdb.lab", name: "ShopDB", vulnerabilities: [{ type: "SQL_INJECTION" }], ports: [{ external: 3306, service: "database", version: "PebbleDB 9.0" }] },
    { ip: "198.51.100.15", domain: "cache.lab", name: "Cache", vulnerabilities: [{ type: "RCE" }], ports: [{ external: 6379, service: "redis", version: "FoxCache 1.4" }] },
    { ip: "198.51.100.16", domain: "mailgw.lab", name: "MailGateway", vulnerabilities: [{ type: "RCE" }], ports: [{ external: 25, service: "smtp", version: "PostHaste 5.0" }] },
    { ip: "198.51.100.17", domain: "jump.lab", name: "Jump", vulnerabilities: [{ type: "RCE" }], ports: [{ external: 22, service: "ssh", version: "NimbusSSH 4.2" }] },
    { ip: "198.51.100.18", domain: "files.lab", name: "FileShare", vulnerabilities: [{ type: "RCE" }], ports: [{ external: 445, service: "smb", version: "GaleShare 2.2" }] },
    {
        ip: "198.51.100.19",
        domain: "edge.lab",
        name: "Edge",
        vulnerabilities: [{ type: "RCE" }, { type: "LFI" }],
        ports: [
            { external: 8080, service: "http", version: "EdgeHTTP 1.0", vulns: ["RCE"] },
            { external: 21, service: "ftp", version: "EdgeFTP 1.0", vulns: ["LFI"] },
        ],
    },
    { ip: "198.51.100.20", domain: "bastion.lab", name: "Bastion", vulnerabilities: [{ type: "RCE" }], ports: [{ external: 8080, service: "http", version: "FortHTTP 5.0", exploitable: false }] },
    {
        ip: "198.51.100.21",
        domain: "annex.lab",
        name: "Annex",
        vulnerabilities: [{ type: "RCE" }],
        ports: [
            { external: 8080, service: "http", version: "PatchWeb 2.0", exploitable: false },
            { external: 21, service: "ftp", version: "AnnexFTP 1.0" },
        ],
    },
];

/**
 * Both halves of the tier mechanic, using the two lab hosts that already run ftp. archive.lab is
 * gated at a tier the player is handed, so the stock list refuses and the granted one works.
 * edge.lab is gated above anything granted, so the refusal has somewhere to be seen.
 */
export function registerLabWordlists(): void {
    if (!isDemoContentEnabled()) return;
    BreachBackend.registerWordlist({ name: "labdeep.lst", tier: 2, entries: 96_000 });
    BreachBackend.grantWordlist("labdeep.lst");
    BreachBackend.setWordlistGate("198.51.100.11", 2);
    BreachBackend.setWordlistGate("198.51.100.19", 3);
}

export function unregisterLabWordlists(): void {
    BreachBackend.removeWordlist("labdeep.lst");
    BreachBackend.clearWordlistGate("198.51.100.11");
    BreachBackend.clearWordlistGate("198.51.100.19");
}

export function registerReconNgTestLab(): void {
    if (!isDemoContentEnabled()) return;
    for (const host of LAB_HOSTS) {
        if (!Network.getSubnet(host.ip)) {
            Network.createSubnetNetwork({
                ip: host.ip,
                type: NetworkDeviceType.Router,
                name: host.name,
                accessable: true,
                domain: { name: host.domain, vulnerabilities: host.vulnerabilities },
                ports: host.ports.map((port) => ({
                    external: port.external,
                    internal: port.external,
                    active: true,
                    service: port.service,
                    version: port.version,
                })),
                users: [
                    Network.createUser({
                        username: "operator",
                        password: "operator",
                        online: true,
                        acceptReverseTCP: true,
                    }),
                ],
                children: [],
            });
        } else {
            for (const port of host.ports) {
                Network.removePort(host.ip, port.external);
                Network.addPort(host.ip, {
                    external: port.external,
                    internal: port.external,
                    active: true,
                    service: port.service,
                    version: port.version,
                });
            }
        }

        Network.registerDomain(host.domain, host.ip, host.vulnerabilities);
        Network.setVulnerabilities(host.ip, host.vulnerabilities);

        for (const port of host.ports) {
            if (port.exploitable === false || port.vulns) {
                registerServiceBinary({
                    service: port.service,
                    version: port.version,
                    ...(port.exploitable === false ? { exploitable: false } : {}),
                    ...(port.vulns ? { vulns: port.vulns } : {}),
                });
            }
        }
    }

}

/** Retracts the lab immediately while leaving its inert network records available for reactivation. */
export function deactivateReconNgTestLab(): void {
    BreachBackend.purgeTargets(LAB_HOSTS.flatMap((host) => [host.ip, host.domain]));
    for (const host of LAB_HOSTS) {
        for (const port of host.ports) {
            if (port.exploitable === false || port.vulns) {
                unregisterServiceBinary(port.service, port.version);
            }
            if (Network.getSubnet(host.ip)) Network.removePort(host.ip, port.external);
        }
        if (Network.getSubnet(host.ip)) Network.setVulnerabilities(host.ip, []);
        try {
            Network.removeDomain(host.domain);
        } catch {
            // The domain may already be absent.
        }
    }
}

/**
 * Tears down every lab host that currently exists. destroyNetwork is worker backed and does not
 * settle for an address with nothing on it, so the subnet check must happen before awaiting it.
 */
export async function resetReconNgTestLab(): Promise<string[]> {
    const released: string[] = [];
    deactivateReconNgTestLab();
    for (const host of LAB_HOSTS) {
        if (!Network.getSubnet(host.ip)) continue;
        try {
            await Network.destroyNetwork(host.ip);
            released.push(host.ip);
        } catch {
            // Nothing to tear down at that address.
        }
    }
    return released;
}
