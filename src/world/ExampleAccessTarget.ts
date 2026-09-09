import { isDemoContentEnabled } from "./DemoContent";
import {
    Network,
    NetworkDeviceType,
    type NetworkVulnerability,
} from "@hotbunny/hackhub-content-sdk";
import { BreachBackend } from "./BreachBackend";
import { registerServiceBinary, unregisterServiceBinary } from "./ServiceBinary";

const IP = "203.0.113.20";
const DOMAIN = "whalesync.lab";
const SERVICE = "sync";
const VERSION = "WhaleSync 1.4";
const VULNERABILITIES: NetworkVulnerability[] = [{ type: "RCE" }];

export function deactivateExampleAccessTarget(): void {
    BreachBackend.purgeTargets([IP, DOMAIN]);
    unregisterServiceBinary(SERVICE, VERSION);
    if (Network.getSubnet(IP)) {
        Network.removePort(IP, 9001);
        Network.setVulnerabilities(IP, []);
    }
    Network.removeDomain(DOMAIN);
}

export async function unregisterExampleAccessTarget(): Promise<void> {
    deactivateExampleAccessTarget();
    if (Network.getSubnet(IP)) await Network.destroyNetwork(IP);
}

export function registerExampleAccessTarget(): void {
    if (!isDemoContentEnabled()) return;
    if (!Network.getSubnet(IP)) {
        Network.createSubnetNetwork({
            ip: IP,
            type: NetworkDeviceType.Router,
            name: "WhaleSync",
            accessable: true,
            domain: { name: DOMAIN, vulnerabilities: VULNERABILITIES },
            ports: [
                { external: 9001, internal: 9001, active: true, service: SERVICE, version: VERSION },
            ],
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
        Network.removePort(IP, 9001);
        Network.addPort(IP, { external: 9001, internal: 9001, active: true, service: SERVICE, version: VERSION });
    }

    Network.registerDomain(DOMAIN, IP, VULNERABILITIES);
    Network.setVulnerabilities(IP, VULNERABILITIES);

    registerServiceBinary({ service: SERVICE, version: VERSION, access: "memory-leak" });

    BreachBackend.attachLoot(DOMAIN, [
        { path: "/mem/fragments/memory_leak_004.bin", data: "LAST_SYNC_HOST=krakenGate.hadal\nLAST_SYNC_PORT=8443\nTOKEN_FRAGMENT=blue-orchid\n" },
        { path: "/mem/fragments/process_map.txt", data: "pid 411 sync-worker active\npid 522 web-preview jailed\n" },
    ]);
}
