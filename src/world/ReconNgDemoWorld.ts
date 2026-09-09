import { isDemoContentEnabled } from "./DemoContent";
import {
    Network,
    NetworkDeviceType,
    type NetworkVulnerability,
} from "@hotbunny/hackhub-content-sdk";
import { BreachBackend } from "./BreachBackend";
import { GameStorage as Storage } from "./ReconNgStorage";

const DEMO_IP_KEY = "recon-ng.demo.breach.ip";
const DEMO_HOST = "breach-demo.io";
const DEMO_VULNS: NetworkVulnerability[] = [
    { type: "RCE", version: "vsftpd 2.3.4" },
    { type: "RCE", version: "nginx 1.18.0" },
];

export function registerReconNgDemoWorld(): void {
    if (!isDemoContentEnabled()) return;

    let ip = Storage.get(DEMO_IP_KEY) as string | null;
    if (!ip) {
        ip = Network.randomIp();
        Storage.set(DEMO_IP_KEY, ip);
    }

    if (!Network.getSubnet(ip)) {
        // Must be a Router. CreateSubnetNetwork moves a leaf node's ports into its parent's port
        // array and then deletes them from the node itself. At the root of a subnet there is no
        // parent, so a Device here loses every port it declares: the host answers, keeps its
        // domain, and exposes nothing. The Router branch is the only one that keeps its own ports.
        Network.createSubnetNetwork({
            ip,
            type: NetworkDeviceType.Router,
            accessable: true,
            children: [],
            name: "Breach Demo Host",
            domain: { name: DEMO_HOST, vulnerabilities: DEMO_VULNS },
            location: {
                latitude: "37.7610",
                longitude: "-122.4210",
                city: "Port Azure",
                country: "In-Game",
            },
            ports: [
                { external: 80, internal: 80, active: true, service: "http", version: "nginx 1.18.0" },
                { external: 21, internal: 21, active: true, service: "ftp", version: "vsftpd 2.3.4" },
            ],
            users: [
                Network.createUser({
                    username: "operator",
                    password: "operator",
                    firstName: "Service",
                    lastName: "Operator",
                    online: true,
                    acceptReverseTCP: true,
                }),
            ],
        });
    } else {
        Network.removePort(ip, 80);
        Network.removePort(ip, 21);
        Network.addPort(ip, { external: 80, internal: 80, active: true, service: "http", version: "nginx 1.18.0" });
        Network.addPort(ip, { external: 21, internal: 21, active: true, service: "ftp", version: "vsftpd 2.3.4" });
    }

    Network.registerDomain(DEMO_HOST, ip, DEMO_VULNS);
    Network.setVulnerabilities(ip, DEMO_VULNS);
}

/**
 * Makes an existing demo host unavailable without waiting for worker-backed network deletion.
 * The address is retained so enabling the setting again can restore the same host in place.
 */
export function deactivateReconNgDemoWorld(): string | null {
    const ip = Storage.get(DEMO_IP_KEY) as string | null;
    BreachBackend.purgeTargets([DEMO_HOST, ...(ip ? [ip] : [])]);
    if (ip && Network.getSubnet(ip)) {
        Network.removePort(ip, 80);
        Network.removePort(ip, 21);
        Network.setVulnerabilities(ip, []);
    }
    try {
        Network.removeDomain(DEMO_HOST);
    } catch {
        // The domain may already be absent.
    }
    return ip;
}

/**
 * Drops the demo host and forgets its address so the next registration rebuilds it from scratch.
 * Recreating over a damaged address does not clear it, which is what the reset command is for.
 */
export async function resetReconNgDemoWorld(): Promise<string | null> {
    const ip = deactivateReconNgDemoWorld();
    if (ip && Network.getSubnet(ip)) {
        try {
            await Network.destroyNetwork(ip);
        } catch {
            // Nothing to tear down at that address.
        }
    }
    Storage.remove(DEMO_IP_KEY);
    return ip;
}
