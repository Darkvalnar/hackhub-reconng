import { isDemoContentEnabled } from "./DemoContent";
import {
    Network,
    NetworkDeviceType,
    type NetworkVulnerability,
} from "@hotbunny/hackhub-content-sdk";
import { BreachBackend } from "./BreachBackend";

const IP = "203.0.113.10";
const DOMAIN = "acme-labs.test";
const VULNERABILITIES: NetworkVulnerability[] = [{ type: "RCE" }];

export function deactivateExampleTarget(): void {
    BreachBackend.purgeTargets([IP, DOMAIN]);
    if (Network.getSubnet(IP)) {
        Network.removePort(IP, 8080);
        Network.setVulnerabilities(IP, []);
    }
    Network.removeDomain(DOMAIN);
}

export async function unregisterExampleTarget(): Promise<void> {
    deactivateExampleTarget();
    if (Network.getSubnet(IP)) await Network.destroyNetwork(IP);
}

export function registerExampleTarget(): void {
    if (!isDemoContentEnabled()) return;
    if (!Network.getSubnet(IP)) {
        Network.createSubnetNetwork({
            ip: IP,
            type: NetworkDeviceType.Router,
            name: "Acme Labs",
            accessable: true,
            domain: { name: DOMAIN, vulnerabilities: VULNERABILITIES },
            ports: [
                { external: 8080, internal: 8080, active: true, service: "http", version: "AcmeWeb 1.0" },
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
        Network.removePort(IP, 8080);
        Network.addPort(IP, { external: 8080, internal: 8080, active: true, service: "http", version: "AcmeWeb 1.0" });
    }

    Network.registerDomain(DOMAIN, IP, VULNERABILITIES);
    Network.setVulnerabilities(IP, VULNERABILITIES);
}
