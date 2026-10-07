const SHIFTS = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const CONSTANTS = Array.from({ length: 64 }, (_, index) =>
    Math.floor(Math.abs(Math.sin(index + 1)) * 2 ** 32) >>> 0
);

function rotateLeft(value: number, shift: number): number {
    return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

function littleEndianHex(word: number): string {
    let hex = "";
    for (let index = 0; index < 4; index += 1) {
        hex += ((word >>> (8 * index)) & 0xff).toString(16).padStart(2, "0");
    }
    return hex;
}

export function md5Hex(input: string): string {
    const bytes = Array.from(new TextEncoder().encode(input));
    const bitLength = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (let index = 0; index < 8; index += 1) {
        bytes.push(Math.floor(bitLength / 2 ** (8 * index)) & 0xff);
    }

    let a0 = 0x67452301;
    let b0 = 0xefcdab89;
    let c0 = 0x98badcfe;
    let d0 = 0x10325476;

    for (let offset = 0; offset < bytes.length; offset += 64) {
        const words: number[] = [];
        for (let index = 0; index < 16; index += 1) {
            const at = offset + index * 4;
            words.push((bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24)) >>> 0);
        }

        let a = a0;
        let b = b0;
        let c = c0;
        let d = d0;
        for (let index = 0; index < 64; index += 1) {
            let mixed: number;
            let wordIndex: number;
            if (index < 16) {
                mixed = (b & c) | (~b & d);
                wordIndex = index;
            } else if (index < 32) {
                mixed = (d & b) | (~d & c);
                wordIndex = (5 * index + 1) % 16;
            } else if (index < 48) {
                mixed = b ^ c ^ d;
                wordIndex = (3 * index + 5) % 16;
            } else {
                mixed = c ^ (b | ~d);
                wordIndex = (7 * index) % 16;
            }
            const sum = (a + mixed + CONSTANTS[index] + words[wordIndex]) >>> 0;
            a = d;
            d = c;
            c = b;
            b = (b + rotateLeft(sum, SHIFTS[index])) >>> 0;
        }

        a0 = (a0 + a) >>> 0;
        b0 = (b0 + b) >>> 0;
        c0 = (c0 + c) >>> 0;
        d0 = (d0 + d) >>> 0;
    }

    return [a0, b0, c0, d0].map(littleEndianHex).join("");
}
