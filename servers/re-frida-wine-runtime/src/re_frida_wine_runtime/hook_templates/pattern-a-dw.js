// Pattern A-DW: encrypted-VM + Denuvo ATD (UE5 variant)
// Hook the POGO entry validation + the encryption-stub entry.
const POGO_ENTRY = ptr("0x0DEADBEEF");
const ENCRYPTION_STUB_RVA = ptr("0x0DEADBEEF");
Interceptor.attach(POGO_ENTRY, {
    onEnter(args) { console.log("[pattern-A-DW] POGO entry"); },
    onLeave(retval) { console.log("[pattern-A-DW] POGO exit"); }
});
Interceptor.attach(ENCRYPTION_STUB_RVA, {
    onEnter(args) { this.input = args[0]; },
    onLeave(retval) {
        const out = Memory.readByteArray(retval, 4096);
        send({ kind: "decrypted", rva: ENCRYPTION_STUB_RVA, payload_b64: Array.from(new Uint8Array(out)) });
    }
});
