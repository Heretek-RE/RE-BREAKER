// Pattern A: encrypted-VM bytecode interpreter (Unity IL2CPP)
// Hook the encryption-stub entry; dump each method's plaintext before execution.
const ENCRYPTION_STUB_RVA = ptr("0x0DEADBEEF");  // resolved at runtime
Interceptor.attach(ENCRYPTION_STUB_RVA, {
    onEnter(args) {
        console.log("[pattern-A] encryption-stub called");
        this.input = args[0];
        this.input_size = args[1].toInt32();
    },
    onLeave(retval) {
        const out = Memory.readByteArray(retval, this.input_size || 0);
        send({ kind: "decrypted", rva: ENCRYPTION_STUB_RVA, payload_b64: Array.from(new Uint8Array(out)) });
    }
});
