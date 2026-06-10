// v0.8.0+ Wave 3 (Item G): per-target YARA fingerprint rules
// Auto-generated. Do not edit by hand.

rule re_breaker_target_f1_25
{
    meta:
        target_key = "f1_25"
        target = "RE_BREAKER_PLUGIN_ROOT/Input/F1.25.Iconic.Edition-InsaneRamZes/F1_25.exe"
        confidence_this_target = 100
        confidence_other_targets = 0
        generated_by = "re-target-fingerprint v0.1.0"
        generated_date = "auto-generated"

    strings:
    $p0 = { 64 65 6E 75 76 6F 5F 61 74 64 }
    $p1 = { 61 6E 74 69 74 61 6D 70 65 72 64 69 61 67 6E 6F 73 69 73 }
    $p2 = { 66 31 32 30 32 35 }

    condition:
        $p0 or
        $p1 or
        $p2
}
