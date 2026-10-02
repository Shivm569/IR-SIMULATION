rule NOVA_LOCK_Ransom_Note
{
    meta:
        description = "Detects the fictional NOVA-LOCK ransom note"
        author      = "IR Simulation Project"
        date        = "2026-03-10"
        severity    = "critical"
        note        = "Fictional sample for training only"

    strings:
        $h1 = "Your files have been encrypted" ascii wide nocase
        $h2 = ".nvlock" ascii wide
        $h3 = "NOVA-LOCK" ascii wide
        $h4 = "do not rename" ascii wide nocase
        $c1 = "contact" ascii wide nocase

    condition:
        filesize < 10KB and 2 of ($h*) and $c1
}
