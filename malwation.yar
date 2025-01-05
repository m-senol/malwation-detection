rule Malwation
{
    strings:
        $malwation_text_string = "Malwation" nocase
        $malwation_hex_string = { 4D 61 6C 77 61 74 69 6F 6E }
        $malwation_utf16_string = { 4D 00 61 00 6C 00 77 00 61 00 74 00 69 00 6F 00 6E 00 }

    condition:
        $malwation_text_string or $malwation_hex_string or $malwation_utf16_string
}
