rule Malwation
{
    strings:
        $malwation_text_string = "Malwation" nocase
        $malwation_hex_string = { 4D 61 6C 77 61 74 69 6F 6E }

    condition:
        $malwation_text_string or $malwation_hex_string
}
