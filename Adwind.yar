rule Adwind
{
      meta:
        author = "Asaf Aprozper, asafa AT minerva-labs.com"
        description = "Adwind RAT"
        last_modified = "2017-07-13"
strings:
        $a0 = "META-INF/MANIFEST.MF"
        $a1 = /Main(\$)[a-zA-Z][0-9][0-9][0-9][0-9]/
        $PK = "PK"
condition:
        $PK at 0 and $a0 and $a1
}
