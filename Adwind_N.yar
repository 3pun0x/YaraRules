rule Adwind
{
      meta:
		author= "Asaf Aprozper, asafa@minerva-labs.com"
		description = "Detect Adwind RAT"
		last_modified = "2017-06-25"
strings:
		$a0 = "META-INF/MANIFEST.MF"
        	$a1 = /Main(\$)N[0-9][0-9][0-9][0-9]/
		$PK = "PK"
condition:
		$PK at 0 and $a0 and $a1
}
