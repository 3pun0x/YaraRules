rule AmmyyRAT_Evasive
{

	meta:
      description = "Rule to detect evasive FlawedAmmyy (AmmyAdmin) RAT"
      author = "Asaf Aprozper / @3pun0x"
      date = "2019-01-17"
      
	strings:
      $s1 = "CMDAGENT.EXE" fullword wide
      $s2 = "SPIDERAGENT.EXE" fullword wide
      $s3 = "QHACTIVEDEFENSE.EXE" fullword wide
      $s4 = "CEqAOPdi.exe" fullword wide
      $s5 = "DWARKDAEMON.EXE" fullword wide
      $s6 = "DWENGINE.EXE" fullword wide
      $s7 = "V3MAIN.EXE" fullword wide
      $s8 = "QHSAFETRAY.EXE" fullword wide
      $s9 = "QHWATCHDOG.EXE" fullword wide
      $s10 = "V3LITE.EXE" fullword wide
      $s11 = "CIS.EXE" fullword wide
      $s12 = "V3SP.EXE" fullword wide
      $s13 = "Global\\Ammyy.Target.StateEvent_%d_" fullword wide
      $s14 = "ERROR %d Cre  the Ammyy service" fullword ascii
      
	condition: 
      5 of them and ($s13 or $s14)
}
