import "pe"

rule SUSP_PEB_Access
{
	meta:
		description = "Code-based signature for hunting Process Environment Block (PEB) structure access"
		reference = "https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm"
		author = "Shelly Raban"
		date = "2021-10-03"
		
	strings:
		/*
		Example:
		
		64 A1 30 00 00 00                   mov     eax, large fs:30h
		
		For a faster scan, use the following string instead:
		$load_peb_address = { 64 A1 30 00 00 00 }
		*/
		
		$load_peb_address = { 64 (A?|8?|B?|C?) [0-1] 30 00 00 00 }
	
	condition:
		uint16(0) == 0x5a4d and
		$load_peb_address
		
}
