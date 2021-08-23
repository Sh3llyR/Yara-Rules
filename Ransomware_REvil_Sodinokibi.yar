import "pe"

rule Ransomware_REvil_Sodinokibi {

	meta:
		
		description = "Code-Based Detection for REvil Sodinokibi Malware Family. Detects 46 Different Samples."
		reference = "https://attack.mitre.org/software/S0496/"
		author = "Shelly Raban"
		date = "2021-08-19"

	strings:

		/*
						rol     eax, 8
						and     eax, 0FF00FFh
						ror     edx, 8
						and     edx, 0FF00FF00h
						or      edx, eax
						mov     eax, [ecx+4]
		*/

		$sequence_1 = { c1 c0 08 25 ff 00 ff 00 c1 ca 08 81 e2 00 ff 00 ff 0b d0 8b 41 04 }

		/*
						xor     edx, [esi]
						mov     [esp+24h+var_C], edx
						mov     edx, eax
						rol     eax, 8
						and     eax, 0FF00FFh
						ror     edx, 8
		*/

		$sequence_2 = { 33 16 89 54 24 18 8b d0 c1 c0 08 25 ff 00 ff 00 c1 ca 08 }

		/*
						and     edx, 0FF00FF00h
						or      edx, eax
						mov     eax, [ecx+8]
						xor     edx, [esi+4]
						mov     ebx, eax
						rol     eax, 8
		*/

		$sequence_3 = { 81 e2 00 ff 00 ff 0b d0 8b 41 08 33 56 04 8b d8 c1 c0 08 }

		/*
						and     eax, 0FF00FFh
						ror     ebx, 8
						mov     [esp+24h+var_14], edx
						and     ebx, 0FF00FF00h
						or      ebx, eax
						mov     eax, [ecx+0Ch]
		*/

		$sequence_4 = { 25 ff 00 ff 00 c1 cb 08 89 54 24 10 81 e3 00 ff 00 ff 0b d8 8b 41 0c }
		
		/*
		
		from loc_1004BC04
		
				movzx   ecx, byte ptr ds:Rijndael_Te1[eax*4]
                movzx   eax, byte ptr [esi-1]
                mov     ecx, ds:Rijndael_Td0[ecx*4]
                movzx   eax, byte ptr ds:Rijndael_Te1[eax*4]
                xor     ecx, ds:Rijndael_Td2[eax*4]
                movzx   eax, dl
		*/
		
		$sequence_5 = { 0f b6 [6] 0f b6 [2] 8b [6] 0f b6 [6] 33 }
		
		/*
		
		from mw_255_loop (named by me)
		
				mov     edx, 1
                imul    eax, edx, 0
                mov     ecx, [ebp+arg_0]
                movzx   edx, byte ptr [ecx+eax]
                xor     edx, [ebp+var_4]
                mov     [ebp+var_C], edx
                cmp     [ebp+var_C], 24h
                jnz     short loc_10001159
		
		*/
		
		$sequence_6_1 = { ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 33 55 fc 89 55 f4 83 7d f4 24 75 02 }

		/*
		from mw_256_loop (named by me)
		
		loc_DE447F:
		
			8B C1                   mov     eax, ecx
			8A 1C 39                mov     bl, [ecx+edi]
			33 D2                   xor     edx, edx
			0F B6 CB                movzx   ecx, bl
			F7 75 10                div     [ebp+arg_8]
			8B 45 0C                mov     eax, [ebp+arg_4]
			0F B6 04 02             movzx   eax, byte ptr [edx+eax]
			03 C6                   add     eax, esi
			03 C8                   add     ecx, eax
			0F B6 F1                movzx   esi, cl
			8B 4D FC                mov     ecx, [ebp+var_4]
			8A 04 3E                mov     al, [esi+edi]
			88 04 39                mov     [ecx+edi], al
			41                      inc     ecx
			88 1C 3E                mov     [esi+edi], bl
			89 4D FC                mov     [ebp+var_4], ecx
			81 F9 00 01 00 00       cmp     ecx, 256
			72 CD                   jb      short loc_DE447F
		*/

		$sequence_6_2 = { 8B C1 8A 1C 39 33 D2 0F B6 CB F7 75 10 8B 45 0C 0F [3] 03 C6 03 C8 0F B6 F1 8B 4D FC 8A 04 3E 88 04 39 41 88 1C 3E 89 4D FC 81 F9 00 01 00 00 7? }
		
		/*
		from mw_AES_matched_func (named by me)
		
		loc_DE60C2:
			6A 10                   push    10h
			57                      push    edi
			E8 6F E6 FF FF          call    __alloca_probe
			8D 45 D0                lea     eax, [ebp+var_30]
			03 C6                   add     eax, esi
			50                      push    eax
			57                      push    edi
			53                      push    ebx
			E8 C3 FC FF FF          call    mw_AES_wrap
			83 C6 10                add     esi, 16
			83 C4 14                add     esp, 20
			83 FE 30                cmp     esi, 48
			72 E0                   jb      short loc_DE60C2
		*/
		
		$sequence_7 = { 6A 10 57 E8 [4] 8D 45 D0 03 C6 50 57 53 E8 [4] 83 C6 10 83 C4 14 83 FE 30 7? }
		
		/*
		from mw_encrypt_files (named by me)
		
			55                      push    ebp
			8B EC                   mov     ebp, esp
			57                      push    edi
			8B 7D 08                mov     edi, [ebp+arg_0]
			66 83 3F 5E             cmp     word ptr [edi], 5Eh
			75 10                   jnz     short loc_DE3685

		loc_DE3685:
			56                      push    esi
			8B 75 0C                mov     esi, [ebp+arg_4]
		
		loc_DE3689:
			56                      push    esi
			57                      push    edi
			E8 1C 00 00 00          call    sub_DE36AC
			59                      pop     ecx
			59                      pop     ecx
			85 C0                   test    eax, eax
			75 0F                   jnz     short loc_DE36A5
		*/
	
		$sequence_8 = { 55 8B EC 57 8B 7D ?? 66 [2] 5E 7? }
		
		
		
	condition:
		( uint16(0) == 0x5A4D and filesize < 1000KB ) and 2 of them

}
