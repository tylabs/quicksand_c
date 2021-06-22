/* QuickSand.io (c) Copyright 2017
 * General or Trojan signatures here */


/*rule bitcoin_address
{

	strings:
	$s1 = /\b[13]{1}[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,33}\b/

	condition:
	$s1

}*/

rule mime_mso_vba_macros
{
meta:
    comment = "mime mso office obfuscation"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "@mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "macrosPresent=\"yes\""
    $b = "schemas.microsoft.com"

condition:
    all of them
}


rule mime_mso_embedded_ole
{
meta:
    comment = "mime mso office obfuscation"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "@mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "docOleData"
    $b = "binData"
    $c = "schemas.microsoft.com"
 
condition:
    all of them
}

rule mime_mso
{
meta:
    comment = "mime mso detection"
    author = "@mwtracker"
strings:
	$a="application/x-mso"
	$b="MIME-Version"
	$c="ocxstg001.mso"
	$d="?mso-application"
condition:
	$a and $b or $c or $d
}


rule office97_guid
{
	meta:
		ref = "http://search.lores.eu/fiatlu/GUIDnumber.html"
		
	strings:
		$a = "_PID_GUID"
		$magic = {D0 CF 11 E0}

	condition:
		$magic at 0 and $a
}


rule apt_template_tran_duy_linh
{
        meta:
          info = "author"
        strings:
	  $auth = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 10 00 00 00 54 72 61 6E 20 44 75 79 20 4C 69 6E 68 }

        condition:
                $auth
}

rule apt_template_mcsystem
{
        meta:
          info = "author"
        strings:
	  $mc = { 04 00 00 00 00 00 00 00 1E 00 00 00 0C 00 00 00 4E 6F 72 6D 61 6C 2E 64 6F 74 00 00 1E 00 00 00 0C 00 00 00 4D 43 20 53 59 53 54 45 4D }

        condition:
                $mc
}

rule apt_template_qq
{
        meta:
          info = "author"
        strings:
          $qq = { 04 00 00 00 00 00 00 00 1E 00 00 00 04 00 00 00 71 71 00 00 1E 00 00 00 10 00 00 00 4D 69 63 72 6F 73 6F 66 74 }

        condition:
                $qq
}

rule apt_template_IUHRDF
{
meta:
		info = "IUHRDF author"
		ref = "ee84c5d626bf8450782f24fd7d2f3ae6"
	strings:
		$ih = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 08 00 00 00 49 55 48 52 44 46  } 
	condition:
		$ih
}



rule apt_template_bmw
{
	meta:
		info = "author"
	strings:
		$bmw = { 04 00 00 00 00 00 00 00 1E 00 00 00 0C 00 00 00 4E 6F 72 6D 61 6C 2E 64 6F 74 00 00 1E 00 00 00 04 00 00 00 42 4D 57 00 } 
	condition:
		$bmw
}

rule apt_template_john_doe
{
meta:

		info = "author"
	strings:
		$doe = { 07 74 6E 61 75 74 68 6F 72 20 4A 6F 68 6E 20 44 6F 65 7D } 
	condition:
		$doe in (0..1024)
}

rule apt_template_captain
{
meta:
		info = "author"
	strings:
		$captain = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 08 00 00 00 63 61 70 74 61 69 6E } 
	condition:
		$captain
}

rule help_file_embed_exe
{
	meta:
		description = "Probably bad help file"
	strings:
		$type0 = {4C 4E 02 00}
		$type1 = {3F 5F 03 00}
		$patt1 = /RR\(.KERNEL32.DLL.,/ nocase
		$patt3 = "CreateThread" nocase
	condition:
		$type0 at 0 or $type1 at 0 and $patt1 and $patt3
}

rule gen_ie_secrets {
 	strings:
 	$a = "abe2869f-9b47-4cd9-a358-c22904dba7f7"
 condition:
 	all of them
}

rule this_dbl_xor
{
meta:
	hash = "d85d54434e990e84a28862523c277057"
strings:
	$a = {86 BB BD A6 F6 A7 5A 46 4D 59 4D 40 0E 4C 41 4F 4C 4C 50 05 44 42 18 4B 4F 55 1C 54 50 1F 74 7E 61 13 59 5A 52 52 }
condition:
	any of them
}

rule this_alt_key
{
meta:
	hash = "821f7ef4349d542f5f34f90b10bcc690"
strings:
$a = {79 BA 1E 6F E1 16 79 DF 32 88 FE 29 C9 ED 52 B6 13 4D B3 4C 73 D3 7B 72 D0 24 CF FD 57 FE C7 67 9E 52 7A D3 05 63}
condition:
	any of them
}

rule doc_zws_flash {
	meta:
	ref ="2192f9b0209b7e7aa6d32a075e53126d"
	author = "MalwareTracker.com"
	date = "2013-01-11"

	strings:
		$a = {66 55 66 55 ?? ?? ?? 00 5A 57 53}
		$b = "CONTROL ShockwaveFlash.ShockwaveFlash"
		
	condition:
		all of them 
}

rule builder_mswordintruder
{
	meta:
	hash = "ed1e15a51c4c3a83179b7cb3e79774bc0db6c2edf8ec27a564f79d5d8d53c5ae"

	strings:
	$s1 = {7b5c 7274 8950 4e47}
	$s2 = "IHDR"
	$s3 = "sRGBf"

	condition:
	all of them

}

rule office_hidden_url {
  meta:
    author = "@tylabs"
    hash = "tbd"
    description = "https://securelist.com/an-undocumented-word-feature-abused-by-attackers/81899/"
  strings:
    $a = "INCLUDEPICTURE" ascii
     //14 01 15 is the important part
    $b = {4D 45 52 47 45 46 4F 52 4D 41 54 20 5C 64 20 14 01 15}
    $magic = {D0 CF 11 E0}
  condition:
    $magic at 0 and $a and $b
}


rule xml_oleobj
{
	meta:
	hash = "ed1e15a51c4c3a83179b7cb3e79774bc0db6c2edf8ec27a564f79d5d8d53c5ae"

	strings:
        $header_xml = "<?xml version=" nocase wide ascii
	$s1 = "o:OLEObject" nocase wide ascii

	condition:
	all of them

}

rule xml_potential_heapspray
{
	meta:
	hash = "nil"

	strings:
        $header_xml = "<?xml version=" nocase wide ascii
	$s1 = "ax:classid=\"{00000000-0000-0000-0000-000000000001}\" ax:persistence=\"persistStorage\"" nocase wide ascii

	condition:
	all of them

}



