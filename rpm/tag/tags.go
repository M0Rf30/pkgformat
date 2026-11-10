/*
 * Copyright (c) SAS Institute, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package tag holds the numeric constants of the RPM header format: the types
// of header entries, the tag numbers of the general header and of the signature
// header (mirroring rpmtag.h of rpm), the bitmasks found in some of the tags,
// and the OpenPGP hash algorithm identifiers used by signatures.
//
// The reader (package rpm) and the writer (package pack) share these constants.
package tag

// tag data types
const (
	RPM_NULL_TYPE         = 0
	RPM_CHAR_TYPE         = 1
	RPM_INT8_TYPE         = 2
	RPM_INT16_TYPE        = 3
	RPM_INT32_TYPE        = 4
	RPM_INT64_TYPE        = 5
	RPM_STRING_TYPE       = 6
	RPM_BIN_TYPE          = 7
	RPM_STRING_ARRAY_TYPE = 8
	RPM_I18NSTRING_TYPE   = 9
)

// RPM header tags found in the general header
const (
	GENERAL_TAG_BASE  = 1000
	NAME              = 1000
	VERSION           = 1001
	RELEASE           = 1002
	EPOCH             = 1003
	SUMMARY           = 1004
	DESCRIPTION       = 1005
	BUILDTIME         = 1006
	BUILDHOST         = 1007
	INSTALLTIME       = 1008
	SIZE              = 1009
	DISTRIBUTION      = 1010
	VENDOR            = 1011
	GIF               = 1012
	XPM               = 1013
	LICENSE           = 1014
	PACKAGER          = 1015
	GROUP             = 1016
	CHANGELOG         = 1017
	SOURCE            = 1018
	PATCH             = 1019
	URL               = 1020
	OS                = 1021
	ARCH              = 1022
	PREIN             = 1023
	POSTIN            = 1024
	PREUN             = 1025
	POSTUN            = 1026
	OLDFILENAMES      = 1027
	FILESIZES         = 1028
	FILEMODES         = 1030
	FILERDEVS         = 1033
	FILEMTIMES        = 1034
	FILEDIGESTS       = 1035 // AKA FILEMD5S
	FILELINKTOS       = 1036
	FILEFLAGS         = 1037 // bitmask: RPMFILE_* are bitmasks to interpret
	FILEUSERNAME      = 1039
	FILEGROUPNAME     = 1040
	ICON              = 1043
	SOURCERPM         = 1044
	FILEVERIFYFLAGS   = 1045 // bitmask: RPMVERIFY_* are bitmasks to interpret
	ARCHIVESIZE       = 1046
	PROVIDENAME       = 1047
	REQUIREFLAGS      = 1048
	REQUIRENAME       = 1049
	REQUIREVERSION    = 1050
	CONFLICTFLAGS     = 1053
	CONFLICTNAME      = 1054
	CONFLICTVERSION   = 1055
	RPMVERSION        = 1064
	TRIGGERSCRIPTS    = 1065
	TRIGGERNAME       = 1066
	TRIGGERVERSION    = 1067
	TRIGGERFLAGS      = 1068 // bitmask: RPMSENSE_* are bitmasks to interpret
	TRIGGERINDEX      = 1069
	VERIFYSCRIPT      = 1079
	CHANGELOGTIME     = 1080
	CHANGELOGNAME     = 1081
	CHANGELOGTEXT     = 1082
	PREINPROG         = 1085
	POSTINPROG        = 1086
	PREUNPROG         = 1087
	POSTUNPROG        = 1088
	OBSOLETENAME      = 1090
	FILEDEVICES       = 1095
	FILEINODES        = 1096
	FILELANGS         = 1097
	PREFIXES          = 1098
	PROVIDEFLAGS      = 1112
	PROVIDEVERSION    = 1113
	OBSOLETEFLAGS     = 1114
	OBSOLETEVERSION   = 1115
	VERIFYSCRIPTPROG  = 1091
	TRIGGERSCRIPTPROG = 1092
	DIRINDEXES        = 1116
	BASENAMES         = 1117
	DIRNAMES          = 1118
	PAYLOADFORMAT     = 1124
	PAYLOADCOMPRESSOR = 1125
	PAYLOADFLAGS      = 1126
	FILECOLORS        = 1140
	PRETRANS          = 1151
	POSTTRANS         = 1152
	PRETRANSPROG      = 1153
	POSTTRANSPROG     = 1154

	OLDSUGGESTSNAME    = 1156 // obsolete
	OLDSUGGESTSVERSION = 1157 // obsolete
	OLDSUGGESTSFLAGS   = 1158 // obsolete
	OLDENHANCESNAME    = 1159 // obsolete
	OLDENHANCESVERSION = 1160 // obsolete
	OLDENHANCESFLAGS   = 1161 // obsolete

	// BLINK*, FLINK*, and TRIGGERPREIN are tags of the SUSE flavour of RPM
	BLINKPKGID   = 1164
	BLINKHDRID   = 1165
	BLINKNEVRA   = 1166
	FLINKPKGID   = 1167
	FLINKHDRID   = 1168
	FLINKNEVRA   = 1169
	TRIGGERPREIN = 1170

	LONGFILESIZES  = 5008
	LONGSIZE       = 5009
	FILECAPS       = 5010
	FILEDIGESTALGO = 5011
	BUGURL         = 5012
	VCS            = 5034

	RECOMMENDNAME     = 5046
	RECOMMENDVERSION  = 5047
	RECOMMENDFLAGS    = 5048
	SUGGESTNAME       = 5049
	SUGGESTVERSION    = 5050
	SUGGESTFLAGS      = 5051
	SUPPLEMENTNAME    = 5052
	SUPPLEMENTVERSION = 5053
	SUPPLEMENTFLAGS   = 5054
	ENHANCENAME       = 5055
	ENHANCEVERSION    = 5056
	ENHANCEFLAGS      = 5057

	ENCODING = 5062

	// PAYLOADDIGEST is the digest of the compressed payload. In RPM v6 it is
	// always SHA256 (the algorithm tag is omitted); also known as PAYLOADSHA256.
	PAYLOADDIGEST      = 5092
	PAYLOADDIGESTALGO  = 5093
	PAYLOADSHA256ALT   = 5097 // SHA256 of the uncompressed payload
	PAYLOADSIZE        = 5112 // compressed payload size (INT64)
	PAYLOADSIZEALT     = 5113 // uncompressed payload size (INT64)
	RPMFORMAT          = 5114 // package format version (INT32), absent in v4
	FILEMIMEINDEX      = 5115
	MIMEDICT           = 5116
	SOURCENEVR         = 5120
	PAYLOADSHA512      = 5121 // SHA512 of the compressed payload
	PAYLOADSHA512ALT   = 5122 // SHA512 of the uncompressed payload
	PAYLOADSHA3_256    = 5123 // SHA3-256 of the compressed payload
	PAYLOADSHA3_256ALT = 5124 // SHA3-256 of the uncompressed payload
)

// RPM header tags found in the signature header
const (
	SIG_BASE            = 256
	SIG_DSA             = SIG_BASE + 11 // DSA signature over header only
	SIG_RSA             = SIG_BASE + 12 // RSA signature over header only
	SIG_SHA1            = SIG_BASE + 13 // SHA1 over header only (hex)
	SIG_LONGSIGSIZE     = SIG_BASE + 14 // header + compressed payload (uint64)
	SIG_LONGARCHIVESIZE = SIG_BASE + 15 // uncompressed payload bytes (uint64)
	SIG_SHA256          = SIG_BASE + 17 // SHA256 over header only (hex)
	SIG_OPENPGP         = SIG_BASE + 22 // RPM v6: base64 OpenPGP signatures over header only (string array)
	SIG_SHA3_256        = SIG_BASE + 23 // RPM v6: SHA3-256 over header only (hex)
	SIG_RESERVED        = 999           // RPM v6: reserved space for signatures

	// SIGHEADER_TAG_BASE offsets the signature tags that overlap the numbers of
	// general header tags, so that both kinds can be addressed with a single
	// number (RpmHeader.Get and friends). It is not part of the file format:
	// the number stored in the signature header is the tag minus
	// SIGHEADER_TAG_BASE, e.g. SIG_SIZE - SIGHEADER_TAG_BASE is 1000.
	SIGHEADER_TAG_BASE = 16384
	SIG_SIZE           = SIGHEADER_TAG_BASE + 1000 // Header + Payload size
	SIG_PGP            = SIGHEADER_TAG_BASE + 1002 // Signature over header + payload
	SIG_MD5            = SIGHEADER_TAG_BASE + 1004 // MD5SUM of header + payload
	SIG_GPG            = SIGHEADER_TAG_BASE + 1005 // (same as SIG_PGP)
	SIG_PAYLOADSIZE    = SIGHEADER_TAG_BASE + 1007 // uncompressed payload bytes (uint32)
	SIG_RESERVEDSPACE  = SIGHEADER_TAG_BASE + 1008 // blank space that can be replaced by a signature
)

// FILEFLAGS bitmask elements
const (
	RPMFILE_NONE      = 0
	RPMFILE_CONFIG    = 1 << 0
	RPMFILE_DOC       = 1 << 1
	RPMFILE_ICON      = 1 << 2
	RPMFILE_MISSINGOK = 1 << 3
	RPMFILE_NOREPLACE = 1 << 4
	RPMFILE_SPECFILE  = 1 << 5
	RPMFILE_GHOST     = 1 << 6
	RPMFILE_LICENSE   = 1 << 7
	RPMFILE_README    = 1 << 8
	RPMFILE_EXCLUDE   = 1 << 9
	RPMFILE_UNPATCHED = 1 << 10
	RPMFILE_PUBKEY    = 1 << 11
	RPMFILE_POLICY    = 1 << 12
)

// FILEVERIFYFLAGS bitmask elements
const (
	RPMVERIFY_NONE       = 0
	RPMVERIFY_MD5        = 1 << 0
	RPMVERIFY_FILEDIGEST = 1 << 0
	RPMVERIFY_FILESIZE   = 1 << 1
	RPMVERIFY_LINKTO     = 1 << 2
	RPMVERIFY_USER       = 1 << 3
	RPMVERIFY_GROUP      = 1 << 4
	RPMVERIFY_MTIME      = 1 << 5
	RPMVERIFY_MODE       = 1 << 6
	RPMVERIFY_RDEV       = 1 << 7
	RPMVERIFY_CAPS       = 1 << 8
	RPMVERIFY_CONTEXTS   = 1 << 15
)

// TRIGGERFLAGS bitmask elements -- not all rpmsenseFlags make sense in TRIGGERFLAGS
const (
	RPMSENSE_ANY     = 0
	RPMSENSE_LESS    = 1 << 1
	RPMSENSE_GREATER = 1 << 2
	RPMSENSE_EQUAL   = 1 << 3

	RPMSENSE_POSTTRANS   = 1 << 5
	RPMSENSE_PREREQ      = 1 << 6
	RPMSENSE_PRETRANS    = 1 << 7
	RPMSENSE_INTERP      = 1 << 8
	RPMSENSE_SCRIPT_PRE  = 1 << 9
	RPMSENSE_SCRIPT_POST = 1 << 10

	// RPMSENSE_RPMLIB marks rpmlib(...) feature requirements.
	RPMSENSE_RPMLIB = 1 << 24

	RPMSENSE_TRIGGERIN     = 1 << 16
	RPMSENSE_TRIGGERUN     = 1 << 17
	RPMSENSE_TRIGGERPOSTUN = 1 << 18
	RPMSENSE_TRIGGERPREIN  = 1 << 25
)

// Header region tags
const (
	HEADERI18NTABLE         = 100
	RPMTAG_HEADERSIGNATURES = 62
	RPMTAG_HEADERIMMUTABLE  = 63
	RPMTAG_HEADERREGIONS    = 64
)

// Crypto algos
const (
	HASH_MD5         = 1
	HASH_SHA1        = 2
	HASH_RIPEMD160   = 3
	HASH_MD2         = 5
	HASH_TIGER192    = 6
	HASH_HAVAL_5_160 = 7
	HASH_SHA256      = 8
	HASH_SHA384      = 9
	HASH_SHA512      = 10
	HASH_SHA224      = 11
)
