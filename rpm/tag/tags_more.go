// Tag numbers, flags and enumerations of rpm 6 that the reader and the writer
// expose beyond the core set in tags.go. Values are those of rpmtag.h and
// rpmds.h of rpm 6.0.

package tag

// More RPM header tags found in the general header.
const (
	FILESTATES                  = 1029
	NOSOURCE                    = 1051
	NOPATCH                     = 1052
	EXCLUDEARCH                 = 1059
	EXCLUDEOS                   = 1060
	EXCLUSIVEARCH               = 1061
	EXCLUSIVEOS                 = 1062
	BUILDARCHS                  = 1089
	COOKIE                      = 1094
	INSTPREFIXES                = 1099
	SOURCEPACKAGE               = 1106
	ORIGDIRINDEXES              = 1119
	ORIGBASENAMES               = 1120
	ORIGDIRNAMES                = 1121
	OPTFLAGS                    = 1122
	DISTURL                     = 1123
	INSTALLCOLOR                = 1127
	INSTALLTID                  = 1128
	REMOVETID                   = 1129
	PLATFORM                    = 1132
	PATCHESNAME                 = 1133
	PATCHESFLAGS                = 1134
	PATCHESVERSION              = 1135
	FILECLASS                   = 1141
	CLASSDICT                   = 1142
	FILEDEPENDSX                = 1143
	FILEDEPENDSN                = 1144
	DEPENDSDICT                 = 1145
	SOURCESIGMD5                = 1146
	FILECONTEXTS                = 1147
	FSCONTEXTS                  = 1148
	RECONTEXTS                  = 1149
	POLICIES                    = 1150
	DISTTAG                     = 1155
	DBINSTANCE                  = 1195
	NVRA                        = 1196
	FILENAMES                   = 5000
	FILEPROVIDE                 = 5001
	FILEREQUIRE                 = 5002
	TRIGGERCONDS                = 5005
	TRIGGERTYPE                 = 5006
	ORIGFILENAMES               = 5007
	EVR                         = 5013
	NVR                         = 5014
	NEVR                        = 5015
	NEVRA                       = 5016
	HEADERCOLOR                 = 5017
	VERBOSE                     = 5018
	EPOCHNUM                    = 5019
	PREINFLAGS                  = 5020
	POSTINFLAGS                 = 5021
	PREUNFLAGS                  = 5022
	POSTUNFLAGS                 = 5023
	PRETRANSFLAGS               = 5024
	POSTTRANSFLAGS              = 5025
	VERIFYSCRIPTFLAGS           = 5026
	TRIGGERSCRIPTFLAGS          = 5027
	POLICYNAMES                 = 5030
	POLICYTYPES                 = 5031
	POLICYTYPESINDEXES          = 5032
	POLICYFLAGS                 = 5033
	ORDERNAME                   = 5035
	ORDERVERSION                = 5036
	ORDERFLAGS                  = 5037
	INSTFILENAMES               = 5040
	REQUIRENEVRS                = 5041
	PROVIDENEVRS                = 5042
	OBSOLETENEVRS               = 5043
	CONFLICTNEVRS               = 5044
	FILENLINKS                  = 5045
	RECOMMENDNEVRS              = 5058
	SUGGESTNEVRS                = 5059
	SUPPLEMENTNEVRS             = 5060
	ENHANCENEVRS                = 5061
	FILETRIGGERSCRIPTS          = 5066
	FILETRIGGERSCRIPTPROG       = 5067
	FILETRIGGERSCRIPTFLAGS      = 5068
	FILETRIGGERNAME             = 5069
	FILETRIGGERINDEX            = 5070
	FILETRIGGERVERSION          = 5071
	FILETRIGGERFLAGS            = 5072
	TRANSFILETRIGGERSCRIPTS     = 5076
	TRANSFILETRIGGERSCRIPTPROG  = 5077
	TRANSFILETRIGGERSCRIPTFLAGS = 5078
	TRANSFILETRIGGERNAME        = 5079
	TRANSFILETRIGGERINDEX       = 5080
	TRANSFILETRIGGERVERSION     = 5081
	TRANSFILETRIGGERFLAGS       = 5082
	FILETRIGGERPRIORITIES       = 5084
	TRANSFILETRIGGERPRIORITIES  = 5085
	FILETRIGGERCONDS            = 5086
	FILETRIGGERTYPE             = 5087
	TRANSFILETRIGGERCONDS       = 5088
	TRANSFILETRIGGERTYPE        = 5089
	FILESIGNATURES              = 5090
	FILESIGNATURELENGTH         = 5091
	MODULARITYLABEL             = 5096
	ARCHSUFFIX                  = 5098
	SPEC                        = 5099
	TRANSLATIONURL              = 5100
	UPSTREAMRELEASES            = 5101
	PREUNTRANS                  = 5103
	POSTUNTRANS                 = 5104
	PREUNTRANSPROG              = 5105
	POSTUNTRANSPROG             = 5106
	PREUNTRANSFLAGS             = 5107
	POSTUNTRANSFLAGS            = 5108
	SYSUSERS                    = 5109
	FILEMIMES                   = 5117
	PACKAGEDIGESTS              = 5118
	PACKAGEDIGESTALGOS          = 5119
)

// More signature header tags.
const (
	SIG_PUBKEYS             = SIG_BASE + 10 // OpenPGP public keys (unused in packages)
	SIG_VERITYSIGNATURES    = SIG_BASE + 20 // fs-verity signatures, one per file (base64)
	SIG_VERITYSIGNATUREALGO = SIG_BASE + 21 // fs-verity signature algorithm
)

// More dependency sense flags (rpmds.h).
const (
	RPMSENSE_SCRIPT_PREUN  = 2048
	RPMSENSE_SCRIPT_POSTUN = 4096
	RPMSENSE_SCRIPT_VERIFY = 8192
	RPMSENSE_FIND_REQUIRES = 16384
	RPMSENSE_FIND_PROVIDES = 32768
	RPMSENSE_MISSINGOK     = 524288
	RPMSENSE_PREUNTRANS    = 1048576
	RPMSENSE_POSTUNTRANS   = 2097152
	RPMSENSE_KEYRING       = 67108864
	RPMSENSE_CONFIG        = 268435456
	RPMSENSE_RICH          = 536870912 // set by rpm on rich (boolean) dependencies when parsing; never stored
)

// More file flags.
const (
	RPMFILE_ARTIFACT = 4096
)

// File states (FILESTATES).
const (
	RPMFILE_STATE_NORMAL       = 0
	RPMFILE_STATE_REPLACED     = 1
	RPMFILE_STATE_NOTINSTALLED = 2
	RPMFILE_STATE_NETSHARED    = 3
	RPMFILE_STATE_WRONGCOLOR   = 4
)

// Scriptlet flags (*FLAGS tags such as PREINFLAGS).
const (
	RPMSCRIPT_FLAG_EXPAND   = 1 << 0 // macro expansion
	RPMSCRIPT_FLAG_QFORMAT  = 1 << 1 // header queryformat expansion
	RPMSCRIPT_FLAG_CRITICAL = 1 << 2 // a failure aborts the transaction
)
