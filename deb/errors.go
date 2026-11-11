package deb

import "errors"

// Sentinel errors. Functions wrap them with context, so match with errors.Is.
var (
	// ErrInvalidPackage wraps every structural problem found in a .deb file.
	ErrInvalidPackage = errors.New("deb: invalid package")

	// ErrInvalidARMagic is returned when a file does not start with the ar magic.
	ErrInvalidARMagic = errors.New("deb: invalid ar archive magic")
	// ErrInvalidHeaderSize is returned for an ar member header that is not 60 bytes.
	ErrInvalidHeaderSize = errors.New("deb: invalid ar header size")
	// ErrInvalidModTime is returned for an unparsable ar modification time.
	ErrInvalidModTime = errors.New("deb: invalid ar modification time")
	// ErrInvalidOwnerID is returned for an unparsable ar owner id.
	ErrInvalidOwnerID = errors.New("deb: invalid ar owner id")
	// ErrInvalidGroupID is returned for an unparsable ar group id.
	ErrInvalidGroupID = errors.New("deb: invalid ar group id")
	// ErrInvalidMode is returned for an unparsable ar mode.
	ErrInvalidMode = errors.New("deb: invalid ar mode")
	// ErrInvalidSize is returned for an unparsable or negative ar member size.
	ErrInvalidSize = errors.New("deb: invalid ar member size")
	// ErrARMemberTooLarge is returned for a member that is larger than the file
	// holding it or than the limit for its kind.
	ErrARMemberTooLarge = errors.New("deb: ar member size exceeds maximum allowed")
	// ErrInvalidARHeaderEnd is returned when an ar header lacks its "`\n" trailer.
	ErrInvalidARHeaderEnd = errors.New("deb: invalid ar header ending marker")
	// ErrTooManyMembers is returned for an ar archive with more members than a .deb needs.
	ErrTooManyMembers = errors.New("deb: too many ar members")

	// ErrInvalidControlFormat is returned for a malformed deb822 paragraph.
	ErrInvalidControlFormat = errors.New("deb: invalid control file format")
	// ErrMissingRequiredField is returned when a mandatory control field is absent or empty.
	ErrMissingRequiredField = errors.New("deb: required field not found in control file")

	// ErrControlArchiveNotFound is returned when a .deb has no control.tar member.
	ErrControlArchiveNotFound = errors.New("deb: control archive not found in deb file")
	// ErrDataArchiveNotFound is returned when a .deb has no data.tar member.
	ErrDataArchiveNotFound = errors.New("deb: data archive not found in deb file")
	// ErrUnsupportedArchiveFormat is returned for a member with an unknown compression suffix.
	ErrUnsupportedArchiveFormat = errors.New("deb: unsupported archive compression")
	// ErrFileNotFoundInTar is returned when a wanted file is not in a tar archive.
	ErrFileNotFoundInTar = errors.New("deb: file not found in tar archive")

	// ErrDebFileTooLarge is returned for a .deb over MaxDebFileSize.
	ErrDebFileTooLarge = errors.New("deb: deb file exceeds max size")
	// ErrControlArchiveTooLarge is returned for a control archive that
	// decompresses to more than MaxControlArchiveSize.
	ErrControlArchiveTooLarge = errors.New("deb: control archive exceeds max decompressed size")
	// ErrControlFileTooLarge is returned for a control file over MaxControlFileSize.
	ErrControlFileTooLarge = errors.New("deb: control file exceeds max size")
	// ErrTooLarge is returned when a text input (a line, a paragraph, an index,
	// a Release file) is over its size limit.
	ErrTooLarge = errors.New("deb: input exceeds size limit")
	// ErrDataTooLarge is returned when extracting a data archive would exceed the
	// configured byte or entry limit.
	ErrDataTooLarge = errors.New("deb: data archive exceeds extraction limit")
	// ErrUnsafeEntry is returned for a data archive entry that would be written
	// outside the extraction directory.
	ErrUnsafeEntry = errors.New("deb: unsafe archive entry")

	// ErrInvalidRelease is returned for a malformed Release file.
	ErrInvalidRelease = errors.New("deb: invalid release file")

	// ErrInvalidSpec is returned by the package writer for a Spec that cannot
	// be turned into a valid .deb.
	ErrInvalidSpec = errors.New("deb: invalid package spec")
	// ErrUnsupportedEntryType is returned by the package writer for a payload
	// entry of a type a tar archive cannot hold, such as a socket.
	ErrUnsupportedEntryType = errors.New("deb: unsupported entry type")
	// ErrUnsupportedCompression is returned for a compression name the writer
	// does not know.
	ErrUnsupportedCompression = errors.New("deb: unsupported compression")
)
