// Package xzlimit guards the xz decoder against streams that declare an
// oversized dictionary: the decoder allocates whatever the header asks for, up
// to 4 GiB, before reading any data. NewReader vets every block header against
// MaxDictSize first and decodes a single stream; CheckDictCap does the same
// for a stream already in memory.
package xzlimit
