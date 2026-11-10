// Package cpio reads, writes and extracts the cpio archives that make up the
// payload of rpm packages: the "newc" format of format 4 packages and the
// stripped variant of format 6 packages, which holds only the index of each
// file in the header.
//
// Reader and CpioStream read archives sequentially, Writer writes them and
// Extract extracts an archive below a directory.
package cpio
