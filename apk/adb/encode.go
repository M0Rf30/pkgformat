package adb

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"
)

// maxRepoCommit bounds the hexadecimal commit of an info object.
const maxRepoCommit = 128

// deps writes a dependency list: each dependency in the order given, then the
// array with its items sorted and de-duplicated.
func (b *builder) deps(list []string) (value, error) {
	if len(list) == 0 {
		return null, nil
	}

	type item struct {
		d Dependency
		v value
	}

	items := make([]item, 0, len(list))

	for _, s := range list {
		d, err := ParseDependency(s)
		if err != nil {
			return null, err
		}

		slots := make([]value, depMatch+1)
		slots[depName] = b.str(d.Name)
		slots[depVersion] = b.str(d.Version)

		if d.Match != 0 {
			slots[depMatch] = b.uint(uint64(d.Match))
		}

		items = append(items, item{d, b.object(typeObject, slots)})
	}

	slices.SortStableFunc(items, func(x, y item) int { return compareDeps(x.d, y.d) })

	slots := make([]value, 1, len(items)+1)

	for i, it := range items {
		if i > 0 && it.v == items[i-1].v {
			continue
		}

		slots = append(slots, it.v)
	}

	return b.object(typeObject, slots), nil
}

// strs writes a list of strings in the order given.
func (b *builder) strs(list []string) value {
	if len(list) == 0 {
		return null
	}

	slots := make([]value, 1, len(list)+1)
	for _, s := range list {
		slots = append(slots, b.str(s))
	}

	return b.object(typeObject, slots)
}

// acl writes an ACL: the mode, the owner and the extended attributes.
func (b *builder) acl(a *ACL) value {
	slots := make([]value, aclXattrs+1)
	slots[aclMode] = b.uint(uint64(a.Mode))
	slots[aclUser] = b.str(a.User)
	slots[aclGroup] = b.str(a.Group)

	if len(a.Xattrs) > 0 {
		type pair struct {
			raw []byte
			v   value
		}

		pairs := make([]pair, 0, len(a.Xattrs))

		for _, x := range a.Xattrs {
			raw := slices.Concat([]byte(x.Name), []byte{0}, x.Value)
			pairs = append(pairs, pair{raw, b.blob(raw)})
		}

		slices.SortStableFunc(pairs, func(x, y pair) int { return bytes.Compare(x.raw, y.raw) })

		vals := make([]value, 1, len(pairs)+1)
		for _, p := range pairs {
			vals = append(vals, p.v)
		}

		slots[aclXattrs] = b.object(typeArray, vals)
	}

	return b.object(typeObject, slots)
}

// file writes a file entry. link, when not nil, is the target blob of a
// file that later entries hard-link to; it is written before the entry, as
// the first file of a link group is.
func (b *builder) file(f *FileEntry, preLink []byte) value {
	if preLink != nil {
		b.blob(preLink)
	}

	slots := make([]value, fiTarget+1)
	slots[fiName] = b.str(f.Name)
	slots[fiHash] = b.blob(f.Hash)
	slots[fiTarget] = b.blob(f.Target)
	slots[fiMTime] = b.uint(f.MTime)
	slots[fiSize] = b.uint(f.Size)
	slots[fiACL] = b.acl(&f.ACL)

	return b.object(typeObject, slots)
}

// info writes the scalar fields of an info object in field order. For a
// package the identity hash, the installed size and the file size are left to
// the caller; for an index entry all are written.
func (b *builder) info(in *Info, index bool) ([]value, error) {
	slots := make([]value, piMax)

	if err := checkPkgName(in.Name); err != nil {
		return nil, err
	}

	if !ValidVersion(in.Version) {
		return nil, specErr("invalid version %q", in.Version)
	}

	slots[piName] = b.str(in.Name)
	slots[piVersion] = b.str(in.Version)

	if index && len(in.Hashes) > 0 {
		slots[piHashes] = b.blob(in.Hashes)
	}

	slots[piDescription] = b.str(in.Description)
	slots[piArch] = b.str(in.Arch)
	slots[piLicense] = b.str(in.License)
	slots[piOrigin] = b.str(in.Origin)
	slots[piMaintainer] = b.str(in.Maintainer)
	slots[piURL] = b.str(in.URL)

	if in.RepoCommit != "" {
		raw, err := hex.DecodeString(in.RepoCommit)
		if err != nil || len(in.RepoCommit) < 40 || len(in.RepoCommit) > maxRepoCommit {
			return nil, specErr("repo-commit %q is not 40 to %d hexadecimal digits", in.RepoCommit, maxRepoCommit)
		}

		slots[piRepoCommit] = b.blob(raw)
	}

	if in.BuildTime != 0 {
		slots[piBuildTime] = b.uint(in.BuildTime)
	}

	if index {
		if in.InstalledSize != 0 {
			slots[piInstalledSize] = b.uint(in.InstalledSize)
		}

		if in.FileSize != 0 {
			slots[piFileSize] = b.uint(in.FileSize)
		}
	}

	if in.ProviderPriority != 0 {
		slots[piProviderPriority] = b.uint(in.ProviderPriority)
	}

	var err error

	for _, f := range [...]struct {
		slot int
		list []string
	}{
		{piDepends, in.Depends}, {piProvides, in.Provides}, {piReplaces, in.Replaces},
		{piInstallIf, in.InstallIf}, {piRecommends, in.Recommends},
	} {
		if slots[f.slot], err = b.deps(f.list); err != nil {
			return nil, err
		}
	}

	if in.Layer != 0 {
		slots[piLayer] = b.uint(in.Layer)
	}

	for _, t := range in.Tags {
		if t == "" || strings.ContainsFunc(t, func(r rune) bool { return r > 0x7f || !isTagByte(byte(r)) }) {
			return nil, specErr("invalid tag %q", t)
		}
	}

	slots[piTags] = b.strs(in.Tags)

	return slots, nil
}

// compareInfo orders the entries of an index like apk: by the scalar fields in
// the order of the schema, the name and the version first.
func compareInfo(a, b *Info) int {
	for _, r := range [...]int{
		strings.Compare(a.Name, b.Name),
		compareOptVersion(a.Version, b.Version),
		bytes.Compare(a.Hashes, b.Hashes),
		strings.Compare(a.Description, b.Description),
		strings.Compare(a.Arch, b.Arch),
		strings.Compare(a.License, b.License),
		strings.Compare(a.Origin, b.Origin),
		strings.Compare(a.Maintainer, b.Maintainer),
		strings.Compare(a.URL, b.URL),
		strings.Compare(a.RepoCommit, b.RepoCommit),
		cmpUint(a.BuildTime, b.BuildTime),
		cmpUint(a.InstalledSize, b.InstalledSize),
		cmpUint(a.FileSize, b.FileSize),
		cmpUint(a.ProviderPriority, b.ProviderPriority),
	} {
		if r != 0 {
			return r
		}
	}

	return 0
}
