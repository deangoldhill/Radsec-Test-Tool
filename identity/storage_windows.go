//go:build windows

package identity

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	size uint32
	data *byte
}

var crypt32 = syscall.NewLazyDLL("crypt32.dll")
var protect = crypt32.NewProc("CryptProtectData")
var unprotect = crypt32.NewProc("CryptUnprotectData")
var localFree = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func blob(b []byte) dataBlob { return dataBlob{uint32(len(b)), &b[0]} }
func dpapi(input []byte, encrypt bool) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("empty identity")
	}
	in := blob(input)
	var out dataBlob
	proc := protect
	if !encrypt {
		proc = unprotect
	}
	ok, _, _ := proc.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(input)
	if ok == 0 {
		return nil, errors.New("Windows identity protection failed")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.data)))
	if out.data == nil || out.size == 0 || out.size > MaxPlainBytes+4096 {
		return nil, errors.New("invalid protected identity size")
	}
	return append([]byte(nil), unsafe.Slice(out.data, int(out.size))...), nil
}
func identityPath() (string, error) {
	base := os.Getenv("APPDATA")
	if base == "" {
		return "", errors.New("APPDATA is unavailable")
	}
	return filepath.Join(base, "RadSecConnectionLab", "identity.dpapi"), nil
}
func Save(p Profile) error {
	if err := Validate(p); err != nil {
		return err
	}
	raw, err := Marshal(p)
	if err != nil {
		return err
	}
	ciphertext, err := dpapi(raw, true)
	clear(raw)
	if err != nil {
		return err
	}
	defer clear(ciphertext)
	path, err := identityPath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New("cannot create identity directory")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return errors.New("cannot create protected identity")
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(ciphertext)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot write protected identity")
	}
	src := syscall.StringToUTF16Ptr(f.Name())
	dst := syscall.StringToUTF16Ptr(path)
	ok, _, _ := moveFileEx.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), 0x1|0x8) // REPLACE_EXISTING | WRITE_THROUGH
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	if ok == 0 {
		return errors.New("cannot replace protected identity")
	}
	return nil
}
func Load() (Profile, error) {
	path, err := identityPath()
	if err != nil {
		return Profile{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() < 1 || info.Size() > MaxPlainBytes+4096 {
		return Profile{}, errors.New("invalid protected identity size")
	}
	ciphertext, err := io.ReadAll(io.LimitReader(f, MaxPlainBytes+4097))
	if err != nil || len(ciphertext) > MaxPlainBytes+4096 {
		return Profile{}, errors.New("cannot read protected identity")
	}
	raw, err := dpapi(ciphertext, false)
	if err != nil {
		return Profile{}, err
	}
	defer clear(raw)
	p, err := Unmarshal(raw)
	if err != nil {
		return Profile{}, err
	}
	if err = Validate(p); err != nil {
		return Profile{}, err
	}
	return p, nil
}
func Forget() error {
	path, err := identityPath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("cannot remove protected identity")
	}
	return nil
}
