package main

import (
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"github.com/iovisor/gobpf/elf"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
)

//go:embed bin/src
var bins embed.FS

func decompress(data []byte) (string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer func(reader *gzip.Reader) {
		err := reader.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(reader)

	var result bytes.Buffer
	_, err = io.Copy(&result, reader)
	if err != nil {
		return "", err
	}
	return result.String(), nil
}

func findFirstSmaller(nums []uint32, target uint32) (uint32, bool) {
	// 排序数组
	sort.SliceStable(nums, func(i, j int) bool { return nums[i] < nums[j] })

	// 遍历查找比目标小的第一个数
	for i := len(nums) - 1; i >= 0; i-- {
		if nums[i] < target {
			return nums[i], true
		}
	}
	// 如果没有比目标小的数
	return 0, false
}

func main() {
	var vs []uint32
	var vsMap = map[uint32][2]string{}
	// 读取 bin 目录下的所有文件和子目录
	entries, err := bins.ReadDir("bin/src")
	if err != nil {
		log.Fatalf("Failed to read embedded directory: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".gz" {
			preLen := len(entry.Name()) - len(filepath.Ext(entry.Name()))
			name := filepath.Base(entry.Name())[:preLen]
			release, err := elf.KernelVersionFromReleaseString(name)
			if err != nil {
				log.Fatalf("Failed to extract ELF version from %s: %v", name, err)
			}
			vs = append(vs, release)
			vsMap[release] = [2]string{entry.Name(), name}
		}
	}
	version, err := elf.CurrentKernelVersion()
	if err != nil {
		log.Fatalf("Failed to extract ELF version: %v", err)
	}

	smaller, b := findFirstSmaller(vs, version)
	if !b {
		log.Fatalf("Failed to find smaller %d", version)
	}
	names := vsMap[smaller]

	tmpDirs, err := os.MkdirTemp("", "main")
	if err != nil {
		fmt.Println("Error creating temp file:", err)
		return
	}

	bin := path.Join(tmpDirs, names[1])
	ko := path.Join(tmpDirs, "iptables-trace.ko")
	file, err := bins.ReadFile("bin/src/" + names[0])
	if err != nil {
		log.Fatalf("Failed to read embedded binary: %v", err)
	}
	ddata, err := decompress(file)
	if err != nil {
		log.Fatalf("Failed to decompress binary: %v", err)
	}
	err = ioutil.WriteFile(bin, []byte(ddata), 0755)
	log.Printf("Created embedded binary: %s", bin)
	if err != nil {
		fmt.Println("Error writing to temp file:", err)
		return
	}

	cmd := exec.Command(bin, fmt.Sprintf("--ko=%s", ko))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
