package nftrace

import (
	"bufio"
	"github.com/pkg/errors"
	"os"
	"strings"
)

var (
	RequiredKernelModules = []string{"nf_tables"}
)

func IsKernelModuleLoaded(moduleName string) (bool, error) {
	file, err := os.Open("/proc/modules")
	if err != nil {
		return false, errors.WithMessage(err, "failed to open /proc/modules")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, moduleName+" ") {
			return true, nil
		}
	}

	if err = scanner.Err(); err != nil {
		return false, errors.WithMessage(err, "error reading /proc/modules")
	}

	return false, nil
}
