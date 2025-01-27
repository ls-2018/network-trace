package main

import (
	"fmt"
	"os/exec"
)

func main() {
	// 定义 AppleScript 的内容
	script := `
tell application "iTerm"
    -- 创建新的窗口
    set newWindow to (create window with default profile)
	
    -- 切换到新窗口
    tell current session of newWindow
		write text "ssh root@vm2404"
		write text "cd /ebpf/ebpf-nftrace"
		write text "make  "
    end tell
	delay 1 


	tell current session of newWindow
		set newSession to (split horizontally with default profile)
	end tell
	delay 1
	tell newSession
        write text "ssh root@vm2404"
        write text "watch -d nft -a list ruleset"
	end tell

	tell current session of newWindow
		set newSession to (split vertically with default profile)
	end tell
	delay 1
	tell newSession
		write text "ssh root@vm2404"
        write text "ping -c 100000 -i 1 -s 64 8.8.8.8"
	end tell

	tell current session of newWindow
		set newSession to (split vertically with default profile)
	end tell
	delay 1
	tell newSession
		write text "ssh root@vm2404"
        write text "cat /sys/kernel/debug/tracing/trace_pipe"
	end tell
end tell
`

	// 创建临时文件以写入 AppleScript
	tmpFile, err := exec.Command("mktemp").Output()
	if err != nil {
		fmt.Println("Error creating temporary file:", err)
		return
	}
	//exec.Command("bash", "-c", " cd /Users/acejilam/Desktop/vm && pkill -9 vmware-vmx && vagrant reload").Run()

	scriptFile := string(tmpFile)[:len(tmpFile)-1] // remove the trailing newline

	// 将 AppleScript 写入临时文件
	err = exec.Command("bash", "-c", fmt.Sprintf("echo '%s' > %s", script, scriptFile)).Run()
	if err != nil {
		fmt.Println("Error writing script to file:", err)
		return
	}

	// 使用 osascript 执行 AppleScript
	err = exec.Command("osascript", scriptFile).Run()
	if err != nil {
		fmt.Println("Error executing script:", err)
		return
	}

	// 一旦完成，您可以删除临时文件
	exec.Command("rm", scriptFile).Run()

	fmt.Println("Commands executed in iTerm2 windows.")
}
