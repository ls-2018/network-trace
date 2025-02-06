package process

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"strconv"
	"strings"
)

type Sig int

func (s Sig) MarshalJSON() ([]byte, error) {
	var ss []string
	var i int
	for i = 0; i < 32; i++ {
		if (int(s) & (1 << i)) != 0 {
			ss = append(ss, fmt.Sprintf("%d(%s)", i+1, SignalName(i+1)))
		}
	}
	return json.Marshal(ss)
}

type PidSig struct {
	// SIGKILL 和 SIGSTOP 信号是两个特权信号，它们不可以被捕获和忽略
	SigBlk Sig `json:"SigBlk"` // 阻止
	SigIgn Sig `json:"SigIgn"` // 忽略
	SigCgt Sig `json:"SigCgt"` // 捕获
}

func Parse(pid int) (*PidSig, error) {
	ps := &PidSig{}
	// 打开 /proc/1/status 文件
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 1 {
			if strings.HasPrefix(line, "SigBlk") {
				i, err := strconv.ParseInt(fields[1], 16, 64)
				ps.SigBlk = Sig(int(i))
				if err != nil {
					return nil, errors.Wrap(err, "parse SigBlk failed")
				}
			}
			if strings.HasPrefix(line, "SigIgn") {
				i, err := strconv.ParseInt(fields[1], 16, 64)
				ps.SigIgn = Sig(int(i))
				if err != nil {
					return nil, errors.Wrap(err, "parse SigIgn failed")
				}
			}
			if strings.HasPrefix(line, "SigCgt") {
				i, err := strconv.ParseInt(fields[1], 16, 64)
				ps.SigCgt = Sig(int(i))
				if err != nil {
					return nil, errors.Wrap(err, "parse SigCgt failed")
				}
			}
		}
	}

	// 检查读取过程中的错误
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ps, nil
}

func SignalName(sig int) string {
	switch sig {
	case 1:
		return "SIGHUP" // 挂起信号，通常表示终端断开连接或终止控制进程。
	case 2:
		return "SIGINT" // 中断信号，通常是按 Ctrl+C 时发送给进程。
	case 3:
		return "SIGQUIT" // 退出信号，通常是按 Ctrl+\ 时发送给进程。
	case 4:
		return "SIGILL" // 非法指令信号，进程尝试执行无效或无法识别的指令。
	case 5:
		return "SIGTRAP" // 跟踪/调试信号，用于调试器。
	case 6:
		return "SIGABRT" // 中止信号，通常由进程通过 abort() 系统调用发送。
	case 7:
		return "SIGBUS" // 总线错误信号，通常发生在进程试图访问无效内存时。
	case 8:
		return "SIGFPE" // 浮动点异常信号，通常发生在算术运算错误（如除零）时。
	case 9:
		return "SIGKILL" // 强制终止信号，不能被捕获、阻塞或忽略，用于强制终止进程。
	case 10:
		return "SIGUSR1" // 用户定义的信号 1，供用户进程自定义使用。
	case 11:
		return "SIGSEGV" // 段错误信号，通常发生在进程访问无效内存地址时。
	case 12:
		return "SIGUSR2" // 用户定义的信号 2，供用户进程自定义使用。
	case 13:
		return "SIGPIPE" // 管道破裂信号，通常是向没有读取端的管道写入数据时发生。
	case 14:
		return "SIGALRM" // 定时器到期信号，通常由 alarm() 或 timer_create() 发出。
	case 15:
		return "SIGTERM" // 终止信号，表示请求进程优雅地终止。
	case 16:
		return "SIGSTKFLT" // 堆栈故障信号（很少使用）。
	case 17:
		return "SIGCHLD" // 子进程状态变化信号，通常在子进程退出时发送给父进程。
	case 18:
		return "SIGCONT" // 继续执行信号，恢复暂停或停止的进程。
	case 19:
		return "SIGSTOP" // 停止信号，强制暂停进程执行，不能被捕获、阻塞或忽略。
	case 20:
		return "SIGTSTP" // 终端暂停信号，通常是按 Ctrl+Z 时发送给前台进程。
	case 21:
		return "SIGTTIN" // 后台进程读取终端输入时发送的信号。
	case 22:
		return "SIGTTOU" // 后台进程写入终端输出时发送的信号。
	case 23:
		return "SIGURG" // 紧急数据到达信号，通常用于套接字编程。
	case 24:
		return "SIGXCPU" // 超过 CPU 时间限制信号。
	case 25:
		return "SIGXFSZ" // 超过文件大小限制信号。
	case 26:
		return "SIGVTALRM" // 虚拟定时器信号，通常由定时器生成。
	case 27:
		return "SIGPROF" // 进程剖析定时器信号，用于剖析进程的性能。
	case 28:
		return "SIGWINCH" // 窗口大小改变信号，通常由终端发送。
	case 29:
		return "SIGIO" // 输入/输出信号，通常用于异步 I/O 操作。
	case 30:
		return "SIGPWR" // 电源故障信号，通常在系统电源状态变化时发送。
	case 31:
		return "SIGSYS" // 系统调用错误信号，通常在系统调用传递错误参数时发生。
	}
	return fmt.Sprintf("%d", sig)
}
