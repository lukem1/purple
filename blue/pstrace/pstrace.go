//
// pstrace.go
//
// lukem1
// 25 April 2021
//

//
// Linux process auditing tool
//

package main

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"

	/*"io/ioutil"*/
	"log"
	/*"net"*/
	"os"
	"os/exec"
	"strconv"
	"strings"
	/*"sync"*/ /*"syscall"*/ /*"time"*/)

type Process struct {
	// pstrace data
	upid     int    // unique process id // TODO: Remove or use
	lastseen uint64 // clock ticks since boot that pstrace last saw the proc // TODO: Remove or use

	// stats read from /proc/<pid>/stat
	pid         int    // process id
	comm        string // executable name
	state       rune   // process state
	ppid        int    // parent process id
	pgrp        int    // process group id
	session     int    // session id
	tty_nr      int    // controlling terminal
	tpgid       int    // id of process group controlling tty
	flags       uint   // kernel flags
	minflt      uint64 // number of minor faults
	cminflt     uint64 // number of minor faults by children
	majflt      uint64 // number of major faults
	cmajflt     uint64 // number of major faults by children
	utime       uint64 // clock ticks proc has been scheduled in user mode
	stime       uint64 // clock ticks proc has been scheduled in kernel mode
	cutime      int64  // clock ticks children have been scheduled in user mode
	cstime      int64  // clock ticks children have been scheduled in kernel mode
	priority    int64  // scheduling priority
	nice        int64  // the nice value
	num_threads int64  // number of threads in the proc
	itrealvalue int64  // jiffies before the next SIGALRM
	starttime   uint64 // clock ticks since boot at proc start
	vsize       uint64 // virtual memory size in bytes

	// other stats
	exelink string // link to the executable
	exesum  string // md5sum of the executable
	exedel  bool   // true if exe has been deleted from disk

	cmdline string // command line arguments
}

// Prints a summary of a proc
func procSummary(proc Process) {
	summary := "Process %d (%s)\nstate: %c tty: %d session: %d ppid: %d\nlink: %s sum: %s\n"
	summary = fmt.Sprintf(summary, proc.pid, proc.comm, proc.state, proc.tty_nr, proc.session, proc.ppid,
		proc.exelink, proc.exesum)

	fmt.Printf(summary)
}

// Kill a process
func kill(pid int) error {
	if os.Getuid() != 0 {
		return errors.New("Insufficient privileges")
	}
	spid := fmt.Sprintf("%d", pid)
	cmd := exec.Command("kill", spid)
	cmd.Start()
	return nil
}

// Reads data about an individual process from the /proc filesystem and returns a Process
func readProc(pid int) (Process, error) {
	proc := Process{pid: pid}
	procDir := fmt.Sprintf("/proc/%d", pid)

	if _, e := os.Stat(procDir); os.IsNotExist(e) {
		return proc, errors.New("Process does not exist")
	}

	// Read and fill data from /proc/[pid]/stat

	statFile := procDir + "/stat"
	statData, _ := os.ReadFile(statFile)
	statStr := string(statData)

	// Read comm then slice past it
	// (File names can cause issues if comm is handled with Sscanf)
	commStart := strings.IndexRune(statStr, '(')
	commEnd := strings.LastIndex(statStr, ")")
	proc.comm = statStr[commStart+1 : commEnd]
	statStr = statStr[commEnd+2:]
	fmtStr := "%c %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d"
	//fmt.Printf("stat: %s\n", statStr)

	fmt.Sscanf(
		statStr,
		fmtStr,
		&proc.state,
		&proc.ppid,
		&proc.pgrp,
		&proc.session,
		&proc.tty_nr,
		&proc.tpgid,
		&proc.flags,
		&proc.minflt,
		&proc.cminflt,
		&proc.majflt,
		&proc.cmajflt,
		&proc.utime,
		&proc.stime,
		&proc.cutime,
		&proc.cstime,
		&proc.priority,
		&proc.nice,
		&proc.num_threads,
		&proc.itrealvalue,
		&proc.starttime,
		&proc.vsize)

	/*
		log.Printf("Parsed: %d\n", r)
		if e != nil {
			log.Printf("Error: %s\n", e.Error())
		}

		fmt.Printf("Proc: %c %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
			proc.state,
			proc.ppid,
			proc.pgrp,
			proc.session,
			proc.tty_nr,
			proc.tpgid,
			proc.flags,
			proc.minflt,
			proc.cminflt,
			proc.majflt,
			proc.cmajflt,
			proc.utime,
			proc.stime,
			proc.cutime,
			proc.cstime,
			proc.priority,
			proc.nice,
			proc.num_threads,
			proc.itrealvalue,
			proc.starttime,
			proc.vsize)
	*/

	// Read /proc/[pid]/exe (often requires root)

	exeFile := procDir + "/exe"

	linkData, _ := os.Readlink(exeFile)
	proc.exelink = linkData

	if strings.Contains(linkData, "(deleted)") {
		proc.exedel = true
	} else {
		proc.exedel = false
	}

	exeData, _ := os.Open(exeFile)

	h := md5.New()
	if _, e := io.Copy(h, exeData); e == nil {
		sum := fmt.Sprintf("%x", h.Sum(nil))
		proc.exesum = sum
	}

	// Read /proc/[pid]/cmdline

	cmdFile := procDir + "/cmdline"
	cmdData, _ := os.ReadFile(cmdFile)
	proc.cmdline = string(cmdData)

	return proc, nil
}

// Reads the /proc filesystem and returns a map of Processes
func readProcfs() map[int]Process {
	procs := make(map[int]Process)
	contents, e := os.ReadDir("/proc")
	if e != nil {
		log.Printf(e.Error())
	}
	for _, entry := range contents {
		ename := entry.Name()
		if ename[0] < '0' || ename[0] > '9' {
			continue
		}

		id, _ := strconv.Atoi(ename)
		proc, _ := readProc(id)
		procs[proc.pid] = proc
	}

	return procs
}

// TODO
// Audit a process for suspect behavior
// - Check if exe is still on disk
// - Check if exe in memory matches exe on disk
// - what files are being used
// - network activity

// Group processes by exe and get info about exes
func exeTrace(procs map[int]Process) {
	exes := make(map[string][]Process)
	keys := make([]string, 0)
	for _, p := range procs {
		exe := p.exelink
		// If exelink is empty fall back to comm (kernel threads)
		if exe == "" {
			exe = fmt.Sprintf("(%s)", p.comm)
		}
		// Store new keys and map exes to procs
		if _, k := exes[exe]; !k {
			keys = append(keys, exe)
		}
		exes[exe] = append(exes[exe], p)
	}
	// Print results
	for _, k := range keys {
		fmt.Printf("┌ %s (Count: %d)\n", k, len(exes[k]))
		for i, p := range exes[k] {
			line := '├'
			if i == len(exes[k])-1 {
				line = '└'
			}
			fmt.Printf("%c [-] (%d) -> (%d) %s started at %d\n", line, p.ppid, p.pid, p.cmdline, p.starttime)
		}
	}
}

// Monitor process info
// TODO:
// - Add sleep so this is less demanding? What response time is optimal?
//   - This method (reading procfs) will always result in race conditions and missed processes.
//   - Kernel space modifications (ie Snoopy) are necessary to catch everything.
func psMonitor() {
	var procs map[int]Process
	exes := make(map[string]string)
	for true {
		newProcs := readProcfs()
		for _, p := range newProcs {
			// Ignore kernel threads
			if p.exelink != "" {
				kill_proc := false

				// Check if we have seen this exe running before
				if _, k := exes[p.exelink]; !k {
					fmt.Printf("Info - New Executable Seen - %s\n", p.exelink)
					exes[p.exelink] = p.exesum
				}

				// Check if we have a previous state for this proc
				prevState, exists := procs[p.pid]
				// If the previous state's start time does not match the start time
				// of the current state the old proc has died and the pid was reused.
				if exists && prevState.starttime != p.starttime {
					exists = false
				}

				//if !exists {
				//	fmt.Printf("Info - New Process Seen - %d: %s\n", p.pid, p.exelink)
				//}

				// Check if the in exe md5 changes across procs
				if exes[p.exelink] != p.exesum {
					fmt.Printf("Warning - Exe MD5 Changed - PID: %d EXE: %s\n", p.pid, p.exelink)
					exes[p.exelink] = p.exesum
				}

				// Check if the proc is running with a deleted executable
				if p.exedel {
					kill_proc = true
					// If we have a previous state make sure we are not duplicating an alert
					if !exists || (exists && prevState.exedel != p.exedel) {
						fmt.Printf("Critical - Proc With Deleted Executable - PID: %d EXE: %s\n", p.pid, p.exelink)
					}
				}

				// Attempt to kill a bad proc
				if kill_proc {
					e := kill(p.pid)
					if e != nil {
						fmt.Printf("Failed to kill process %d. %s\n", p.pid, e)
					} else {
						fmt.Printf("Killed process %d.\n", p.pid)
					}
				}
			}
		}
		// Save current state
		procs = newProcs
	}
}

func main() {
	// TODO: improve cli arg parsing
	// - more options
	// - better targeting
	// - help and usage

	if len(os.Args) == 1 {
		procs := readProcfs()
		exeTrace(procs)
	} else {
		var starti int
		procs := make(map[int]Process)
		if os.Args[1][0] != '-' {
			pid, _ := strconv.Atoi(os.Args[1])
			p, e := readProc(pid)
			if e != nil {
				log.Fatal(e.Error())
			}
			procs[p.pid] = p
			starti = 2
		} else {
			procs = readProcfs()
			starti = 1
		}

		for i := starti; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--deleted": // only list procs with deleted exes
				for _, p := range procs {
					if p.exedel {
						procSummary(p)
					}
				}
				return
			case "--mon": // Monitor mode
				psMonitor()
			default:
				log.Fatal("Unrecognized argument: ", os.Args[i])
			}
		}
		exeTrace(procs)
	}
}
