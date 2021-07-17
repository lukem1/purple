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
	/*"sync"*/
	/*"syscall"*/
	/*"time"*/
)

type Process struct {
	// stats read from /proc/<pid>/stat
	pid int			// process id
	comm string		// executable name
	state rune		// process state
	ppid int		// parent process id
	pgrp int		// process group id
	session int		// session id
	tty_nr int		// controlling terminal
	tpgid int 		// id of process group controlling tty
	flags uint 		// kernel flags
	
	
	// other stats
	exelink string	// link to the executable
	exesum string	// md5sum of the executable
	exedel bool		// true if exe has been deleted from disk
	
	cmdline string  // command line arguments
}


// Prints a summary of a proc
func procSummary(proc Process) {
	summary := "Process %d (%s)\nstate: %c tty: %d session: %d ppid: %d\nlink: %s sum: %s\n"
	summary = fmt.Sprintf(summary, proc.pid, proc.comm, proc.state, proc.tty_nr, proc.session, proc.ppid,
	proc.exelink, proc.exesum)
	
	fmt.Printf(summary)
}


// Kill a process
// TODO: Check for insufficient priv?
func kill(pid int) {
	spid := fmt.Sprintf("%d", pid)
	cmd := exec.Command("kill", spid)
	cmd.Start()
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
	proc.comm = statStr[commStart+1:commEnd]
	statStr = statStr[commEnd+2:]
	
	fmt.Sscanf(
		statStr, 
		"%c %d %d %d %d %d %u",
		&proc.state,
		&proc.ppid,
		&proc.pgrp,
		&proc.session,
		&proc.tty_nr,
		&proc.tpgid,
		&proc.flags)
		
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


// Reads the /proc filesystem and returns a slice of Processes
func readProcfs() []Process {
	procs := make([]Process, 0)
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
		procs = append(procs, proc)
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
func exeTrace(procs []Process) {
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
			if i == len(exes[k]) - 1 {
				line = '└'
			}
			fmt.Printf("%c [-] (%d) -> (%d) %s\n", line, p.ppid, p.pid, p.cmdline)
		}
	}
}


func main() {
	if len(os.Args) == 2 {
		pid, _ := strconv.Atoi(os.Args[1])
		proc, _ := readProc(pid)
		procSummary(proc)
	} else {
		procs := readProcfs()
		
		for _, p := range procs {
			if p.exedel {
				procSummary(p)
			}
		}
		//exeTrace(procs)
	}
}
