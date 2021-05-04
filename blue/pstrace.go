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
	comm string		// Executable name
	state rune		// process state
	ppid int		// parent process id
	pgrp int		// process group id
	session int		// session id
	tty_nr int		// controlling terminal
	tpgid int 		// id of process group controlling tty
	flags uint 		// kernel flags
	
	
	// other stats
	exelink string	// Link to the executable
	exesum string	// md5sum of the executable
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
	
	exeData, _ := os.Open(exeFile)
	
	h := md5.New()
	if _, e := io.Copy(h, exeData); e == nil {
		sum := fmt.Sprintf("%x", h.Sum(nil))
		proc.exesum = sum
	}
	
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


// Audit a process for suspect behavior
// - Check if exe is still on disk
// - Check if exe in memory matches exe on disk
// - what files are being used
// - network activity
func audit(proc Process) {
	// TODO
}


func main() {
	if len(os.Args) == 2 {
		pid, _ := strconv.Atoi(os.Args[1])
		proc, _ := readProc(pid)
		procSummary(proc)
	} else {
		procs := readProcfs()
		for _, p := range procs {
			procSummary(p)
		}
	}
}
