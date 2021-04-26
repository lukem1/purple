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
	"fmt"
	/*"io"*/
	/*"io/ioutil"*/
	"log"
	/*"net"*/
	"os"
	/*"os/exec"*/
	"strconv"
	/*"strings"*/
	/*"sync"*/
	/*"syscall"*/
	/*"time"*/
)

type Process struct {
	pid int
	ppid int
	cmdline string
	cwd string
	exe string
	exesum string
}


// Kill a process
func kill(pid int) {
	// TODO
}


// Reads data about an inddividual process from the /proc filesystem and returns a Process
func readProc(pid int) Process {
	proc := Process{pid: pid}
	
	// TODO
	// Read and store the rest of the data
	
	return proc
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
		proc := readProc(id)
		procs = append(procs, proc)
	}
	for _, p := range procs {
		fmt.Printf("%d\n", p.pid)
	}
	return procs
}


// Audit a process for suspect behavior
// - Check if exe is still on disk
// - Check if exe in memory matches exe on disk
// - what files are being used
// - network activity
func audit(Process proc) {
	// TODO
}


func main() {
	readProcfs()
}
