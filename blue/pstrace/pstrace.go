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
	"encoding/binary"
	"encoding/hex"
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
	"time"
	/*"sync"*/ /*"syscall"*/)

type Socket struct {
	protocol string // Name of the protocol (tcp, udp, etc)

	state string // State of the socket as a hex string

	local_addr  string // Local ip address
	local_port  int    // Local port
	remote_addr string // Remote ip address
	remote_port int    // Remote port

	inode string // inode of the socket
}

type Process struct {
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
	exesum  string // md5sum of the executable in memory
	exedel  bool   // true if exe has been deleted from disk

	cmdline string // command line arguments

	uid  int // Real id of the user who started the process
	euid int // Effective user id
	suid int // Saved set user id
	fuid int // Filesystem user id

	sockets []Socket // Sockets related to the process
}

// Prints a summary of a proc
func procSummary(proc Process) {
	summary := "Process %d (%s)\nstate: %c tty: %d session: %d ppid: %d\nuid: %d euid: %d\nlink: %s sum: %s\n"
	summary = fmt.Sprintf(summary, proc.pid, proc.comm, proc.state, proc.tty_nr, proc.session, proc.ppid,
		proc.uid, proc.euid,
		proc.exelink, proc.exesum)

	fmt.Printf(summary)

	fmt.Println("Related sockets:")
	for i, s := range proc.sockets {
		fmt.Printf("%d: Proto: %s State: %s Local: %s:%d Remote: %s:%d\n", i, s.protocol, s.state, s.local_addr, s.local_port, s.remote_addr, s.remote_port)
	}
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

// Decode a hex string ip:port pair into a human readable ip and an integer port
func decodeAddr(hexAddr string) (ip string, port int) {
	ipHex := strings.Split(hexAddr, ":")[0]
	ip = ""
	for i := 0; i < len(ipHex); i += 2 {
		ipBytes, _ := hex.DecodeString(ipHex[i : i+2])
		ip = fmt.Sprintf("%d.", int(ipBytes[0])) + ip
	}
	ip = ip[:len(ip)-1]

	portBytes, _ := hex.DecodeString(strings.Split(hexAddr, ":")[1])
	port = int(binary.BigEndian.Uint16(portBytes))

	return ip, port
}

// Reads data about an individual process from the /proc filesystem and returns a Process
func readProc(pid int) (Process, error) {
	proc := Process{pid: pid}
	procDir := fmt.Sprintf("/proc/%d", pid)

	if _, e := os.Stat(procDir); os.IsNotExist(e) {
		return proc, errors.New("Process does not exist")
	}

	// Read data from /proc/[pid]/stat

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

	// Get the md5sum of the in memory executable
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

	// Read UID info from /proc/[pid]/status

	statusFile := procDir + "/status"
	statusData, _ := os.ReadFile(statusFile)
	statusStr := string(statusData)
	uidStart := strings.Index(statusStr, "Uid:")
	uidEnd := strings.IndexRune(statusStr[uidStart:], '\n')
	fmt.Sscanf(
		statusStr[uidStart+4:uidStart+uidEnd],
		"%d %d %d %d",
		&proc.uid,
		&proc.euid,
		&proc.suid,
		&proc.fuid)

	// Read net information from /proc/[pid]/net/.

	// Protocols to watch
	// TODO:
	// - Parse available protocols from /etc/protocols?
	// - ipv6 addresses not currently handled by decodeAddr
	protocols := []string{"tcp", "udp", "icmp"}

	for _, proto := range protocols {
		pData, _ := os.ReadFile(procDir + "/net/" + proto)
		strSockets := strings.Split(string(pData), "\n")
		if len(strSockets) > 1 {
			// Remove the header line and the extra line at the end of the file
			strSockets = strSockets[1 : len(strSockets)-1]
			// Iterate over each line containing socket info
			for _, s := range strSockets {
				// Split the line containing socket info into its fields
				// Each line has the following fields:
				// sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
				sInfo := strings.Fields(s)
				socket := Socket{protocol: proto}

				socket.local_addr, socket.local_port = decodeAddr(sInfo[1])
				socket.remote_addr, socket.remote_port = decodeAddr(sInfo[2])
				socket.state = sInfo[3]
				socket.inode = sInfo[11]

				proc.sockets = append(proc.sockets, socket)
			}
		}
	}

	procSummary(proc)

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
					fmt.Printf("INFO - New Executable Seen - %s\n", p.exelink)
					exes[p.exelink] = p.exesum
				}

				// Check if we have a previous state for this proc
				prevState, exists := procs[p.pid]
				// If the previous state's start time does not match the start time
				// of the current state the old proc has died and the pid was reused.
				if exists && prevState.starttime != p.starttime {
					exists = false
				}

				// TODO: Alerting on new procs generates a lot of noise. Should be optional.
				if !exists {
					fmt.Printf("INFO - New Process Seen - %d: %s - %s\n", p.pid, p.exelink, p.cmdline)
				}

				// Check if the in exe md5 changes across procs
				if exes[p.exelink] != p.exesum {
					fmt.Printf("WARN - Exe MD5 Changed - PID: %d EXE: %s\n", p.pid, p.exelink)
					exes[p.exelink] = p.exesum
				}

				// Check if the proc is running with a deleted executable
				if p.exedel {
					// If we have a previous state make sure we are not duplicating an alert
					if !exists || (exists && prevState.exedel != p.exedel) {
						fmt.Printf("CRIT - Proc With Deleted Executable - PID: %d EXE: %s\n", p.pid, p.exelink)
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

		// Prevent spinning and high cpu use
		// Longer sleep means more procs may be missed but the main goal
		// of mon mode is to increase visibility of long running procs.
		time.Sleep(30 * time.Millisecond)
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
