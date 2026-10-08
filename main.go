package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Technosport/Pseudonymisation/internal/server"
)

var version = "dev"

func main() {
	dataFlag := flag.String("data", "", "dossier des données (défaut : « data » à côté de l'exécutable)")
	noBrowser := flag.Bool("no-browser", false, "ne pas ouvrir le navigateur")
	flag.Parse()

	if err := run(*dataFlag, *noBrowser); err != nil {
		fmt.Fprintln(os.Stderr, "\nErreur :", err)
		fmt.Fprintln(os.Stderr, "Appuyez sur Entrée pour fermer.")
		fmt.Scanln()
		os.Exit(1)
	}
}

func run(dataFlag string, noBrowser bool) error {
	root := dataFlag
	if root == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return err
		}
		appDir := filepath.Dir(exe)
		CleanupOldFiles(appDir)
		checkAndApplyZipUpdate(appDir, version)
		root = filepath.Join(appDir, "data")
	}
	dataDir, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	backupDir := filepath.Join(filepath.Dir(dataDir), "backups")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("impossible de créer %s : %w", dataDir, err)
	}
	lockPath := filepath.Join(dataDir, ".instance")

	// Une seule instance : si l'application tourne déjà, on rouvre simplement le navigateur.
	if port := runningPort(lockPath); port > 0 {
		fmt.Println("L'application est déjà ouverte, ouverture du navigateur…")
		if !noBrowser {
			openBrowser(fmt.Sprintf("http://127.0.0.1:%d/", port))
		}
		return nil
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(lockPath, []byte(strconv.Itoa(port)), 0o600); err != nil {
		return fmt.Errorf("écriture impossible dans %s (clé protégée en écriture ?) : %w", dataDir, err)
	}
	defer os.Remove(lockPath)

	srv := server.New(filepath.Join(dataDir, "participants.pdb"), backupDir, version)
	
	// Inject update callbacks
	appDirForUpdate := filepath.Dir(dataDir) // since dataDir is inside appDir
	srv.CheckUpdate = func() (any, error) {
		return CheckRemoteUpdate(version)
	}
	srv.ApplyUpdate = func(url string) error {
		return ApplyRemoteUpdate(appDirForUpdate, url)
	}

	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go httpSrv.Serve(ln)
	go srv.WatchIdle()

	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	printBanner(version, url)
	if !noBrowser {
		openBrowser(url)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case <-srv.Quit():
	case <-sig:
	}
	if err := srv.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "Sauvegarde finale impossible :", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)
	fmt.Println("Application fermée.")
	return nil
}

func runningPort(lockPath string) int {
	b, err := os.ReadFile(lockPath)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	c := http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/api/ping", port))
	if err != nil {
		return 0
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0
	}
	return port
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Println("Ouvrez ce lien dans votre navigateur :", url)
	}
}
