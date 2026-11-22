package conf

import (
	"fmt"
	"log"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchFile watches filePath with a short debounce and invokes onChange without mutating any Conf struct.
func WatchFile(filePath string, onChange func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("new watcher error: %s", err)
	}
	go func() {
		var pre time.Time
		defer watcher.Close()
		for {
			select {
			case e := <-watcher.Events:
				if e.Has(fsnotify.Chmod) {
					continue
				}
				if pre.Add(10 * time.Second).After(time.Now()) {
					continue
				}
				pre = time.Now()
				go func() {
					time.Sleep(5 * time.Second)
					log.Println("config file changed, reloading...")
					onChange()
				}()
			case err := <-watcher.Errors:
				if err != nil {
					log.Printf("File watcher error: %s", err)
				}
			}
		}
	}()
	err = watcher.Add(filePath)
	if err != nil {
		_ = watcher.Close()
		return fmt.Errorf("watch file error: %s", err)
	}
	return nil
}

func (p *Conf) Watch(filePath string, reload func()) error {
	return WatchFile(filePath, func() {
		next := New()
		if err := next.LoadFromPath(filePath); err != nil {
			log.Printf("reload config error: %s", err)
			return
		}
		*p = *next
		reload()
		log.Println("reload config success")
	})
}
