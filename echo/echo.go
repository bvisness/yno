package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.ListenAndServe(":8000", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s\n", r.Method, r.URL)
		w.Write([]byte("yay!"))
	}))
}
