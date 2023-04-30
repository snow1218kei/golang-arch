package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type person struct {
	First string
}

func main() {
	// p1 := person{
	// 	First: "Janny",
	// }

	// p2 := person{
	// 	First: "James",
	// }

	// xp := []person{p1, p2}

	// bs, err := json.Marshal(xp)
	// if err != nil {
	// 	log.Panic(err)
	// }
	// fmt.Println("PRINT JSON", string(bs))

	// xp2 := []person{}

	// err = json.Unmarshal(bs, &xp2)
	// if err != nil {
	// 	log.Panic(err)
	// }
	// fmt.Println("back into a Go data structure", xp2)

	http.HandleFunc("/encode", foo)
	http.HandleFunc("/decode", bar)
	http.ListenAndServe(":8080", nil)
}

func foo(w http.ResponseWriter, req *http.Request) {
	p1 := person{
		First: "Jenny",
	}

	err := json.NewEncoder(w).Encode(p1)
	if err != nil {
		log.Println("Encode bad data", err)
	}
}

func bar(w http.ResponseWriter, req *http.Request) {
	var p1 person
	err := json.NewDecoder(req.Body).Decode(&p1)
	if err != nil {
		log.Println("Decode bad data", err)
	}
	log.Println("person: ", p1)
}
