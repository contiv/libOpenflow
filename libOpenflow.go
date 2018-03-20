package main

import (
	"./ofctrl"
)

func main() {

	// Main app
	var app ofctrl.OfApp

	// Create a controller
	ctrler := ofctrl.NewController(&app)

	// start listening
	ctrler.Listen(":6633")
}