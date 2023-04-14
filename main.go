package main

import (
	"github.com/bvisness/yno/cmd"
	"github.com/bvisness/yno/utils"
)

func main() {
	utils.Must(cmd.RootCmd.Execute())
}
