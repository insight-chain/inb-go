// Copyright 2018 The go-inb Authors
// This file is part of the go-inb library.
//
// The go-inb library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-inb library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-inb library. If not, see <http://www.gnu.org/licenses/>.

// +build !windows

package dashboard

import (
	"syscall"

	"github.com/insight-chain/inb-go/log"
)

// getProcessCPUTime retrieves the process' CPU time since program startup.
func getProcessCPUTime() float64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		log.Warn("Failed to retrieve CPU time", "err", err)
		return 0
	}
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1000000
}
