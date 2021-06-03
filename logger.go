/*
Copyright AppsCode Inc. and Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/olekukonko/tablewriter"
)

type Logger struct {
	w io.Writer

	// context
	filename string
	count    int
	errFound bool
}

func NewLogger(w io.Writer) *Logger {
	return &Logger{w: w}
}

func (l *Logger) Init(filename string) {
	l.filename = filename
	l.count = 0
}

func (l *Logger) Log(err error) {
	if err == nil {
		return
	}
	if l.count == 0 {
		table := tablewriter.NewWriter(l.w)
		table.SetHeader([]string{l.filename})
		table.SetAutoFormatHeaders(false)
		table.SetRowLine(true)
		table.Render()
	}
	_, _ = fmt.Fprintln(l.w, err)
	l.count++
	l.errFound = true
}

func (l *Logger) Result() error {
	if l.errFound {
		return errors.New("error found")
	}
	return nil
}
